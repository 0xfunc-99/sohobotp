<?php defined('PORTAL_ROOT') || exit; ?>
<?php $inv = $endpoint['inventory']; $healthLabel = ['online' => 'Online', 'offline' => 'Offline', 'never' => 'Never checked in', 'pending' => 'Waiting for approval', 'disabled' => 'Disabled']; ?>
<?php $ad = $endpoint['directory'] ?? null; $assigned = $endpoint['assigned_by'] ?? 'token'; ?>
<p><a href="<?= e(route('endpoints')) ?>">← Endpoints</a></p>
<?php if (null !== $endpoint['attention']): ?>
  <div class="alert alert-error" role="alert"><?= e($endpoint['attention']) ?></div>
<?php endif; ?>
<?php if ('pending' === $endpoint['status'] && $canManage): ?>
  <section class="panel">
    <h2>Approve this machine?</h2>
    <p>It enrolled from <code><?= e($endpoint['enrolled_ip']) ?></code> on <?= e(format_time($endpoint['enrolled_at'])) ?> with token <code><?= e($endpoint['token_id']) ?></code> and reports the host name <strong><?= e($inv['hostname'] ?: '—') ?></strong>. Approve only machines you recognise: until then it receives no configuration and no secrets.</p>
    <div class="actions">
      <form method="post" action="<?= e(route('endpoint', ['id' => $endpoint['id']])) ?>" class="inline">
        <?= csrf_field() ?><input type="hidden" name="op" value="approve"><button type="submit" class="button-primary">Approve</button></form>
      <form method="post" action="<?= e(route('endpoint', ['id' => $endpoint['id']])) ?>" class="inline" data-confirm="Reject and remove this enrolment?">
        <?= csrf_field() ?><input type="hidden" name="op" value="reject"><button type="submit" class="button">Reject</button></form>
    </div>
  </section>
<?php endif; ?>
<section class="panel">
  <h2>Machine</h2>
  <dl class="details">
    <dt>Host name</dt><dd><?= e($inv['hostname'] ?: '—') ?></dd>
    <dt>Operating system</dt><dd><?= e(Portal\Endpoints::OS[$endpoint['os']] ?? $endpoint['os']) ?> <?= e(trim($inv['os_name'] . ' ' . $inv['os_version'])) ?></dd>
    <dt>Kernel / architecture</dt><dd><?= e($inv['kernel'] ?: '—') ?> / <?= e($inv['arch'] ?: '—') ?></dd>
    <dt>Domain</dt><dd><?= e($inv['domain'] ?: '—') ?></dd>
    <dt>IP addresses</dt><dd><?= e([] === $inv['ips'] ? '—' : implode(', ', $inv['ips'])) ?></dd>
    <dt>Agent version</dt><dd><?= e($inv['agent_version'] ?: '—') ?></dd>
    <dt>Login component</dt><dd><?= e(trim($inv['component']['name'] . ' ' . $inv['component']['version']) ?: '—') ?></dd>
    <dt>Endpoint id</dt><dd><code><?= e($endpoint['id']) ?></code></dd>
  </dl>
</section>
<section class="panel">
  <h2>Management</h2>
  <dl class="details">
    <dt>State</dt><dd><?= e($healthLabel[$endpoint['health']]) ?></dd>
    <dt>Group</dt><dd><?= e($group['name'] ?? '?') ?> <span class="muted">(<?= e(str_starts_with($assigned, 'rule:') ? 'chosen by an Active Directory rule' : ('admin' === $assigned ? 'set by an administrator; AD rules do not move it' : 'from the enrolment token')) ?>)</span></dd>
    <dt>Last check-in</dt><dd><?= e(format_time($endpoint['last_seen'])) ?> from <?= e($endpoint['last_ip']) ?></dd>
    <dt>Enrolled</dt><dd><?= e(format_time($endpoint['enrolled_at'])) ?> from <?= e($endpoint['enrolled_ip']) ?></dd>
    <dt>Configuration wanted</dt><dd>version <?= (int) $endpoint['config']['version'] ?><?= null !== $endpoint['config']['at'] ? ' (' . e(format_time($endpoint['config']['at'])) . ')' : '' ?></dd>
    <dt>Configuration on the machine</dt><dd>version <?= (int) $endpoint['applied']['version'] ?> — <?= e($endpoint['applied']['status']) ?><?= '' !== $endpoint['applied']['error'] ? ': ' . e($endpoint['applied']['error']) : '' ?></dd>
    <dt>Active Directory</dt><dd><?php if (null === $ad): ?>not checked<?php elseif (!$ad['found']): ?><?= e(isset($ad['error']) ? 'check failed: ' . $ad['error'] : 'no computer account found') ?> (<?= e(format_time($ad['checked_at'])) ?>)<?php else: ?>
      <code><?= e($ad['dn']) ?></code><?= $ad['enabled'] ? '' : ' <span class="status status-denied">disabled in AD</span>' ?><br>
      <span class="muted">DNS name <?= e($ad['dns_host'] ?: '—') ?> · groups <?= e([] === $ad['groups'] ? '—' : implode(', ', $ad['groups'])) ?> · checked <?= e(format_time($ad['checked_at'])) ?></span><?php endif; ?></dd>
    <?php if ('windows' === $endpoint['os']): ?>
      <dt>Windows sign-in</dt><dd><?= null === ($endpoint['cp_last_seen'] ?? null) ? 'no sign-in request yet' : 'last request ' . e(format_time($endpoint['cp_last_seen'])) . ' from ' . e($endpoint['cp_last_ip']) ?></dd>
    <?php endif; ?>
    <?php if ('linux' === $endpoint['os']): ?>
      <dt>RADIUS client</dt><dd><?= null !== $radiusClient ? '<code>' . e($radiusClient['name']) . '</code> at <code>' . e($radiusClient['address']) . '</code>' : '—' ?></dd>
    <?php endif; ?>
  </dl>
  <?php if ($canManage): ?>
    <div class="actions">
      <form method="post" action="<?= e(route('endpoint', ['id' => $endpoint['id']])) ?>" class="inline">
        <?= csrf_field() ?><input type="hidden" name="op" value="move">
        <label>Move to
          <select name="group_id">
            <?php foreach ($groups as $g): ?><option value="<?= e($g['id']) ?>"<?= $g['id'] === $endpoint['group_id'] ? ' selected' : '' ?>><?= e($g['name']) ?></option><?php endforeach; ?>
          </select></label>
        <button type="submit" class="button-small">Move</button>
      </form>
      <?php if ('admin' === $assigned): ?>
        <form method="post" action="<?= e(route('endpoint', ['id' => $endpoint['id']])) ?>" class="inline">
          <?= csrf_field() ?><input type="hidden" name="op" value="unlock-group"><button type="submit" class="button-small">Let AD rules choose the group</button></form>
      <?php endif; ?>
      <?php if ('active' === $endpoint['status']): ?>
        <form method="post" action="<?= e(route('endpoint', ['id' => $endpoint['id']])) ?>" class="inline" data-confirm="Disable this endpoint? Its agent will be refused and its secrets revoked; the machine keeps its last configuration.">
          <?= csrf_field() ?><input type="hidden" name="op" value="disable"><button type="submit" class="button-small">Disable</button></form>
      <?php else: ?>
        <form method="post" action="<?= e(route('endpoint', ['id' => $endpoint['id']])) ?>" class="inline">
          <?= csrf_field() ?><input type="hidden" name="op" value="enable"><button type="submit" class="button-small">Enable</button></form>
      <?php endif; ?>
      <form method="post" action="<?= e(route('endpoint', ['id' => $endpoint['id']])) ?>" class="inline" data-confirm="Delete this endpoint? Its RADIUS client is removed too. The machine keeps its last configuration until the agent is uninstalled.">
        <?= csrf_field() ?><input type="hidden" name="op" value="delete"><button type="submit" class="button-small">Delete</button></form>
    </div>
  <?php endif; ?>
</section>
