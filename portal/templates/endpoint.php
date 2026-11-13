<?php defined('PORTAL_ROOT') || exit; ?>
<?php $inv = $endpoint['inventory']; $healthLabel = ['online' => 'Online', 'offline' => 'Offline', 'never' => 'Never checked in', 'pending' => 'Waiting for approval', 'disabled' => 'Disabled']; ?>
<?php $ad = $endpoint['directory'] ?? null; $assigned = $endpoint['assigned_by'] ?? 'token'; ?>
<p class="back"><a href="<?= e(route('endpoints')) ?>">← Computers</a></p>
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
  <h2>Users on this computer</h2>
  <?php if ([] === $accounts): ?>
    <p class="muted">The agent has not reported the accounts yet (needs the agent from this release; it reports them at each check-in).</p>
  <?php else: ?>
    <?php $linux = 'linux' === $endpoint['os']; ?>
    <p class="hint">For each account, choose when it needs a code. Ticked: password <strong>and</strong> code. Unticked: password only (for example a script or service account).</p>
    <ul class="hint">
      <li><strong>At sign-in</strong>: <?= $linux ? 'SSH and the console login.' : 'the Windows sign-in screen, unlock and Remote Desktop into this computer.' ?></li>
      <li><strong>For admin actions</strong>: <?= $linux ? 'sudo and su.' : 'the "Enter your credentials" windows on this computer: UAC elevation ("Run as administrator") and Run as.' ?></li>
    </ul>
    <?php if (!$linux && !$promptsOn): ?>
      <div class="alert alert-info" role="status">Admin actions on this computer do not ask for a code at all right now: the computer policy has <strong>Credential prompts on this machine</strong> turned off. Turn it on in the <a href="<?= e(route('endpoint-group', ['id' => $endpoint['group_id']])) ?>">computer policy</a> for this column to apply.</div>
    <?php endif; ?>
    <form method="post" action="<?= e(route('endpoint', ['id' => $endpoint['id']])) ?>">
      <?= csrf_field() ?><input type="hidden" name="op" value="accounts">
      <div class="toolbar">
        <input type="search" class="search" id="accounts-search" placeholder="Search users on this computer" aria-label="Search users on this computer" data-filter-table="accounts-table">
        <?php if ($canManage): ?>
          <span class="toolbar-end tick-tools" aria-label="For the users shown">
            <span class="muted">For the users shown:</span>
            <button type="button" class="button-small" data-tick-visible="accounts-table" data-tick-name="needs_code[]" data-tick-state="1">Tick all at sign-in</button>
            <button type="button" class="button-small" data-tick-visible="accounts-table" data-tick-name="needs_code[]" data-tick-state="0">Untick all at sign-in</button>
            <button type="button" class="button-small" data-tick-visible="accounts-table" data-tick-name="needs_code_admin[]" data-tick-state="1">Tick all for admin</button>
            <button type="button" class="button-small" data-tick-visible="accounts-table" data-tick-name="needs_code_admin[]" data-tick-state="0">Untick all for admin</button>
          </span>
        <?php endif; ?>
      </div>
      <div class="table-wrap">
        <table class="table" id="accounts-table">
          <thead><tr><th>Account</th><th>Code at sign-in</th><th>Code for admin actions</th><th>Type</th><th>SohobOTP user</th></tr></thead>
          <tbody>
            <?php foreach ($accounts as $a): ?>
              <tr>
                <td><strong><?= e($a['name']) ?></strong><?= $a['admin'] ? ' <span class="status status-info">admin</span>' : '' ?></td>
                <?php if (null !== $a['fixed']): ?>
                  <td colspan="2"><span class="status">never</span> <span class="muted"><?= e($a['fixed']) ?></span></td>
                <?php else: ?>
                  <td><label class="choice"><input type="checkbox" name="needs_code[]" value="<?= e($a['name']) ?>"<?= $a['needs_code'] ? ' checked' : '' ?><?= $canManage ? '' : ' disabled' ?>><span class="sr-only">Code at sign-in: <?= e($a['name']) ?></span></label></td>
                  <td><label class="choice"><input type="checkbox" name="needs_code_admin[]" value="<?= e($a['name']) ?>"<?= $a['needs_code_admin'] ? ' checked' : '' ?><?= $canManage ? '' : ' disabled' ?>><span class="sr-only">Code for admin actions: <?= e($a['name']) ?></span></label></td>
                <?php endif; ?>
                <td><?= 'domain' === $a['kind'] ? 'Active Directory' : 'local' ?></td>
                <td>
                  <?php if ($a['has_user']): ?>
                    <a href="<?= e(route('user', ['u' => $a['user']])) ?>"><?= e($a['user']) ?></a>
                  <?php elseif (null === $a['fixed'] && ($a['needs_code'] || $a['needs_code_admin'])): ?>
                    <span class="status status-failure">none</span> <span class="muted">cannot sign in where it needs a code</span>
                  <?php else: ?>
                    <span class="muted">none</span>
                  <?php endif; ?>
                </td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <?php if ($canManage): ?><div class="actions"><button type="submit" class="button-primary">Save</button><span class="muted">The computer applies it at its next check-in (about a minute).</span></div><?php endif; ?>
    </form>
    <?php if ($canManage && $canCreateUsers): ?>
      <?php foreach ($accounts as $a): ?>
        <?php if (!$a['has_user'] && null === $a['fixed'] && 'local' === $a['kind']): ?>
          <form method="post" action="<?= e(route('endpoint', ['id' => $endpoint['id']])) ?>" class="inline">
            <?= csrf_field() ?><input type="hidden" name="op" value="create-user"><input type="hidden" name="account" value="<?= e($a['name']) ?>">
            <button type="submit" class="button-small">Create a SohobOTP user for <?= e($a['name']) ?></button>
          </form>
        <?php endif; ?>
      <?php endforeach; ?>
    <?php endif; ?>
  <?php endif; ?>
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
        <?= csrf_field() ?><input type="hidden" name="op" value="delete"><button type="submit" class="button-small button-danger">Delete</button></form>
    </div>
  <?php endif; ?>
</section>
