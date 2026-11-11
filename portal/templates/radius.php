<?php defined('PORTAL_ROOT') || exit; ?>
<?php if (null !== $active): ?>
  <div class="alert alert-info" role="status">The configuration is being applied. <a href="<?= e(route('job', ['id' => $active['id']])) ?>">Follow progress</a></div>
<?php elseif ($state['pending']): ?>
  <div class="alert alert-info" role="status">
    There are changes not yet active on FreeRADIUS.
    <?php if ($canManage): ?>
      <form method="post" action="<?= e(route('radius-apply')) ?>" class="inline"><?= csrf_field() ?>
        <button type="submit" class="button-primary">Apply configuration</button></form>
    <?php endif; ?>
  </div>
<?php endif; ?>
<div class="statusbar">
  <?php if (null !== $state['last_apply']): ?>
    <span class="muted">Last apply: <?= e(format_time($state['last_apply']['at'])) ?></span>
    <span class="status status-<?= 'applied' === $state['last_apply']['status'] ? 'success' : 'failure' ?>"><?= e($state['last_apply']['status']) ?></span>
  <?php else: ?>
    <span class="muted">The configuration has not been applied from the portal yet.</span>
  <?php endif; ?>
  <a class="button toolbar-end" href="<?= e(route('radius-diagnostics')) ?>">Diagnostics</a>
</div>

<section class="panel">
  <div class="toolbar">
    <h2>Server groups</h2>
    <?php if ($canManage): ?><a class="button-primary" href="<?= e(route('radius-group')) ?>">+ New group</a><?php endif; ?>
  </div>
  <p class="hint">A group sets the login policy for every server in it (for example VPN, firewalls, Wi-Fi).</p>
  <div class="table-wrap">
    <table class="table">
      <thead><tr><th>Group</th><th>Servers</th><th>Policy</th><?php if ($canManage): ?><th></th><?php endif; ?></tr></thead>
      <tbody>
        <?php foreach ($groups as $g): $p = $g['policy']; ?>
          <tr>
            <td><strong><?= e($g['name']) ?></strong><?php if ('' !== $g['description']): ?><br><span class="muted"><?= e($g['description']) ?></span><?php endif; ?></td>
            <td><?= (int) $g['clients'] ?></td>
            <td>
              <?= $p['challenge_response'] ? 'Challenge-response' . ($p['sms_challenge'] ? ' (SMS)' : '') : 'Code in the password field' ?>
              <?= $p['cache_result'] ? ' · result cached ' . (int) $p['cache_timeout'] . ' s' : '' ?>
              <?= $p['force_no_prefix_pin'] ? ' · no PIN prefix' : '' ?>
              <?= $p['dont_send_groups'] ? ' · no group attribute' : '' ?>
              <?= !empty($p['vip_forward']) ? ' · <strong>forwards users not on SohobOTP to Symantec VIP</strong>' : '' ?>
              <?= '' !== (string) ($p['allowed_groups'] ?? '') ? ' · only user groups: <strong>' . e($p['allowed_groups']) . '</strong>' : '' ?>
            </td>
            <?php if ($canManage): ?>
              <td class="row-actions">
                <a class="button-small" href="<?= e(route('radius-group', ['id' => $g['id']])) ?>">Edit</a>
                <a class="button-small" href="<?= e(route('radius-client', ['group' => $g['id']])) ?>">Add server</a>
                <?php if (0 === (int) $g['clients']): ?>
                  <form method="post" action="<?= e(route('radius-group-delete')) ?>" class="inline" data-confirm="Delete group <?= e($g['name']) ?>?">
                    <?= csrf_field() ?><input type="hidden" name="id" value="<?= e($g['id']) ?>"><button type="submit" class="button-small button-danger">Delete</button>
                  </form>
                <?php endif; ?>
              </td>
            <?php endif; ?>
          </tr>
        <?php endforeach; ?>
        <?php if ([] === $groups): ?><tr><td colspan="4" class="empty">No server groups yet. Create a group first: it sets the login policy for the servers you add to it.</td></tr><?php endif; ?>
      </tbody>
    </table>
  </div>
</section>

<section class="panel">
  <div class="toolbar">
    <h2>Symantec VIP migration</h2>
    <?php if ($canManage): ?><a class="button" href="<?= e(route('radius-vip')) ?>">Settings</a><?php endif; ?>
  </div>
  <p>
    <?php if ([] === $vip['servers']): ?>Not configured. Use it to keep Symantec VIP working for users who are not on SohobOTP yet, behind the same RADIUS server.
    <?php else: ?>
      Symantec VIP Enterprise Gateway: <?= e(implode(', ', array_map(static fn (array $s): string => $s['address'] . ':' . $s['port'], $vip['servers']))) ?>
      — <?= $vipActive ? '<span class="status status-success">active</span>' : '<span class="status status-failure">not applied yet</span>' ?>
      · forwarding in: <?= [] === $vipGroups ? 'no server group yet' : e(implode(', ', $vipGroups)) ?>
      · users on SohobOTP: <?= (int) $vipCounts['sohobotp'] ?>
    <?php endif; ?>
  </p>
</section>

<section class="panel">
  <div class="toolbar">
    <h2>Servers (RADIUS clients)</h2>
    <input type="search" class="search" placeholder="Search servers" data-filter-table="clients-table" aria-label="Search servers">
    <?php if ($canManage && [] !== $groups): ?><a class="button-primary" href="<?= e(route('radius-client')) ?>">+ Add server</a><?php endif; ?>
  </div>
  <div class="table-wrap">
    <table class="table" id="clients-table">
      <thead><tr><th>Name</th><th>Address</th><th>Group</th><th>Type</th><th>Secret set</th><?php if ($canManage): ?><th></th><?php endif; ?></tr></thead>
      <tbody>
        <?php foreach ($clients as $c): ?>
          <tr>
            <td><strong><?= e($c['name']) ?></strong><?php if ('' !== $c['description']): ?><br><span class="muted"><?= e($c['description']) ?></span><?php endif; ?></td>
            <td><code><?= e($c['address']) ?></code></td>
            <td><?= e($names[$c['group_id']] ?? '?') ?></td>
            <td><?= e(Portal\Radius::NAS_TYPES[$c['nas_type']] ?? $c['nas_type']) ?><?= $c['require_message_authenticator'] ? '' : ' <span class="status status-failure">no Message-Authenticator</span>' ?></td>
            <td class="nowrap"><?= e(format_time($c['secret_set_at'])) ?></td>
            <?php if ($canManage): ?>
              <td class="row-actions">
                <a class="button-small" href="<?= e(route('radius-client', ['id' => $c['id']])) ?>">Edit</a>
                <form method="post" action="<?= e(route('radius-client-action')) ?>" class="inline" data-confirm="Generate a new shared secret for <?= e($c['name']) ?>? The device must be updated with it.">
                  <?= csrf_field() ?><input type="hidden" name="id" value="<?= e($c['id']) ?>"><input type="hidden" name="op" value="rotate-secret">
                  <button type="submit" class="button-small">New secret</button>
                </form>
                <form method="post" action="<?= e(route('radius-client-action')) ?>" class="inline" data-confirm="Delete server <?= e($c['name']) ?>?">
                  <?= csrf_field() ?><input type="hidden" name="id" value="<?= e($c['id']) ?>"><input type="hidden" name="op" value="delete">
                  <button type="submit" class="button-small button-danger">Delete</button>
                </form>
              </td>
            <?php endif; ?>
          </tr>
        <?php endforeach; ?>
        <?php if ([] === $clients): ?><tr><td colspan="6" class="empty">No servers yet. Add the VPNs, firewalls and other devices that send RADIUS requests.</td></tr><?php endif; ?>
      </tbody>
    </table>
  </div>
</section>
