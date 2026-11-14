<?php defined('PORTAL_ROOT') || exit; ?>
<?php $healthLabel = ['online' => 'Online', 'offline' => 'Offline', 'never' => 'Never checked in', 'pending' => 'Waiting for approval', 'disabled' => 'Disabled']; ?>
<?php $healthClass = ['online' => 'success', 'offline' => 'failure', 'never' => 'info', 'pending' => 'info', 'disabled' => 'denied']; ?>
<section class="cards" aria-label="Endpoint status">
  <div class="card"><span class="card-label">Computers</span><span class="card-value"><?= (int) $total ?></span></div>
  <div class="card"><span class="card-label">Online</span><span class="card-value"><?= (int) $counts['online'] ?></span></div>
  <div class="card<?= $counts['offline'] > 0 ? ' card-warning' : '' ?>"><span class="card-label">Offline</span><span class="card-value"><?= (int) $counts['offline'] ?></span></div>
  <a class="card card-link<?= $counts['pending'] > 0 ? ' card-warning' : '' ?>" href="<?= e(route('endpoints', ['health' => 'pending'])) ?>"><span class="card-label">Waiting for approval</span><span class="card-value"><?= (int) $counts['pending'] ?></span></a>
  <div class="card<?= $counts['attention'] > 0 ? ' card-warning' : '' ?>"><span class="card-label">Need attention</span><span class="card-value"><?= (int) $counts['attention'] ?></span></div>
</section>

<section class="panel">
  <div class="toolbar">
    <h2>Computers</h2>
    <input type="search" class="search" placeholder="Search endpoints" data-filter-table="endpoints-table" aria-label="Search endpoints">
    <a class="button" href="<?= e(route('endpoint-groups')) ?>">Computer policies</a><?php if ($canManage): ?> <a class="button" href="<?= e(route('endpoint-enrol')) ?>">Enrolment tokens</a> <a class="button" href="<?= e(route('signin-packages')) ?>">Windows sign-in installers</a><?php endif; ?>
    <?php if ($canManage): ?><a class="button-primary" href="<?= e(route('agent-download')) ?>">+ Add a computer</a><?php endif; ?>
  </div>
  <form method="get" action="index.php" class="filters">
    <input type="hidden" name="r" value="endpoints">
    <label>Group
      <select name="group">
        <option value="">All</option>
        <?php foreach ($groups as $g): ?><option value="<?= e($g['id']) ?>"<?= $groupFilter === $g['id'] ? ' selected' : '' ?>><?= e($g['name']) ?></option><?php endforeach; ?>
      </select>
    </label>
    <label>State
      <select name="health">
        <option value="">All</option>
        <?php foreach ($healthLabel + ['attention' => 'Needs attention'] as $value => $label): ?><option value="<?= e($value) ?>"<?= $healthFilter === $value ? ' selected' : '' ?>><?= e($label) ?></option><?php endforeach; ?>
      </select>
    </label>
    <button type="submit" class="button-small">Filter</button>
  </form>
  <div class="table-wrap">
    <table class="table" id="endpoints-table">
      <thead><tr><th>Host</th><th>OS</th><th>Group</th><th>State</th><th>Last check-in</th><th>Configuration</th><th>Agent</th></tr></thead>
      <tbody>
        <?php foreach ($rows as $r): $inv = $r['inventory']; ?>
          <tr>
            <td><a href="<?= e(route('endpoint', ['id' => $r['id']])) ?>"><strong><?= e($inv['hostname'] ?: $r['id']) ?></strong></a>
              <?php if ('' !== $inv['domain']): ?><br><span class="muted"><?= e($inv['domain']) ?></span><?php endif; ?></td>
            <td><?= e(Portal\Endpoints::OS[$r['os']] ?? $r['os']) ?><?php if ('' !== $inv['os_name']): ?><br><span class="muted"><?= e(trim($inv['os_name'] . ' ' . $inv['os_version'])) ?></span><?php endif; ?></td>
            <td><?= e($names[$r['group_id']] ?? '?') ?><?php if (str_starts_with($r['assigned_by'] ?? '', 'rule:')): ?><br><span class="muted">by AD rule</span><?php endif; ?></td>
            <td><span class="status status-<?= e($healthClass[$r['health']]) ?>"><?= e($healthLabel[$r['health']]) ?></span>
              <?php if (null !== $r['attention']): ?><br><span class="status status-failure" title="<?= e($r['attention']) ?>">needs attention</span><?php endif; ?></td>
            <td class="nowrap"><?= e(format_time($r['last_seen'])) ?></td>
            <td><?= (int) $r['applied']['version'] ?> / <?= (int) $r['config']['version'] ?>
              <?php if ($r['applied']['version'] === $r['config']['version'] && 'applied' === $r['applied']['status']): ?><span class="muted">up to date</span><?php endif; ?></td>
            <td><?= e($inv['agent_version']) ?></td>
          </tr>
        <?php endforeach; ?>
        <?php if ([] === $rows): ?><tr><td colspan="7" class="empty"><?= 0 === $total ? 'No endpoints yet. Create an enrolment token and install the agent on a machine.' : 'No endpoint matches the filter.' ?></td></tr><?php endif; ?>
      </tbody>
    </table>
  </div>
  <p class="hint">Configuration: version applied on the machine / version the portal wants it to have.</p>
</section>

<section class="panel" id="coverage">
  <div class="toolbar">
    <h2>Computers without the agent</h2>
    <?php if ($canManage && $adReady): ?>
      <form method="post" action="<?= e(route('endpoint-rules')) ?>" class="inline"><?= csrf_field() ?><input type="hidden" name="op" value="coverage">
        <button type="submit" class="button"><?= null === $coverage ? 'Check Active Directory' : 'Check again' ?></button></form>
    <?php endif; ?>
  </div>
  <p class="hint">Compares the computer accounts in Active Directory with the enrolled endpoints. A computer without the agent accepts a password alone at its sign-in screen and for Remote Desktop.</p>
  <?php if (!$adReady): ?>
    <div class="alert alert-info" role="status">Connect Active Directory on the <a href="<?= e(route('directory')) ?>">Directory</a> page to find computers without the agent.</div>
  <?php elseif (null === $coverage): ?>
    <p class="muted">Not checked yet.<?= $canManage ? '' : ' An administrator can run the check.' ?></p>
  <?php else: ?>
    <?php $enabledTotal = $coverage['total'] - $coverage['disabled']; $missing = count($coverage['unprotected']); ?>
    <div class="statusbar">
      <span><strong><?= (int) $enabledTotal ?></strong> enabled computer(s) in Active Directory</span>
      <span class="status status-success"><?= (int) $coverage['protected'] ?> with the agent</span>
      <span class="status status-<?= $missing > 0 ? 'failure' : 'success' ?>"><?= (int) $missing ?> without</span>
      <?php if ($coverage['servers_unprotected'] > 0): ?><span class="status status-denied"><?= (int) $coverage['servers_unprotected'] ?> server(s) without</span><?php endif; ?>
      <span class="muted toolbar-end">Checked <?= e(format_time($coverage['checked_at'])) ?></span>
    </div>
    <?php if ($coverage['truncated']): ?><div class="alert alert-warning" role="status">Only the first 20,000 computer accounts were read.</div><?php endif; ?>
    <?php if ($missing > 0): ?>
      <div class="toolbar">
        <input type="search" class="search" placeholder="Search computers" data-filter-table="coverage-table" aria-label="Search computers without the agent">
        <?php if ($canManage): ?><a class="button-primary toolbar-end" href="<?= e(route('agent-download')) ?>">+ Add a computer</a><?php endif; ?>
      </div>
      <div class="table-wrap">
        <table class="table" id="coverage-table">
          <thead><tr><th>Computer</th><th>Operating system</th><th>DNS name</th><th>Last sign-in (AD)</th></tr></thead>
          <tbody>
            <?php foreach ($coverage['unprotected'] as $c): ?>
              <tr>
                <td><strong><?= e(strtoupper($c['name'])) ?></strong><?php if ($c['server']): ?> <span class="badge">server</span><?php endif; ?><br><span class="muted"><?= e($c['dn']) ?></span></td>
                <td><?= e($c['os'] ?: '—') ?></td>
                <td><?= e($c['dns_host'] ?: '—') ?></td>
                <td class="nowrap"><?= e(format_time($c['last_logon'])) ?></td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <p class="hint">“Last sign-in” comes from Active Directory and can lag by up to two weeks. Computers not seen for months may be retired: disable them in Active Directory.</p>
    <?php endif; ?>
  <?php endif; ?>
</section>
