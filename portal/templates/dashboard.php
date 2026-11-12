<?php defined('PORTAL_ROOT') || exit; ?>
<?php
  $icon = require PORTAL_ROOT . '/templates/partials/icons.php';
  $charts = require PORTAL_ROOT . '/templates/partials/charts.php';
  $can = static fn (string $permission): bool => Portal\Roles::can($me['role'], $permission);

  $users = $stats['users'];
  $active = $stats['active'];
  $locked = (int) ($stats['locked'] ?? 0);
  $disabled = null !== $users && null !== $active ? max(0, $users - $active) : null;
  $endpoints = $can('endpoints.view') ? Portal\DashboardInsights::endpoints() : null;
  $radius = $can('radius.view') ? Portal\DashboardInsights::radius() : null;
  $logins = Portal\DashboardInsights::logins(14);
  $guide = Portal\GettingStarted::steps($me['role'], $users, $directory['enabled'], (int) $logins['ok']);
  $activity = $can('audit.view') ? Portal\DashboardInsights::activity(Portal\Audit::default(), 14) : null;

  // What needs a look, most serious first
  $issues = [];
  $issue = static function (string $level, string $text, ?string $href) use (&$issues): void {
      $issues[] = ['level' => $level, 'text' => $text, 'href' => $href];
  };
  if (null !== $stats['error']) { $issue('critical', $stats['error'], null); }
  if (null === $stats['error'] && Portal\EngineKey::isPublic()) { $issue('critical', 'Token secrets use the public default key', $can('database.manage') ? route('database') : null); }
  if (null !== $radius && true === $radius['catch_all']) { $issue('critical', 'Any device can send sign-ins with the well-known default secret', route('radius-diagnostics')); }
  if (null !== $radius && false === $radius['service']) { $issue('critical', 'The sign-in service for VPNs and devices (FreeRADIUS) is stopped', route('radius-diagnostics')); }
  if ($locked > 0) { $issue('warning', $locked . ' user' . (1 === $locked ? ' is' : 's are') . ' locked out', $can('users.view') ? route('users', ['status' => 'locked']) : null); }
  if ($lockedAdmins > 0) { $issue('warning', $lockedAdmins . ' administrator account' . (1 === $lockedAdmins ? ' is' : 's are') . ' locked', $can('admins.manage') ? route('admins') : null); }
  if (null !== $radius && $radius['pending']) { $issue('warning', 'Changes to VPNs and devices are not active yet: open the page and apply them', route('radius')); }
  if (null !== $endpoints && $endpoints['pending'] > 0) { $issue('warning', $endpoints['pending'] . ' computer' . (1 === $endpoints['pending'] ? ' is' : 's are') . ' waiting for your approval', route('endpoints', ['health' => 'pending'])); }
  if (null !== $endpoints && null !== $endpoints['coverage'] && $endpoints['coverage']['servers_without'] > 0) { $n = $endpoints['coverage']['servers_without']; $issue('warning', $n . ' server' . (1 === $n ? '' : 's') . ' in Active Directory ' . (1 === $n ? 'has' : 'have') . ' no SohobOTP agent', route('endpoints') . '#coverage'); }
  elseif (null !== $endpoints && null !== $endpoints['coverage'] && $endpoints['coverage']['without'] > 0) { $n = $endpoints['coverage']['without']; $issue('info', $n . ' computer' . (1 === $n ? '' : 's') . ' in Active Directory ' . (1 === $n ? 'has' : 'have') . ' no SohobOTP agent', route('endpoints') . '#coverage'); }
  if (null !== $endpoints && $endpoints['offline'] > 0) { $issue('info', $endpoints['offline'] . ' computer' . (1 === $endpoints['offline'] ? ' is' : 's are') . ' offline', route('endpoints', ['health' => 'offline'])); }
  if ($directory['enabled'] && null !== $directory['last'] && 'succeeded' !== $directory['last']['status']) { $issue('warning', 'The last directory sync ' . $directory['last']['status'], route('directory')); }
  $worst = [] === $issues ? 'ok' : (in_array('critical', array_column($issues, 'level'), true) ? 'critical' : (in_array('warning', array_column($issues, 'level'), true) ? 'warning' : 'info'));

  $hour = (int) date('G');
  $greeting = $hour < 12 ? 'Good morning' : ($hour < 18 ? 'Good afternoon' : 'Good evening');
  $firstName = trim((string) (preg_split('/\s+/', trim((string) ($me['display_name'] ?: $me['username'])))[0] ?? ''));

  $ago = static function (string $iso): string {
      $t = strtotime($iso);
      if (false === $t) { return $iso; }
      $s = max(0, time() - $t);
      return match (true) {
          $s < 60 => 'just now',
          $s < 3600 => (int) floor($s / 60) . ' min ago',
          $s < 86400 => (int) floor($s / 3600) . ' h ago',
          $s < 7 * 86400 => (int) floor($s / 86400) . ' d ago',
          default => gmdate('j M Y', $t),
      };
  };
  $kpi = static function (string $iconName, string $label, string $value, string $sub, ?string $href, string $tone = '') use ($icon): string {
      $inner = '<span class="kpi-icon" aria-hidden="true">' . $icon($iconName, '') . '</span>'
          . '<span class="kpi-body"><span class="card-label">' . e($label) . '</span><span class="card-value">' . e($value) . '</span>'
          . ('' !== $sub ? '<span class="kpi-sub">' . e($sub) . '</span>' : '') . '</span>';
      $class = 'card kpi' . ('' !== $tone ? ' kpi-' . $tone : '') . (null !== $href ? ' card-link' : '');
      return null === $href ? '<div class="' . $class . '">' . $inner . '</div>' : '<a class="' . $class . '" href="' . e($href) . '">' . $inner . '</a>';
  };
?>
<section class="hero hero-<?= e($worst) ?>">
  <div class="hero-text">
    <p class="hero-greeting"><?= e($greeting . ('' !== $firstName ? ', ' . $firstName : '')) ?></p>
    <p class="hero-status">
      <span class="hero-dot" aria-hidden="true"></span>
      <?php if ('ok' === $worst): ?>All systems normal. Nothing needs your attention.
      <?php else: ?><?= count($issues) ?> thing<?= 1 === count($issues) ? '' : 's' ?> need<?= 1 === count($issues) ? 's' : '' ?> your attention.<?php endif; ?>
    </p>
  </div>
  <div class="hero-actions">
    <?php if ($can('users.manage')): ?><a class="button-primary" href="<?= e(route('user-new')) ?>"><?= $icon('plus', '') ?>New user</a><?php endif; ?>
    <?php if ($can('endpoints.manage')): ?><a class="button" href="<?= e(route('agent-download')) ?>"><?= $icon('endpoints', '') ?>Add a computer</a><?php endif; ?>
    <?php if ($can('radius.view')): ?><a class="button" href="<?= e(route('radius-diagnostics')) ?>"><?= $icon('activity', '') ?>Diagnostics</a><?php endif; ?>
  </div>
  <?php if ([] !== $issues): ?>
    <ul class="issues">
      <?php foreach ($issues as $i): ?>
        <li class="issue issue-<?= e($i['level']) ?>">
          <span class="issue-mark" aria-hidden="true"></span>
          <span class="sr-only"><?= e(['critical' => 'Critical:', 'warning' => 'Warning:', 'info' => 'Note:'][$i['level']]) ?></span>
          <?php if (null !== $i['href']): ?><a href="<?= e($i['href']) ?>"><?= e($i['text']) ?><?= $icon('arrow-right', 'issue-arrow') ?></a><?php else: ?><span><?= e($i['text']) ?></span><?php endif; ?>
        </li>
      <?php endforeach; ?>
    </ul>
  <?php endif; ?>
</section>

<?php if (!$guide['complete']): ?>
  <section class="panel guide" aria-labelledby="guide-title">
    <div class="panel-head">
      <div><h2 id="guide-title">Get started</h2><p class="panel-sub"><?= (int) $guide['done'] ?> of 4 done. Each step ticks itself when it is set up.</p></div>
      <span class="guide-meter guide-meter-<?= (int) $guide['done'] ?>" aria-hidden="true"><span></span></span>
    </div>
    <ol class="guide-steps">
      <?php $nextShown = false; foreach ($guide['steps'] as $n => $step): $isNext = !$step['done'] && !$nextShown; $nextShown = $nextShown || $isNext; ?>
        <li class="guide-step<?= $step['done'] ? ' is-done' : '' ?><?= $isNext ? ' is-next' : '' ?>">
          <span class="guide-mark" aria-hidden="true"><?= $step['done'] ? $icon('check', '') : (string) ($n + 1) ?></span>
          <span class="guide-body">
            <strong><?= e($step['title']) ?></strong><span class="sr-only"><?= $step['done'] ? ' (done)' : ' (to do)' ?></span>
            <span class="muted"><?= e($step['text']) ?></span>
          </span>
          <?php if (!$step['done']): ?>
            <span class="guide-actions">
              <?php foreach ($step['actions'] as $k => $a): ?><a class="<?= $isNext && 0 === $k ? 'button-primary' : 'button' ?> button-small" href="<?= e(route($a['route'])) ?>"><?= e($a['label']) ?></a><?php endforeach; ?>
            </span>
          <?php endif; ?>
        </li>
      <?php endforeach; ?>
    </ol>
  </section>
<?php endif; ?>

<section class="cards kpis" aria-label="SohobOTP status">
  <?= $kpi('users', 'Users', null === $users ? '—' : (string) $users, null === $active ? '' : 'Active users: ' . $active . ' · disabled: ' . (int) $disabled, $can('users.view') ? route('users') : null, 'good') ?>
  <?= $kpi('lock', 'Locked users', (string) $locked, $locked > 0 ? 'Unlock them from the user page' : 'No one is locked out', $can('users.view') ? route('users', ['status' => 'locked']) : null, $locked > 0 ? 'warn' : '') ?>
  <?= $kpi('tokens', 'Key fobs', null === $stats['tokens'] ? '—' : (string) $stats['tokens'], 'Imported key fobs', $can('tokens.view') ? route('tokens') : null) ?>
  <?php if (null !== $endpoints): ?>
    <?= $kpi('endpoints', 'Computers online', (string) $endpoints['online'], 'of ' . $endpoints['total'] . ' machine' . (1 === $endpoints['total'] ? '' : 's'), route('endpoints'), $endpoints['pending'] > 0 ? 'warn' : '') ?>
  <?php endif; ?>
  <?php if (null !== $radius): ?>
    <?= $kpi('radius', 'VPNs and devices', (string) $radius['servers'], 'in ' . $radius['groups'] . ' group' . (1 === $radius['groups'] ? '' : 's'), route('radius'), $radius['pending'] ? 'warn' : '') ?>
  <?php endif; ?>
  <?= $kpi('admins', 'Portal administrators', (string) (int) $adminCount, $lockedAdmins > 0 ? $lockedAdmins . ' locked' : 'None locked', $can('admins.manage') ? route('admins') : null, $lockedAdmins > 0 ? 'warn' : '') ?>
</section>

<div class="dash-grid">
  <section class="panel dash-wide">
    <div class="panel-head">
      <div><h2>Logins</h2><p class="panel-sub">Codes checked by SohobOTP for VPNs, servers and Windows sign-in, last 14 days</p></div>
      <?php if ($can('radius.view')): ?><a class="button-small" href="<?= e(route('radius-diagnostics')) ?>">Recent logins</a><?php endif; ?>
    </div>
    <?php if (!$logins['available']): ?>
      <p class="chart-empty">The login log could not be read.</p>
    <?php elseif (0 === $logins['ok'] + $logins['failed']): ?>
      <div class="chart-empty">
        <?= $icon('activity', 'chart-empty-icon') ?>
        <p><strong>No logins in the last 14 days.</strong> They appear here once a VPN, server or Windows machine sends its first login to SohobOTP.</p>
      </div>
    <?php else: ?>
      <?= $charts['bars']($logins['days'], [['key' => 'ok', 'label' => 'Accepted', 'class' => 'viz-s1'], ['key' => 'failed', 'label' => 'Refused', 'class' => 'viz-s2']], 'Logins per day, last 14 days') ?>
    <?php endif; ?>
  </section>

  <section class="panel">
    <div class="panel-head"><div><h2>Users by state</h2><p class="panel-sub"><?= null === $users ? 'Not available' : (int) $users . ' in total' ?></p></div></div>
    <?php if (null !== $users): ?>
      <?= $charts['segments']([
          ['label' => 'Active', 'value' => max(0, (int) $active - $locked), 'class' => 'viz-good', 'href' => $can('users.view') ? route('users', ['status' => 'enabled']) : null],
          ['label' => 'Locked', 'value' => $locked, 'class' => 'viz-warn', 'href' => $can('users.view') ? route('users', ['status' => 'locked']) : null],
          ['label' => 'Disabled', 'value' => (int) $disabled, 'class' => 'viz-neutral', 'href' => $can('users.view') ? route('users', ['status' => 'disabled']) : null],
      ], 'Users by state') ?>
    <?php endif; ?>
    <?php if (null !== $endpoints && $endpoints['total'] > 0): ?>
      <h3>Computers</h3>
      <?= $charts['segments']([
          ['label' => 'Online', 'value' => $endpoints['online'], 'class' => 'viz-good', 'href' => route('endpoints', ['health' => 'online'])],
          ['label' => 'Offline', 'value' => $endpoints['offline'], 'class' => 'viz-warn', 'href' => route('endpoints', ['health' => 'offline'])],
          ['label' => 'Waiting', 'value' => $endpoints['pending'] + $endpoints['never'], 'class' => 'viz-info', 'href' => route('endpoints', ['health' => 'pending'])],
          ['label' => 'Disabled', 'value' => $endpoints['disabled'], 'class' => 'viz-neutral', 'href' => route('endpoints', ['health' => 'disabled'])],
      ], 'Computers by state') ?>
    <?php endif; ?>
  </section>

  <?php if (null !== $activity): ?>
    <section class="panel dash-wide">
      <div class="panel-head">
        <div><h2>Portal activity</h2><p class="panel-sub">Sign-ins and changes in this portal, last 14 days</p></div>
        <a class="button-small" href="<?= e(route('audit')) ?>">Audit trail</a>
      </div>
      <?php if (0 === $activity['ok'] + $activity['failed']): ?>
        <p class="chart-empty">No activity in the last 14 days.</p>
      <?php else: ?>
        <?= $charts['bars']($activity['days'], [['key' => 'ok', 'label' => 'Succeeded', 'class' => 'viz-s1'], ['key' => 'failed', 'label' => 'Failed or refused', 'class' => 'viz-s2']], 'Portal activity per day, last 14 days') ?>
      <?php endif; ?>
    </section>
  <?php endif; ?>

  <section class="panel">
    <div class="panel-head"><div><h2>Services</h2><p class="panel-sub">Connections SohobOTP relies on</p></div></div>
    <ul class="services">
      <li>
        <span class="service-icon" aria-hidden="true"><?= $icon('directory', '') ?></span>
        <span class="service-body">
          <strong>Directory synchronisation</strong>
          <?php if (!$directory['enabled']): ?>
            <span class="muted">No directory is configured.</span>
          <?php else: ?>
            <span class="muted">Last sync <?= null === $directory['last'] ? 'never' : e(format_time($directory['last']['at'])) ?> · <?= !empty($directory['schedule']['enabled']) ? 'every ' . (int) $directory['schedule']['minutes'] . ' minutes' : 'manual only' ?></span>
          <?php endif; ?>
        </span>
        <?php if (!$directory['enabled']): ?><span class="status">off</span>
        <?php elseif (null !== $directory['active'] && in_array($directory['active']['status'], Portal\Jobs::ACTIVE, true)): ?><span class="status status-info">sync <?= e($directory['active']['status']) ?></span>
        <?php elseif (null === $directory['last']): ?><span class="status status-info">ready</span>
        <?php else: ?><span class="status status-<?= 'succeeded' === $directory['last']['status'] ? 'success' : 'failure' ?>"><?= e($directory['last']['status']) ?></span><?php endif; ?>
      </li>
      <?php if (null !== $radius): ?>
        <li>
          <span class="service-icon" aria-hidden="true"><?= $icon('radius', '') ?></span>
          <span class="service-body">
            <strong>FreeRADIUS</strong>
            <span class="muted"><?= null === $radius['last_apply'] ? 'Configuration not applied from the portal yet' : 'Last apply ' . e(format_time($radius['last_apply']['at'])) ?></span>
          </span>
          <?php if (null === $radius['service']): ?><span class="status">not installed</span>
          <?php elseif ($radius['service']): ?><span class="status status-success">running</span>
          <?php else: ?><span class="status status-denied">stopped</span><?php endif; ?>
        </li>
      <?php endif; ?>
      <?php if (null !== $endpoints): ?>
        <li>
          <span class="service-icon" aria-hidden="true"><?= $icon('endpoints', '') ?></span>
          <span class="service-body">
            <strong>Computer agents</strong>
            <span class="muted"><?= $endpoints['total'] ?> enrolled · <?= $endpoints['online'] ?> online</span>
          </span>
          <?php if (0 === $endpoints['total']): ?><span class="status">none yet</span>
          <?php elseif ($endpoints['offline'] > 0): ?><span class="status status-failure"><?= $endpoints['offline'] ?> offline</span>
          <?php else: ?><span class="status status-success">healthy</span><?php endif; ?>
        </li>
      <?php endif; ?>
    </ul>
    <?php if ($can('directory.manage') || $can('settings.view')): ?>
      <a class="panel-link" href="<?= e(route('directory')) ?>"><?= $directory['enabled'] ? 'Open directory settings' : 'Set up AD/LDAP' ?> <?= $icon('arrow-right', 'nav-icon') ?></a>
    <?php endif; ?>
  </section>
</div>

<?php if ([] !== $recent): ?>
  <section class="panel">
    <div class="panel-head">
      <div><h2>Recent activity</h2><p class="panel-sub">Latest entries in the audit trail</p></div>
      <a class="button-small" href="<?= e(route('audit')) ?>">Open the audit trail</a>
    </div>
    <ol class="feed">
      <?php foreach ($recent as $entry): ?>
        <?php $who = (string) $entry['actor']; ?>
        <li class="feed-item">
          <span class="feed-avatar" aria-hidden="true"><?= e(mb_strtoupper(mb_substr($who, 0, 1))) ?></span>
          <span class="feed-body">
            <span><strong><?= e($who) ?></strong> <code><?= e($entry['action']) ?></code><?php if ('' !== (string) $entry['target']): ?> <span class="muted">on</span> <?= e($entry['target']) ?><?php endif; ?></span>
            <span class="feed-meta"><time datetime="<?= e($entry['time']) ?>" title="<?= e(str_replace(['T', 'Z'], [' ', ' UTC'], $entry['time'])) ?>"><?= e($ago($entry['time'])) ?></time><?php if ('' !== (string) $entry['ip']): ?> · <?= e($entry['ip']) ?><?php endif; ?></span>
          </span>
          <span class="status status-<?= e($entry['result']) ?>"><?= e($entry['result']) ?></span>
        </li>
      <?php endforeach; ?>
    </ol>
  </section>
<?php endif; ?>
