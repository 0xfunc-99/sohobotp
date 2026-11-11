<?php defined('PORTAL_ROOT') || exit; ?>
<?php
  $icon = require PORTAL_ROOT . '/templates/partials/icons.php';
  $can = static fn (string $permission): bool => Portal\Roles::can($me['role'], $permission);
  $card = static function (string $label, mixed $value, ?string $href = null, bool $warning = false): string {
      $class = 'card' . ($warning ? ' card-warning' : '') . (null !== $href ? ' card-link' : '');
      $inner = '<span class="card-label">' . e($label) . '</span><span class="card-value">' . e($value) . '</span>';
      return null === $href ? '<div class="' . $class . '">' . $inner . '</div>' : '<a class="' . $class . '" href="' . e($href) . '">' . $inner . '</a>';
  };
  $usersLink = static fn (array $query = []): ?string => $can('users.view') ? route('users', $query) : null;
?>
<?php if (null !== $stats['error']): ?>
  <div class="alert alert-error" role="alert"><?= e($stats['error']) ?></div>
<?php endif; ?>
<section class="cards" aria-label="multiOTP status">
  <?= $card('Users', $stats['users'] ?? '—', $usersLink()) ?>
  <?= $card('Active users', $stats['active'] ?? '—', $usersLink(['status' => 'enabled'])) ?>
  <?= $card('Locked users', $stats['locked'] ?? '—', $usersLink(['status' => 'locked']), ($stats['locked'] ?? 0) > 0) ?>
  <?= $card('Hardware tokens', $stats['tokens'] ?? '—', $can('tokens.view') ? route('tokens') : null) ?>
  <?= $card('Portal administrators', (int) $adminCount, $can('admins.manage') ? route('admins') : null) ?>
  <?= $card('Locked administrators', (int) $lockedAdmins, $can('admins.manage') ? route('admins') : null, $lockedAdmins > 0) ?>
</section>

<div class="grid-2">
  <section class="panel">
    <h2>Directory synchronisation</h2>
    <?php if (!$directory['enabled']): ?>
      <p class="muted">No directory is configured. Users are created by hand until Active Directory or LDAP is connected.</p>
      <?php if ($can('directory.manage')): ?><a class="button" href="<?= e(route('directory')) ?>"><?= $icon('directory', '') ?>Set up AD/LDAP</a><?php endif; ?>
    <?php else: ?>
      <dl class="details">
        <dt>Last sync</dt>
        <dd><?php if (null === $directory['last']): ?>never<?php else: ?>
          <?= e(format_time($directory['last']['at'])) ?> —
          <span class="status status-<?= 'succeeded' === $directory['last']['status'] ? 'success' : 'failure' ?>"><?= e($directory['last']['status']) ?></span>
          <?= (int) $directory['last']['summary']['created'] ?> created, <?= (int) $directory['last']['summary']['disabled'] ?> disabled
        <?php endif; ?></dd>
        <dt>Schedule</dt><dd><?= !empty($directory['schedule']['enabled']) ? 'every ' . (int) $directory['schedule']['minutes'] . ' minutes' : 'manual only' ?></dd>
        <?php if (null !== $directory['active'] && in_array($directory['active']['status'], Portal\Jobs::ACTIVE, true)): ?>
          <dt>Now</dt><dd><span class="status status-info">sync <?= e($directory['active']['status']) ?></span></dd>
        <?php endif; ?>
      </dl>
      <a class="panel-link" href="<?= e(route('directory')) ?>">Open directory settings <?= $icon('arrow-right', 'nav-icon') ?></a>
    <?php endif; ?>
  </section>

  <section class="panel">
    <h2>Shortcuts</h2>
    <div class="tiles">
      <?php if ($can('users.view')): ?>
        <a class="tile" href="<?= e(route('users')) ?>"><?= $icon('users', '') ?><span><strong>Find a user</strong><span>Unlock, resync or enrol an authenticator</span></span></a>
      <?php endif; ?>
      <?php if ($can('radius.view')): ?>
        <a class="tile" href="<?= e(route('radius-diagnostics')) ?>"><?= $icon('activity', '') ?><span><strong>RADIUS diagnostics</strong><span>Service state, test logins, recent logins</span></span></a>
      <?php endif; ?>
      <?php if ($can('endpoints.view')): ?>
        <a class="tile" href="<?= e(route('endpoints')) ?>"><?= $icon('endpoints', '') ?><span><strong>Endpoints</strong><span>Machines, check-ins and approvals</span></span></a>
      <?php endif; ?>
      <?php if ($can('audit.view')): ?>
        <a class="tile" href="<?= e(route('audit')) ?>"><?= $icon('audit', '') ?><span><strong>Audit trail</strong><span>Who did what, and when</span></span></a>
      <?php endif; ?>
      <a class="tile" href="<?= e(route('account')) ?>"><?= $icon('account', '') ?><span><strong>My account</strong><span>Password and sessions</span></span></a>
    </div>
  </section>
</div>

<?php if ([] !== $recent): ?>
  <section class="panel">
    <div class="toolbar">
      <h2>Recent activity</h2>
      <a class="button-small" href="<?= e(route('audit')) ?>">Open the audit trail</a>
    </div>
    <?php $entries = $recent; require PORTAL_ROOT . '/templates/partials/audit-table.php'; ?>
  </section>
<?php endif; ?>
