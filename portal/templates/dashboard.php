<?php defined('PORTAL_ROOT') || exit; ?>
<?php if (null !== $stats['error']): ?>
  <div class="alert alert-error" role="alert"><?= e($stats['error']) ?></div>
<?php endif; ?>
<section class="cards" aria-label="multiOTP status">
  <div class="card"><span class="card-label">Users</span><span class="card-value"><?= e($stats['users'] ?? '—') ?></span></div>
  <div class="card"><span class="card-label">Active users</span><span class="card-value"><?= e($stats['active'] ?? '—') ?></span></div>
  <div class="card<?= ($stats['locked'] ?? 0) > 0 ? ' card-warning' : '' ?>"><span class="card-label">Locked users</span><span class="card-value"><?= e($stats['locked'] ?? '—') ?></span></div>
  <div class="card"><span class="card-label">Hardware tokens</span><span class="card-value"><?= e($stats['tokens'] ?? '—') ?></span></div>
  <div class="card"><span class="card-label">Portal administrators</span><span class="card-value"><?= (int) $adminCount ?></span></div>
  <div class="card<?= $lockedAdmins > 0 ? ' card-warning' : '' ?>"><span class="card-label">Locked administrators</span><span class="card-value"><?= (int) $lockedAdmins ?></span></div>
</section>

<section class="panel">
  <h2>Coming in the next stages</h2>
  <p class="muted">Directory synchronisation status, FreeRADIUS health and endpoint status will appear here once those modules are built.</p>
</section>

<?php if ([] !== $recent): ?>
  <section class="panel">
    <h2>Recent activity</h2>
    <?php $entries = $recent; require PORTAL_ROOT . '/templates/partials/audit-table.php'; ?>
    <p><a href="<?= e(route('audit')) ?>">Open the audit trail</a></p>
  </section>
<?php endif; ?>
