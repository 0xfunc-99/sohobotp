<?php defined('PORTAL_ROOT') || exit; ?>
<div class="toolbar">
  <input type="search" class="search" placeholder="Search administrators" data-filter-table="admins-table" aria-label="Search administrators">
  <a class="button-primary toolbar-end" href="<?= e(route('admin-new')) ?>">+ New administrator</a>
</div>
<div class="table-wrap">
  <table class="table" id="admins-table">
    <thead>
      <tr><th>Username</th><th>Name</th><th>Role</th><th>Status</th><th>Second factor</th><th>Last sign-in</th><th>Actions</th></tr>
    </thead>
    <tbody>
      <?php foreach ($admins as $a): ?>
        <?php $locked = Portal\AdminRepository::isLocked($a); ?>
        <tr>
          <td><a href="<?= e(route('admin-edit', ['id' => $a['id']])) ?>"><?= e($a['username']) ?></a><?= $a['id'] === $me['id'] ? ' <span class="muted">(you)</span>' : '' ?></td>
          <td><?= e($a['display_name']) ?></td>
          <td><?= e(Portal\Roles::label($a['role'])) ?></td>
          <td>
            <span class="status status-<?= 'active' === $a['status'] ? 'success' : 'denied' ?>"><?= e($a['status']) ?></span>
            <?php if ($locked): ?><span class="status status-failure">locked</span><?php endif; ?>
            <?php if ($a['must_change_password']): ?><span class="status status-info">temporary password</span><?php endif; ?>
          </td>
          <td><?= null === $a['mfa_mode'] ? '<span class="muted">not set up yet</span>' : ('portal' === $a['mfa_mode'] ? 'Authenticator app' : 'multiOTP: ' . e($a['mfa_user'])) ?></td>
          <td class="nowrap"><?= e(format_time($a['last_login_at'])) ?></td>
          <td class="row-actions">
            <?php
              $ops = ['reset-password' => 'Reset password', 'revoke-sessions' => 'Sign out'];
              if ($locked) { $ops['unlock'] = 'Unlock'; }
              if (null !== $a['mfa_mode'] && $a['id'] !== $me['id']) { $ops['reset-mfa'] = 'Reset 2FA'; }
              if ($a['id'] !== $me['id']) { $ops['active' === $a['status'] ? 'disable' : 'enable'] = 'active' === $a['status'] ? 'Disable' : 'Enable'; }
            ?>
            <?php foreach ($ops as $op => $label): ?>
              <form method="post" action="<?= e(route('admin-action')) ?>" class="inline" data-confirm="<?= e($label . ' for ' . $a['username'] . '?') ?>">
                <?= csrf_field() ?>
                <input type="hidden" name="id" value="<?= e($a['id']) ?>">
                <input type="hidden" name="op" value="<?= e($op) ?>">
                <button type="submit" class="button-small"><?= e($label) ?></button>
              </form>
            <?php endforeach; ?>
          </td>
        </tr>
      <?php endforeach; ?>
    </tbody>
  </table>
</div>
