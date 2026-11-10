<?php defined('PORTAL_ROOT') || exit; ?>
<form method="get" action="index.php" class="toolbar">
  <input type="hidden" name="r" value="users">
  <input type="search" name="q" value="<?= e($q) ?>" class="search" placeholder="Search name, email, group, token" aria-label="Search users">
  <select name="status" aria-label="Status">
    <?php foreach (Portal\Users::STATUSES as $value => $label): ?>
      <option value="<?= e($value) ?>"<?= $status === $value ? ' selected' : '' ?>><?= e($label) ?></option>
    <?php endforeach; ?>
  </select>
  <button type="submit" class="button">Search</button>
  <?php if ($canCreate): ?><a class="button-primary" href="<?= e(route('user-new')) ?>">New user</a><?php endif; ?>
</form>

<p class="muted"><?= (int) $total ?> user(s)<?= '' !== $q || '' !== $status ? ' matching' : '' ?>.</p>

<form method="post" action="<?= e(route('user-bulk')) ?>" data-confirm="Apply this action to the selected users?">
  <?= csrf_field() ?>
  <input type="hidden" name="q" value="<?= e($q) ?>">
  <input type="hidden" name="status" value="<?= e($status) ?>">
  <?php if ([] !== $bulk): ?>
    <div class="toolbar">
      <select name="op" aria-label="Action for selected users">
        <option value="">With selected…</option>
        <?php foreach ($bulk as $op): ?><option value="<?= e($op) ?>"><?= e(Portal\UsersController::BULK_LABELS[$op] ?? ucfirst($op)) ?></option><?php endforeach; ?>
      </select>
      <button type="submit" class="button">Apply</button>
    </div>
  <?php endif; ?>
  <div class="table-wrap">
    <table class="table" id="users-table">
      <thead>
        <tr>
          <?php if ([] !== $bulk): ?><th><input type="checkbox" data-check-all="users-table" aria-label="Select all"></th><?php endif; ?>
          <th>User</th><th>Name</th><th>Email</th><th>Group</th><th>Status</th><th>Source</th><th>Token</th>
        </tr>
      </thead>
      <tbody>
        <?php foreach ($users as $u): ?>
          <tr>
            <?php if ([] !== $bulk): ?><td><input type="checkbox" name="users[]" value="<?= e($u['user']) ?>" aria-label="Select <?= e($u['user']) ?>"></td><?php endif; ?>
            <td><a href="<?= e(route('user', ['u' => $u['user']])) ?>"><?= e($u['user']) ?></a></td>
            <td><?= e($u['display_name'] ?: $u['description']) ?></td>
            <td><?= e($u['email']) ?></td>
            <td><?= e($u['group']) ?></td>
            <td>
              <span class="status status-<?= $u['enabled'] ? 'success' : 'denied' ?>"><?= $u['enabled'] ? 'enabled' : 'disabled' ?></span>
              <?php if ($u['locked']): ?><span class="status status-failure">locked</span><?php endif; ?>
            </td>
            <td><?= (int) $u['synchronized'] ? 'Directory' : 'Local' ?></td>
            <td><?= '' !== (string) $u['token'] ? e($u['token']) : '<span class="muted">software</span>' ?></td>
          </tr>
        <?php endforeach; ?>
        <?php if ([] === $users): ?>
          <tr><td colspan="8" class="muted">No users.</td></tr>
        <?php endif; ?>
      </tbody>
    </table>
  </div>
</form>

<?php if ($pages > 1): ?>
  <nav class="pager" aria-label="Pages">
    <?php $query = array_filter(['q' => $q, 'status' => $status]); ?>
    <?php if ($page > 1): ?><a href="<?= e(route('users', $query + ['page' => $page - 1])) ?>">← Previous</a><?php endif; ?>
    <span>Page <?= (int) $page ?> of <?= (int) $pages ?></span>
    <?php if ($page < $pages): ?><a href="<?= e(route('users', $query + ['page' => $page + 1])) ?>">Next →</a><?php endif; ?>
  </nav>
<?php endif; ?>
