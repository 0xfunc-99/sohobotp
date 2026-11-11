<?php defined('PORTAL_ROOT') || exit; ?>
<?php if ($chain['ok']): ?>
  <div class="alert alert-success" role="status"><strong>Integrity check passed:</strong> <?= (int) $chain['entries'] ?> entries, hash chain unbroken.</div>
<?php else: ?>
  <div class="alert alert-error" role="alert">Integrity check FAILED at line <?= (int) $chain['broken_at'] ?> of the audit file: entries were modified or removed.</div>
<?php endif; ?>

<form method="get" action="index.php" class="filters">
  <input type="hidden" name="r" value="audit">
  <label>Who <input name="actor" value="<?= e($filters['actor']) ?>"></label>
  <label>Action starts with <input name="action" value="<?= e($filters['action']) ?>" placeholder="auth., admin."></label>
  <label>Result
    <select name="result">
      <?php foreach (['' => 'Any', 'success' => 'Success', 'failure' => 'Failure', 'denied' => 'Denied'] as $value => $label): ?>
        <option value="<?= e($value) ?>"<?= $filters['result'] === $value ? ' selected' : '' ?>><?= e($label) ?></option>
      <?php endforeach; ?>
    </select>
  </label>
  <label>Target <input name="target" value="<?= e($filters['target']) ?>"></label>
  <label>From <input type="date" name="from" value="<?= e($filters['from']) ?>"></label>
  <label>To <input type="date" name="to" value="<?= e($filters['to']) ?>"></label>
  <label>Contains <input name="q" value="<?= e($filters['q']) ?>"></label>
  <button type="submit" class="button">Filter</button>
  <a href="<?= e(route('audit')) ?>" class="button-link">Clear</a>
</form>

<p class="table-count"><?= (int) $total ?> matching entries, newest first.</p>
<?php require PORTAL_ROOT . '/templates/partials/audit-table.php'; ?>

<?php if ($pages > 1): ?>
  <nav class="pager" aria-label="Pages">
    <?php $query = array_filter($filters, static fn ($v) => '' !== $v); ?>
    <?php if ($page > 1): ?><a href="<?= e(route('audit', $query + ['page' => $page - 1])) ?>">← Newer</a><?php endif; ?>
    <span>Page <?= (int) $page ?> of <?= (int) $pages ?></span>
    <?php if ($page < $pages): ?><a href="<?= e(route('audit', $query + ['page' => $page + 1])) ?>">Older →</a><?php endif; ?>
  </nav>
<?php endif; ?>
