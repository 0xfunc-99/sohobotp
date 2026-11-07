<?php defined('PORTAL_ROOT') || exit; ?>
<?php foreach ($flashes as $flash): ?>
  <div class="alert alert-<?= e($flash['type']) ?>" role="status"><?= e($flash['message']) ?></div>
<?php endforeach; ?>
<?php if (!empty($error)): ?>
  <div class="alert alert-error" role="alert"><?= e($error) ?></div>
<?php endif; ?>
