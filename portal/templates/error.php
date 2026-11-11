<?php defined('PORTAL_ROOT') || exit; ?>
<div class="error-box">
  <p><?= e($message) ?></p>
  <div class="actions"><a class="button-primary" href="<?= e(route('dashboard')) ?>">Back to the portal</a></div>
</div>
