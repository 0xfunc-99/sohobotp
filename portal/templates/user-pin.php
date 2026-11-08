<?php defined('PORTAL_ROOT') || exit; ?>
<div class="alert alert-info" role="status">
  Shown only once. <strong><?= e($name) ?></strong> now signs in with this PIN followed by the code from the token
  (for example <code><?= e($pin) ?>123456</code>). Give it over a trusted channel.
</div>
<p class="secret"><code><?= e($pin) ?></code></p>
<p><a class="button" href="<?= e(route('user', ['u' => $name])) ?>">Done</a></p>
