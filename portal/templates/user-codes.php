<?php defined('PORTAL_ROOT') || exit; ?>
<div class="alert alert-info" role="status">
  Shown only once. Each code works one time instead of a token code, for example when the phone is lost.
  Give them to <strong><?= e($name) ?></strong> over a trusted channel; previous codes no longer work.
</div>
<ol class="codes">
  <?php foreach ($codes as $code): ?><li><code><?= e(substr($code, 0, 4) . ' ' . substr($code, 4)) ?></code></li><?php endforeach; ?>
</ol>
<p class="hint">Type the code without the space.</p>
<div class="actions"><a class="button-primary" href="<?= e(route('user', ['u' => $name])) ?>">Done</a></div>
