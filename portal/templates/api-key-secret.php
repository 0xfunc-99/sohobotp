<?php defined('PORTAL_ROOT') || exit; ?>
<div class="alert alert-info" role="status">
  This API key is shown <strong>only once</strong>. Store it in the program's secret store; it cannot be shown again (revoke it and create a new one if it is lost).
</div>
<p class="secret"><code><?= e($secret) ?></code></p>
<p>Use it as <code>Authorization: Bearer <?= e(substr($secret, 0, 19)) ?>…</code>. Permissions: <?= e(implode(', ', $key['scopes'])) ?>.</p>
<p><a class="button" href="<?= e(route('api-keys')) ?>">Back to API keys</a></p>
