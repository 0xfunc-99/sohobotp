<?php defined('PORTAL_ROOT') || exit; ?>
<div class="alert alert-info" role="status">
  This pairing code is shown <strong>only once</strong>. It contains the passwords of the replication and the pairing key:
  paste it on the secondary (<?= e($secondary) ?>, <em>High availability → Join as secondary</em>) and do not keep it anywhere else.
</div>
<p class="secret"><code><?= e($code) ?></code></p>
<div class="actions"><a class="button-primary" href="<?= e(route('ha')) ?>">Back to high availability</a></div>
