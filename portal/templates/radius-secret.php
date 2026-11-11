<?php defined('PORTAL_ROOT') || exit; ?>
<div class="alert alert-info" role="status">
  Shown only once. Enter this shared secret in the RADIUS settings of <strong><?= e($client['name']) ?></strong>
  (<code><?= e($client['address']) ?></code>), then apply the configuration.
</div>
<p class="secret"><code><?= e($secret) ?></code></p>
<dl class="details">
  <dt>RADIUS server</dt><dd>this appliance, UDP port 1812 (authentication)</dd>
  <dt>Client name sent to SohobOTP</dt><dd><code><?= e(Portal\Radius::shortname($client)) ?></code></dd>
</dl>
<div class="actions">
  <form method="post" action="<?= e(route('radius-apply')) ?>" class="inline"><?= csrf_field() ?>
    <button type="submit" class="button-primary">Apply configuration now</button></form>
  <a class="button" href="<?= e(route('radius')) ?>">Later</a>
</div>
