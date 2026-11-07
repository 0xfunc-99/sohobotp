<?php defined('PORTAL_ROOT') || exit; ?>
<div class="alert alert-info" role="status">
  This temporary password is shown only once. Give it to <strong><?= e($subject['username']) ?></strong> over a separate, trusted channel.
  It expires in <?= (int) $hours ?> hours and must be changed at first sign-in.
</div>
<p class="secret"><code><?= e($password) ?></code></p>
<?php if (null === $subject['mfa_mode']): ?>
  <p class="hint">At sign-in, <?= e($subject['username']) ?> will set up an authenticator app before getting access.</p>
<?php endif; ?>
<p><a class="button" href="<?= e(null === $me ? route('login') : route('admins')) ?>"><?= null === $me ? 'Go to sign-in' : 'Back to administrators' ?></a></p>
