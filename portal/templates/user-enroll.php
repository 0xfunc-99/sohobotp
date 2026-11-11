<?php defined('PORTAL_ROOT') || exit; ?>
<div class="alert alert-info" role="status">
  Shown only once. Have <strong><?= e($name) ?></strong> scan this code now with an authenticator app
  (Microsoft or Google Authenticator, FreeOTP or any TOTP app). Do not screenshot or send it by email.
</div>
<?php if (null !== $qr): ?>
  <img class="qr" src="<?= e($qr) ?>" alt="Enrolment QR code for <?= e($name) ?>" width="240" height="240">
<?php endif; ?>
<p class="hint">Manual entry key (time-based, 6 digits, 30 seconds):</p>
<p class="secret"><code><?= e($secret) ?></code></p>
<div class="actions"><a class="button-primary" href="<?= e(route('user', ['u' => $name])) ?>">Done</a></div>
