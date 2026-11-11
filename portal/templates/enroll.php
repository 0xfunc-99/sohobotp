<?php defined('PORTAL_ROOT') || exit; ?>
<p class="hint">Administrator accounts require a second factor. Scan this code with an authenticator app (Microsoft or Google Authenticator, FreeOTP or any TOTP app), then enter the code it shows.</p>
<?php if (null !== $qr): ?>
  <img class="qr" src="<?= e($qr) ?>" alt="QR code for your authenticator app" width="220" height="220">
<?php endif; ?>
<p class="hint">Can't scan? Enter this key manually (time-based, 6 digits, 30 seconds):</p>
<p class="secret"><code><?= e($secret) ?></code></p>
<form method="post" action="<?= e(route('enroll')) ?>" class="form">
  <?= csrf_field() ?>
  <label>Code from the app
    <input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,7}" required autofocus>
  </label>
  <button type="submit" class="button-primary">Confirm and sign in</button>
</form>
<form method="post" action="<?= e(route('logout')) ?>" class="form-secondary">
  <?= csrf_field() ?>
  <button type="submit" class="button-link">Cancel</button>
</form>
