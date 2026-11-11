<?php defined('PORTAL_ROOT') || exit; ?>
<p class="hint">
  <?php if ('multiotp' === $mode): ?>
    Enter the code from your SohobOTP token. If your token uses a PIN, type the PIN first, then the code.
  <?php else: ?>
    Enter the 6-digit code from your authenticator app.
  <?php endif; ?>
</p>
<form method="post" action="<?= e(route('mfa')) ?>" class="form">
  <?= csrf_field() ?>
  <label>Code
    <input name="code" inputmode="<?= 'multiotp' === $mode ? 'text' : 'numeric' ?>" autocomplete="one-time-code" required autofocus>
  </label>
  <button type="submit" class="button-primary">Verify</button>
</form>
<form method="post" action="<?= e(route('logout')) ?>" class="form-secondary">
  <?= csrf_field() ?>
  <button type="submit" class="button-link">Cancel</button>
</form>
