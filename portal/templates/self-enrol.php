<?php defined('PORTAL_ROOT') || exit; ?>
<?php if ('login' === $step): ?>
  <p>Sign in with your usual <strong>work</strong> user name and password (the ones you use for your computer).</p>
  <form method="post" action="enrol.php" class="form">
    <?= csrf_field() ?><input type="hidden" name="step" value="login">
    <label>User name
      <input name="username" value="<?= e($username) ?>" autocomplete="username" autocapitalize="none" spellcheck="false" required autofocus>
    </label>
    <label>Password
      <input type="password" name="password" autocomplete="current-password" required>
    </label>
    <button type="submit" class="button-primary">Continue</button>
  </form>
  <p class="muted">Your password is only used to check who you are. It is not stored.</p>

<?php elseif ('scan' === $step): ?>
  <ol class="enrol-steps">
    <li>Install <strong>Google Authenticator</strong> or <strong>Microsoft Authenticator</strong> on your phone (App Store or Google Play).</li>
    <li>In the app, tap <strong>+</strong> and <strong>Scan a QR code</strong>, then scan this code:</li>
  </ol>
  <?php if (null !== $qr): ?><img class="qr" src="<?= e($qr) ?>" alt="QR code for <?= e($user) ?>" width="240" height="240"><?php endif; ?>
  <details class="enrol-manual">
    <summary>Can't scan? Type this key in the app instead</summary>
    <p><code><?= e($secret) ?></code> <span class="muted">(time-based, 6 digits)</span></p>
  </details>
  <form method="post" action="enrol.php" class="form">
    <?= csrf_field() ?><input type="hidden" name="step" value="confirm">
    <label>3. Type the 6-digit code the app shows now
      <input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,7}" maxlength="7" required autofocus>
    </label>
    <button type="submit" class="button-primary">Finish</button>
  </form>
  <form method="post" action="enrol.php" class="inline">
    <?= csrf_field() ?><input type="hidden" name="step" value="cancel">
    <button type="submit" class="button-link">Cancel</button>
  </form>
  <p class="muted">Signed in as <?= e($user) ?>. This page expires in <?= (int) $minutes ?> minute<?= 1 === (int) $minutes ? '' : 's' ?>. Nothing changes until you type the code.</p>

<?php elseif ('done' === $step): ?>
  <div class="alert alert-success" role="status">All done, <?= e($name) ?>. Your sign-in code is ready.</div>
  <p>From now on, when you sign in at work, type your password and then the 6-digit code from your authenticator app.</p>
  <p class="muted">Keep the app on your phone. If you change or lose your phone, ask your IT team to set up the code again.</p>

<?php else: /* closed, refused */ ?>
  <div class="alert alert-info" role="status"><?= e($message) ?></div>
<?php endif; ?>
