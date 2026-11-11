<?php defined('PORTAL_ROOT') || exit; ?>
<?php if ($forced): ?>
  <div class="alert alert-info" role="status">You signed in with a temporary password. Choose your own password to continue.</div>
<?php endif; ?>
<section class="panel panel-narrow">
<form method="post" action="<?= e(route('password')) ?>" class="form">
  <?= csrf_field() ?>
  <label>Current password
    <input type="password" name="current_password" autocomplete="current-password" required>
  </label>
  <label>New password
    <input type="password" name="new_password" autocomplete="new-password" minlength="<?= (int) $min ?>" required>
    <small>At least <?= (int) $min ?> characters, not containing your username. A passphrase works well.</small>
  </label>
  <label>Repeat the new password
    <input type="password" name="confirm_password" autocomplete="new-password" minlength="<?= (int) $min ?>" required>
  </label>
  <button type="submit" class="button-primary">Change password</button>
</form>
</section>
