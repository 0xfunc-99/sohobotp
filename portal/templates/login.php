<?php defined('PORTAL_ROOT') || exit; ?>
<form method="post" action="<?= e(route('login')) ?>" class="form">
  <?= csrf_field() ?>
  <label>Username
    <input name="username" value="<?= e($username) ?>" autocomplete="username" autocapitalize="none" spellcheck="false" required autofocus>
  </label>
  <label>Password
    <input type="password" name="password" autocomplete="current-password" required>
  </label>
  <button type="submit" class="button-primary">Continue</button>
</form>
