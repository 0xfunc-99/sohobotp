<?php defined('PORTAL_ROOT') || exit; ?>
<section class="panel">
<h2>Profile</h2>
<dl class="details">
  <dt>Username</dt><dd><?= e($me['username']) ?></dd>
  <dt>Name</dt><dd><?= e($me['display_name'] ?: '—') ?></dd>
  <dt>Email</dt><dd><?= e($me['email'] ?: '—') ?></dd>
  <dt>Role</dt><dd><?= e(Portal\Roles::label($me['role'])) ?></dd>
  <dt>Second factor</dt><dd><?= 'multiotp' === $me['mfa_mode'] ? 'SohobOTP user ' . e($me['mfa_user']) : 'Authenticator app' ?></dd>
  <dt>Password changed</dt><dd><?= e(format_time($me['password_changed_at'])) ?></dd>
  <dt>Last sign-in</dt><dd><?= e(format_time($me['last_login_at'])) ?><?= $me['last_login_ip'] ? ' from ' . e($me['last_login_ip']) : '' ?></dd>
</dl>
</section>
<section class="panel">
<h2>Security</h2>
<p class="hint">Change your password regularly. “Sign out everywhere” ends every session of your account, including this one, for example after using a shared computer.</p>
<div class="actions">
  <a class="button-primary" href="<?= e(route('password')) ?>">Change password</a>
  <form method="post" action="<?= e(route('account')) ?>" class="inline" data-confirm="Sign out all your sessions, including this one?">
    <?= csrf_field() ?>
    <input type="hidden" name="op" value="revoke-sessions">
    <button type="submit" class="button-danger">Sign out everywhere</button>
  </form>
</div>
</section>
