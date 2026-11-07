<?php defined('PORTAL_ROOT') || exit; ?>
<form method="post" action="<?= e(null === $subject ? route('admin-new') : route('admin-edit', ['id' => $subject['id']])) ?>" class="form narrow">
  <?= csrf_field() ?>
  <?php if (null === $subject): ?>
    <label>Username
      <input name="username" value="<?= e($input['username']) ?>" pattern="[a-z0-9][a-z0-9._\-]{1,63}" autocapitalize="none" spellcheck="false" required>
      <small>Lowercase letters, digits, dot, dash and underscore.</small>
    </label>
  <?php else: ?>
    <p><strong>Username:</strong> <?= e($subject['username']) ?></p>
  <?php endif; ?>
  <label>Display name <input name="display_name" value="<?= e($input['display_name']) ?>"></label>
  <label>Email <input type="email" name="email" value="<?= e($input['email']) ?>"></label>
  <fieldset>
    <legend>Role</legend>
    <?php foreach (Portal\Roles::ROLES as $role => $info): ?>
      <label class="choice">
        <input type="radio" name="role" value="<?= e($role) ?>"<?= $input['role'] === $role ? ' checked' : '' ?>>
        <span><strong><?= e($info['label']) ?></strong> — <?= e($info['description']) ?></span>
      </label>
    <?php endforeach; ?>
  </fieldset>
  <fieldset>
    <legend>Second factor</legend>
    <?php if (null === $subject): ?>
      <label class="choice">
        <input type="radio" name="mfa" value="enroll"<?= 'multiotp' !== $input['mfa'] ? ' checked' : '' ?>>
        <span><strong>Authenticator app</strong> — the administrator scans a QR code at first sign-in. Recommended.</span>
      </label>
      <label class="choice">
        <input type="radio" name="mfa" value="multiotp"<?= 'multiotp' === $input['mfa'] ? ' checked' : '' ?>>
        <span><strong>Existing multiOTP user</strong> — use that user's token, e.g. the administrator's own directory account.</span>
      </label>
      <label>multiOTP user (only for the second option) <input name="mfa_user" value="<?= e($input['mfa_user']) ?>"></label>
    <?php else: ?>
      <p class="muted">Currently: <?= null === $subject['mfa_mode'] ? 'not set up yet' : ('portal' === $subject['mfa_mode'] ? 'authenticator app' : 'multiOTP user ' . e($subject['mfa_user'])) ?>.
        To switch to an authenticator app, use “Reset 2FA” in the list.</p>
      <label>Link to multiOTP user <input name="mfa_user" value="<?= e($input['mfa_user']) ?>"><small>Leave unchanged to keep the current second factor.</small></label>
    <?php endif; ?>
  </fieldset>
  <?php if (null === $subject): ?>
    <p class="hint">A temporary password is generated and shown once. The administrator must change it at first sign-in.</p>
  <?php endif; ?>
  <div class="actions">
    <button type="submit" class="button-primary"><?= null === $subject ? 'Create administrator' : 'Save changes' ?></button>
    <a class="button-link" href="<?= e(route('admins')) ?>">Cancel</a>
  </div>
</form>
