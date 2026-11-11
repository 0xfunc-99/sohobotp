<?php defined('PORTAL_ROOT') || exit; ?>
<p class="hint">Users from AD/LDAP are created by the directory sync. Create users here only for accounts that are not in the directory.</p>
<form method="post" action="<?= e(route('user-new')) ?>" class="form narrow">
  <?= csrf_field() ?>
  <label>Username <input name="user" value="<?= e($input['user']) ?>" autocapitalize="none" spellcheck="false" required>
    <small>The name people type at the RADIUS or Windows login.</small></label>
  <label>Display name <input name="display_name" value="<?= e($input['display_name']) ?>"></label>
  <label>Email <input type="email" name="email" value="<?= e($input['email']) ?>"></label>
  <label>Mobile (SMS) <input name="sms" value="<?= e($input['sms']) ?>" inputmode="tel"></label>
  <label>Description <input name="description" value="<?= e($input['description']) ?>"></label>
  <label>SohobOTP group <input name="group" value="<?= e($input['group']) ?>"></label>
  <fieldset>
    <legend>Token</legend>
    <label class="choice"><input type="radio" name="token_serial" value=""<?= '' === $input['token_serial'] ? ' checked' : '' ?>>
      <span><strong>Authenticator app</strong> — a QR code is shown once after creation.</span></label>
    <?php foreach ($freeTokens as $serial): ?>
      <label class="choice"><input type="radio" name="token_serial" value="<?= e($serial) ?>"<?= $input['token_serial'] === $serial ? ' checked' : '' ?>>
        <span>Hardware token <code><?= e($serial) ?></code></span></label>
    <?php endforeach; ?>
    <?php if ([] === $freeTokens): ?><p class="muted">No unassigned hardware tokens. Import them on the Hardware tokens page.</p><?php endif; ?>
  </fieldset>
  <div class="actions">
    <button type="submit" class="button-primary">Create user</button>
    <a class="button-link" href="<?= e(route('users')) ?>">Cancel</a>
  </div>
</form>
