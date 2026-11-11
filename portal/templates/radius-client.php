<?php defined('PORTAL_ROOT') || exit; ?>
<p class="back"><a href="<?= e(route('radius')) ?>">← RADIUS servers</a></p>
<form method="post" action="<?= e(route('radius-client', null === $client ? [] : ['id' => $client['id']])) ?>" class="form narrow">
  <?= csrf_field() ?>
  <label>Name <input name="name" value="<?= e($input['name']) ?>" pattern="[a-z0-9][a-z0-9\-]{0,39}" maxlength="40" required placeholder="vpn-paris">
    <small>Lowercase letters, digits and dashes. Used as the FreeRADIUS client name.</small></label>
  <label>Description <input name="description" value="<?= e($input['description']) ?>" maxlength="255"></label>
  <label>IP address or network <input name="address" value="<?= e($input['address']) ?>" required placeholder="10.0.0.5 or 10.0.0.0/24">
    <small>The source address of the RADIUS requests. Host names are not accepted.</small></label>
  <label>Server group
    <select name="group_id">
      <?php foreach ($groups as $g): ?>
        <option value="<?= e($g['id']) ?>"<?= $input['group_id'] === $g['id'] ? ' selected' : '' ?>><?= e($g['name']) ?></option>
      <?php endforeach; ?>
    </select>
  </label>
  <label>Device type
    <select name="nas_type">
      <?php foreach (Portal\Radius::NAS_TYPES as $value => $label): ?>
        <option value="<?= e($value) ?>"<?= $input['nas_type'] === $value ? ' selected' : '' ?>><?= e($label) ?></option>
      <?php endforeach; ?>
    </select>
  </label>
  <label class="choice"><input type="checkbox" name="require_message_authenticator" value="1"<?= !empty($input['require_message_authenticator']) ? ' checked' : '' ?>>
    <span>Require Message-Authenticator (protects against the BlastRADIUS attack). Turn off only for old devices that cannot send it.</span></label>
  <?php if (null === $client): ?>
    <label>Shared secret <input type="password" name="secret" autocomplete="new-password" placeholder="Leave empty to generate a strong one">
      <small>Only if the device needs a specific secret: 16-128 characters, no quotes, backslash, $, % or spaces.</small></label>
  <?php else: ?>
    <p class="hint">The shared secret is not shown again. Use “New secret” in the list to replace it.</p>
  <?php endif; ?>
  <div class="actions">
    <button type="submit" class="button-primary"><?= null === $client ? 'Add server' : 'Save' ?></button>
    <a class="button-link" href="<?= e(route('radius')) ?>">Cancel</a>
  </div>
</form>
