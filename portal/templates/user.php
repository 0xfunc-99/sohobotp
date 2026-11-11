<?php defined('PORTAL_ROOT') || exit; ?>
<?php
  $action = static function (string $op, string $label, string $confirm = '', string $class = 'button') use ($user): string {
      return '<form method="post" action="' . e(route('user-action')) . '" class="inline"' . ('' !== $confirm ? ' data-confirm="' . e($confirm) . '"' : '') . '>'
          . csrf_field() . '<input type="hidden" name="u" value="' . e($user['user']) . '"><input type="hidden" name="op" value="' . e($op) . '">'
          . '<button type="submit" class="' . e($class) . '">' . e($label) . '</button></form>';
  };
?>
<p class="back"><a href="<?= e(route('users')) ?>">← All users</a></p>

<?php
  $who = trim((string) ($user['display_name'] ?: $user['description']));
  $letters = '';
  foreach (array_slice(preg_split('/[\s._-]+/u', $who ?: $user['user']) ?: [], 0, 2) as $word) { $letters .= mb_strtoupper(mb_substr($word, 0, 1)); }
?>
<div class="profile">
  <span class="avatar avatar-lg" aria-hidden="true"><?= e($letters) ?></span>
  <div class="profile-main">
    <p class="profile-name"><?= e('' !== $who ? $who : $user['user']) ?></p>
    <p class="profile-meta">
      <span class="status status-<?= $user['enabled'] ? 'success' : 'denied' ?>"><?= $user['enabled'] ? 'enabled' : 'disabled' ?></span>
      <?php if ($user['locked']): ?><span class="status status-failure">locked</span><?php endif; ?>
      <span class="badge"><?= $user['synchronized'] ? 'Directory' : 'Local' ?></span>
      <?php if ('' !== (string) $user['email']): ?><span class="muted"><?= e($user['email']) ?></span><?php endif; ?>
    </p>
  </div>
  <div class="actions profile-actions">
    <?php if ($user['locked'] && $perm['unlock']): ?><?= $action('unlock', 'Unlock', '', 'button-primary') ?><?php endif; ?>
    <?php if ($perm['manage']): ?>
      <?= $user['enabled'] ? $action('disable', 'Disable', 'Disable ' . $user['user'] . '? RADIUS logins will be refused.') : $action('enable', 'Enable') ?>
    <?php endif; ?>
  </div>
</div>

<div class="grid-2">

<section class="panel">
  <h2>Details</h2>
  <dl class="details">
    <dt>Source</dt><dd><?= $user['synchronized'] ? 'Directory sync' . ('' !== $user['synced_server'] ? ' (' . e($user['synced_server']) . ')' : '') : 'Local user' ?></dd>
    <?php if ($user['synchronized']): ?>
      <dt>Directory DN</dt><dd><code><?= e($user['synced_dn']) ?></code></dd>
      <dt>Last synced</dt><dd><?= e(format_time($user['synced_time'])) ?></dd>
    <?php endif; ?>
    <dt>Token</dt><dd><?= '' !== $user['token_serial'] ? 'Hardware token <code>' . e($user['token_serial']) . '</code>' : 'Software (' . e(strtoupper($user['algorithm'] ?: '—')) . ')' ?></dd>
    <dt>Login format</dt>
    <dd>
      <?= e(Portal\Users::LOGIN_FORMATS[$user['login_format']]) ?>
      <?php if ($perm['manage']): ?>
        <form method="post" action="<?= e(route('user-action')) ?>" class="inline" data-confirm="Change how <?= e($user['user']) ?> signs in? Tell the user before they next log in.">
          <?= csrf_field() ?><input type="hidden" name="u" value="<?= e($user['user']) ?>"><input type="hidden" name="op" value="login-format">
          <select name="format" aria-label="Login format">
            <?php foreach (Portal\Users::LOGIN_FORMATS as $value => $label): ?>
              <?php if ('directory' === $value && !$user['synchronized']) { continue; } ?>
              <option value="<?= e($value) ?>"<?= $user['login_format'] === $value ? ' selected' : '' ?>><?= e($label) ?></option>
            <?php endforeach; ?>
          </select>
          <button type="submit" class="button-small">Change</button>
        </form>
      <?php endif; ?>
    </dd>
    <?php if ([] !== $vipGroups || null !== $vipRoute): ?>
      <dt>Symantec VIP migration</dt>
      <dd>
        <?php $onSohobotp = 'sohobotp' === ($vipRoute['state'] ?? null); ?>
        <?= $onSohobotp ? '<strong>On SohobOTP</strong>' : '<strong>Still on Symantec VIP</strong>: forwarded on ' . e(implode(', ', $vipGroups) ?: 'server groups with forwarding on') ?>
        <?php if (null !== $vipRoute): ?><span class="muted">(<?= e($vipRoute['how']) ?>, <?= e(format_time($vipRoute['at'])) ?>)</span><?php endif; ?>
        <?php if ($perm['manage']): ?>
          <form method="post" action="<?= e(route('user-action')) ?>" class="inline" data-confirm="<?= $onSohobotp ? 'Send ' . e($user['user']) . ' back to Symantec VIP?' : 'Move ' . e($user['user']) . ' to SohobOTP? They need a working SohobOTP authenticator.' ?>">
            <?= csrf_field() ?><input type="hidden" name="u" value="<?= e($user['user']) ?>"><input type="hidden" name="op" value="vip-route">
            <input type="hidden" name="route" value="<?= $onSohobotp ? 'vip' : 'sohobotp' ?>">
            <button type="submit" class="button-small"><?= $onSohobotp ? 'Send back to Symantec VIP' : 'Move to SohobOTP' ?></button>
          </form>
        <?php endif; ?>
      </dd>
    <?php endif; ?>
    <dt>Recovery codes left</dt><dd><?= (int) $user['recovery_codes'] ?></dd>
    <dt>Failed attempts</dt><dd><?= (int) $user['error_counter'] ?></dd>
    <dt>Last login</dt><dd><?= e(format_time($user['last_login'])) ?></dd>
  </dl>
</section>

<?php if ($perm['enroll'] || $perm['resync'] || $perm['tokens']): ?>
<section class="panel">
  <h2>Authenticator and token</h2>
  <p class="hint"><?= '' !== $user['token_serial'] ? 'Hardware token ' . e($user['token_serial']) . ' is assigned.' : 'Uses an authenticator app.' ?> <?= (int) $user['recovery_codes'] ?> recovery code(s) left.</p>
  <div class="actions">
    <?php if ($perm['enroll'] && '' === $user['token_serial']): ?>
      <?= $action('enroll', 'Enrol new authenticator', 'This replaces the current token: the old app entry stops working. Continue?', 'button-primary') ?>
    <?php endif; ?>
    <?php if ($perm['enroll']): ?>
      <?= $action('recovery-codes', 'New recovery codes', 'Generate 10 new recovery codes? Previous codes stop working.') ?>
    <?php endif; ?>
    <?php if ($perm['tokens'] && '' !== $user['token_serial']): ?>
      <?= $action('remove-token', 'Remove hardware token', 'Remove token ' . $user['token_serial'] . ' from ' . $user['user'] . '?') ?>
    <?php endif; ?>
  </div>
  <?php if ($perm['tokens'] && '' === $user['token_serial'] && [] !== $freeTokens): ?>
    <form method="post" action="<?= e(route('user-action')) ?>" class="toolbar subform">
      <?= csrf_field() ?>
      <input type="hidden" name="u" value="<?= e($user['user']) ?>">
      <input type="hidden" name="op" value="assign-token">
      <label>Assign hardware token
        <select name="serial"><?php foreach ($freeTokens as $serial): ?><option value="<?= e($serial) ?>"><?= e($serial) ?></option><?php endforeach; ?></select>
      </label>
      <button type="submit" class="button">Assign</button>
    </form>
  <?php endif; ?>
  <?php if ($perm['resync']): ?>
    <form method="post" action="<?= e(route('user-action')) ?>" class="toolbar subform">
      <?= csrf_field() ?>
      <input type="hidden" name="u" value="<?= e($user['user']) ?>">
      <input type="hidden" name="op" value="resync">
      <label>Resync: first code <input name="code1" inputmode="numeric" autocomplete="off" required></label>
      <label>next code <input name="code2" inputmode="numeric" autocomplete="off" required></label>
      <button type="submit" class="button">Resync token</button>
    </form>
  <?php endif; ?>
</section>
<?php endif; ?>
</div>

<?php if ($perm['manage']): ?>
<section class="panel">
  <h2>Edit user</h2>
  <?php if ($user['synchronized']): ?><p class="hint">This user comes from the directory: the next sync may overwrite name, email and mobile.</p><?php endif; ?>
  <form method="post" action="<?= e(route('user-action')) ?>" class="form narrow">
    <?= csrf_field() ?>
    <input type="hidden" name="u" value="<?= e($user['user']) ?>">
    <input type="hidden" name="op" value="save">
    <label>Display name <input name="display_name" value="<?= e($user['display_name']) ?>"></label>
    <label>Email <input type="email" name="email" value="<?= e($user['email']) ?>"></label>
    <label>Mobile (SMS) <input name="sms" value="<?= e($user['sms']) ?>"></label>
    <label>Description <input name="description" value="<?= e($user['description']) ?>"></label>
    <label>multiOTP group <input name="group" value="<?= e($user['group']) ?>"></label>
    <div class="actions"><button type="submit" class="button-primary">Save</button></div>
  </form>
  <div class="actions danger-zone">
    <?= $action('delete', 'Delete user', 'Delete ' . $user['user'] . ' permanently?' . ($user['synchronized'] ? ' It will be created again by the next sync if it is still in the directory.' : ''), 'button-danger') ?>
  </div>
</section>
<?php endif; ?>
