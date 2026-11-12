<?php defined('PORTAL_ROOT') || exit; ?>
<?php
  $servers = $vip['servers'];
  $form = $vip['form'] ?? [];
  $value = static function (string $key, int $n) use ($form, $servers): string {
      if (isset($form["{$key}_$n"])) {
          return $form["{$key}_$n"];
      }
      $s = $servers[$n - 1] ?? null;
      return null === $s ? ('port' === $key ? '1812' : '') : (string) $s[$key];
  };
?>
<p class="back"><a href="<?= e(route('radius')) ?>">← VPNs and devices</a> · <a href="<?= e(route('radius-diagnostics')) ?>">Diagnostics</a></p>

<section class="panel">
  <h2>How it works</h2>
  <p>While you move users from Symantec VIP to SohobOTP, a VPN or firewall can keep one RADIUS
    server: SohobOTP. On a <strong>server group with forwarding on</strong>, SohobOTP checks the
    login of users who are on SohobOTP, and forwards every other login, unchanged, to your
    <strong>Symantec VIP Enterprise Gateway</strong> (its answer, including a challenge for the
    security code, goes back to the device).</p>
  <p>A user is on SohobOTP when an authenticator is enrolled or a hardware token assigned here,
    when an administrator moves them (user page, or the users list), or when they already used
    SohobOTP before forwarding was switched on. Users SohobOTP does not know are forwarded.</p>
  <p class="hint">On the Symantec VIP Enterprise Gateway, add this SohobOTP server's address as a
    RADIUS client of the validation server, with the shared secret you enter below.</p>
  <dl class="details">
    <dt>Status</dt>
    <dd>
      <?php if ([] === $servers): ?>Not configured: nothing is forwarded.
      <?php elseif ($active): ?><span class="status status-success">active</span> on FreeRADIUS
      <?php else: ?><span class="status status-failure">not applied yet</span> — nothing is forwarded until the configuration is applied
        <form method="post" action="<?= e(route('radius-apply')) ?>" class="inline"><?= csrf_field() ?><button type="submit" class="button-small">Apply configuration</button></form>
      <?php endif; ?>
    </dd>
    <dt>Server groups forwarding</dt>
    <dd><?= [] === $groups ? 'none yet (edit a server group and tick “Forward users who are not on SohobOTP yet”)' : e(implode(', ', $groups)) ?></dd>
    <dt>Users on SohobOTP</dt>
    <dd><?= (int) $counts['sohobotp'] ?><?= $counts['vip'] > 0 ? ' · sent back to Symantec VIP: ' . (int) $counts['vip'] : '' ?></dd>
  </dl>
  <form method="post" action="<?= e(route('radius-vip')) ?>" class="inline" data-confirm="Move every user who has a hardware token or has signed in with SohobOTP before to SohobOTP? Users moved by hand keep their choice.">
    <?= csrf_field() ?><input type="hidden" name="op" value="seed">
    <button type="submit" class="button">Move users already using SohobOTP</button>
  </form>
  <?php if (null !== $counts['seeded_at']): ?><span class="muted">Last done <?= e(format_time($counts['seeded_at'])) ?></span><?php endif; ?>
</section>

<section class="panel">
  <h2>Symantec VIP Enterprise Gateway</h2>
  <?php if (null !== $error): ?><div class="alert alert-error" role="alert"><?= e($error) ?></div><?php endif; ?>
  <form method="post" action="<?= e(route('radius-vip')) ?>" class="form narrow" autocomplete="off">
    <?= csrf_field() ?><input type="hidden" name="op" value="save">
    <?php foreach ([1, 2] as $n): $s = $servers[$n - 1] ?? null; ?>
      <fieldset>
        <legend><?= 1 === $n ? 'Server 1' : 'Server 2 (fail-over, optional)' ?></legend>
        <label>IPv4 address <input name="address_<?= $n ?>" value="<?= e($value('address', $n)) ?>" maxlength="15" inputmode="decimal" placeholder="10.0.0.20"></label>
        <label>RADIUS port <input name="port_<?= $n ?>" value="<?= e($value('port', $n)) ?>" maxlength="5" inputmode="numeric"></label>
        <label>Shared secret
          <input type="password" name="secret_<?= $n ?>" maxlength="128" autocomplete="new-password"
                 placeholder="<?= null === $s ? 'as configured on the gateway' : 'saved ' . e(format_time($s['secret_set_at'])) . ' — leave empty to keep' ?>">
        </label>
      </fieldset>
    <?php endforeach; ?>
    <label>Answer timeout (seconds)
      <input name="response_window" value="<?= e((string) ($form['response_window'] ?? $vip['response_window'])) ?>" maxlength="2" inputmode="numeric">
    </label>
    <label>Message-Authenticator in the gateway's answers (protects against forged answers, BlastRADIUS)
      <select name="message_authenticator">
        <?php foreach (Portal\Radius::VIP_MESSAGE_AUTHENTICATOR as $key => $label): ?>
          <option value="<?= e($key) ?>"<?= $vip['message_authenticator'] === $key ? ' selected' : '' ?>><?= e($label) ?></option>
        <?php endforeach; ?>
      </select>
    </label>
    <p class="hint">Leave server 1 empty to stop forwarding (users not on SohobOTP are then refused on groups with forwarding on).</p>
    <div class="actions"><button type="submit" class="button-primary">Save</button></div>
  </form>
</section>

<?php if ([] !== $servers): ?>
<section class="panel">
  <h2>Test the Symantec VIP server</h2>
  <p class="hint">Sends a login from this SohobOTP server straight to the gateway (not through FreeRADIUS): it checks the address, the shared secret and a Symantec user.</p>
  <?php if (null !== $test): ?>
    <div class="alert alert-<?= 'accepted' === $test['result'] ? 'success' : ('challenge' === $test['result'] ? 'info' : 'error') ?>" role="status">
      Server <?= (int) $test['server'] ?>, <?= e($test['user']) ?>: <strong><?= e($test['result']) ?></strong>
      <?= '' !== $test['reply_message'] ? '— ' . e($test['reply_message']) : '' ?>
      <?= null !== $test['error'] ? '— ' . e($test['error']) : '' ?>
      <?php if ('challenge' === $test['result']): ?>(the gateway asks for a second step: the address and secret are right)<?php endif; ?>
    </div>
  <?php endif; ?>
  <form method="post" action="<?= e(route('radius-vip')) ?>" class="form narrow" autocomplete="off">
    <?= csrf_field() ?><input type="hidden" name="op" value="test">
    <label>Server
      <select name="server"><?php foreach ($servers as $i => $s): ?><option value="<?= $i + 1 ?>"><?= $i + 1 ?> — <?= e($s['address'] . ':' . $s['port']) ?></option><?php endforeach; ?></select>
    </label>
    <label>Symantec VIP user <input name="user" maxlength="128" required></label>
    <label>Password / security code (as the VPN would send it) <input type="password" name="password" maxlength="256" autocomplete="off"></label>
    <div class="actions"><button type="submit" class="button">Send test login</button></div>
  </form>
</section>
<?php endif; ?>
