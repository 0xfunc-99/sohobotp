<?php defined('PORTAL_ROOT') || exit; ?>
<?php $on = static fn (string $k): string => !empty($input[$k]) ? ' checked' : ''; ?>
<?php $modes = static function (string $name) use ($input): string {
    $value = (string) $input[$name];
    $html = '<select name="' . e($name) . '">';
    foreach (Portal\Endpoints::CP_MODES as $digit => $label) {
        foreach (['e' => 'multiOTP only', 'd' => 'other sign-in options too'] as $letter => $suffix) {
            $code = $digit . $letter;
            if ('3' === (string) $digit && 'd' === $letter) {
                continue;
            }
            $html .= '<option value="' . e($code) . '"' . ($value === $code ? ' selected' : '') . '>' . e('3' === (string) $digit ? $label : "$label, $suffix") . '</option>';
        }
    }
    return $html . '</select>';
}; ?>
<p><a href="<?= e(route('endpoint-groups')) ?>">← Endpoint groups</a></p>
<form method="post" action="<?= e(route('endpoint-group', null === $group ? [] : ['id' => $group['id']])) ?>" class="form narrow">
  <?= csrf_field() ?>
  <label>Name <input name="name" value="<?= e($input['name']) ?>" required maxlength="64" placeholder="Office laptops"></label>
  <label>Description <input name="description" value="<?= e($input['description']) ?>" maxlength="255"></label>
  <label>Check-in interval (seconds) <input name="checkin_interval" value="<?= (int) $input['checkin_interval'] ?>" inputmode="numeric">
    <small>How often agents ask for changes. An endpoint is shown offline after three missed check-ins.</small></label>
  <label>Agent version
    <select name="agent_version">
      <option value="">No automatic update</option>
      <?php foreach (Portal\AgentReleases::versions() as $version): ?><option value="<?= e($version) ?>"<?= $input['agent_version'] === $version ? ' selected' : '' ?>><?= e($version) ?></option><?php endforeach; ?>
    </select>
    <small>Machines with an older agent update themselves to this signed release (never downgraded). Releases are signed offline and added with portal-admin.php agent-release-add.</small></label>

  <fieldset>
    <legend>Linux (PAM → RADIUS)</legend>
    <label class="choice"><input type="checkbox" name="linux_enabled" value="1"<?= $on('linux_enabled') ?>><span><strong>Require a code on Linux machines</strong>. Turning it off removes the agent's PAM changes at the next check-in.</span></label>
    <label>RADIUS server group
      <select name="linux_radius_group_id">
        <option value="">—</option>
        <?php foreach ($radiusGroups as $rg): ?><option value="<?= e($rg['id']) ?>"<?= $input['linux_radius_group_id'] === $rg['id'] ? ' selected' : '' ?>><?= e($rg['name']) ?></option><?php endforeach; ?>
      </select>
      <small>Each Linux endpoint becomes a RADIUS client (its own address and secret) in this group, which sets the login policy.</small></label>
    <label>RADIUS servers <input name="linux_radius_servers" value="<?= e($input['linux_radius_servers']) ?>" placeholder="radius1.example.com, 10.0.0.6:1812">
      <small>In failover order. Empty: this portal's host name.</small></label>
    <label>Timeout per server (seconds) <input name="linux_timeout" value="<?= (int) $input['linux_timeout'] ?>" inputmode="numeric"></label>
    <div class="choices"><span>Protect</span>
      <?php foreach (Portal\Endpoints::LINUX_SERVICES as $value => $label): ?>
        <label class="choice"><input type="checkbox" name="linux_services[]" value="<?= e($value) ?>"<?= in_array($value, (array) $input['linux_services'], true) ? ' checked' : '' ?>><span><?= e($label) ?></span></label>
      <?php endforeach; ?>
    </div>
    <label>Users never asked for a code <input name="linux_excluded_users" value="<?= e($input['linux_excluded_users']) ?>" placeholder="backup, deploy">
      <small><code>root</code> is always excluded. Excluded users still need their normal password.</small></label>
    <label>Groups never asked for a code <input name="linux_excluded_groups" value="<?= e($input['linux_excluded_groups']) ?>">
      <small>Keep a local break-glass group so a RADIUS outage cannot lock everyone out.</small></label>
    <label class="choice"><input type="checkbox" name="linux_ssh_keys_need_code" value="1"<?= $on('linux_ssh_keys_need_code') ?>><span>SSH key logins also need the code</span></label>
    <label class="choice"><input type="checkbox" name="linux_require_message_authenticator" value="1"<?= $on('linux_require_message_authenticator') ?>><span>Require Message-Authenticator from these machines (only if all have pam_radius 2.0.1 or later)</span></label>
  </fieldset>

  <fieldset>
    <legend>Windows (SohobOTP Sign-in)</legend>
    <label>Sign-in <?= $modes('win_cpus_logon') ?></label>
    <label>Unlock <?= $modes('win_cpus_unlock') ?></label>
    <label>Administrator prompts (UAC) <?= $modes('win_cpus_credui') ?></label>
    <label>Account never asked for a code <input name="win_excluded_account" value="<?= e($input['win_excluded_account']) ?>" placeholder="COMPUTER\breakglass">
      <small>One local break-glass account, DOMAIN\user or COMPUTER\user.</small></label>
    <label class="choice"><input type="checkbox" name="win_cache_enabled" value="1"<?= $on('win_cache_enabled') ?>>
      <span><strong>Offline cache</strong>: users who signed in on the machine can still sign in with a code when it is off the network. The machine then keeps a copy of their token secret: a stolen laptop carries it.</span></label>
    <label>Offline cache lifetime (days) <input name="win_cache_days" value="<?= (int) $input['win_cache_days'] ?>" inputmode="numeric"></label>
    <label>Unlock grace period (minutes) <input name="win_timeout_unlock" value="<?= (int) $input['win_timeout_unlock'] ?>" inputmode="numeric"><small>0: always ask on unlock.</small></label>
    <label>Server timeout (seconds) <input name="win_server_timeout" value="<?= (int) $input['win_server_timeout'] ?>" inputmode="numeric"></label>
    <label class="choice"><input type="checkbox" name="win_upn_format" value="1"<?= $on('win_upn_format') ?>><span>Send user names as user@domain (UPN)</span></label>
    <label>Default domain prefix <input name="win_default_prefix" value="<?= e($input['win_default_prefix']) ?>" maxlength="64"></label>
    <label class="choice"><input type="checkbox" name="win_without2fa" value="1"<?= $on('win_without2fa') ?>><span>Users without a token sign in without a code (migration only)</span></label>
    <label class="choice"><input type="checkbox" name="win_two_step_hide_otp" value="1"<?= $on('win_two_step_hide_otp') ?>><span>Ask for the code in a second step</span></label>
    <label class="choice"><input type="checkbox" name="win_two_step_send_password" value="1"<?= $on('win_two_step_send_password') ?>><span>Send the Windows password to the server (for "directory password + code")</span></label>
    <label>Text under the logo <input name="win_login_text" value="<?= e($input['win_login_text']) ?>" maxlength="100"></label>
    <label>Code field label <input name="win_otp_text" value="<?= e($input['win_otp_text']) ?>" maxlength="100"></label>
  </fieldset>
  <div class="actions">
    <button type="submit" class="button-primary">Save group</button>
    <a class="button-link" href="<?= e(route('endpoint-groups')) ?>">Cancel</a>
  </div>
</form>
