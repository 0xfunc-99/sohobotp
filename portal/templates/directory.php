<?php defined('PORTAL_ROOT') || exit; ?>
<?php
  $s = $settings;
  $ro = $perm['manage'] ? '' : ' disabled';
  $checked = static fn (string $key): string => !empty($s[$key]) ? ' checked' : '';
?>
<section class="panel">
  <h2>Synchronisation</h2>
  <dl class="details">
    <dt>Directory</dt><dd><?= !empty($s['enabled']) ? '<span class="status status-success">enabled</span>' : '<span class="status status-denied">disabled</span>' ?></dd>
    <dt>Last sync</dt>
    <dd>
      <?php if (null === $lastSync): ?>never
      <?php else: ?>
        <?= e(format_time($lastSync['at'])) ?> —
        <span class="status status-<?= 'succeeded' === $lastSync['status'] ? 'success' : 'failure' ?>"><?= e($lastSync['status']) ?></span>
        <?= (int) $lastSync['summary']['created'] ?> created, <?= (int) $lastSync['summary']['disabled'] ?> disabled,
        <?= (int) $lastSync['summary']['enabled'] ?> re-enabled, <?= (int) $lastSync['summary']['deleted'] ?> deleted
        <?php if ($perm['jobs']): ?>(<a href="<?= e(route('job', ['id' => $lastSync['job']])) ?>">details</a>)<?php endif; ?>
      <?php endif; ?>
    </dd>
    <dt>Schedule</dt><dd><?= !empty($s['schedule_enabled']) ? 'every ' . (int) $s['schedule_minutes'] . ' minutes' . (null !== $nextRun ? ', next around ' . e(format_time(max($nextRun, time()))) : '') : 'manual only' ?></dd>
  </dl>
  <?php foreach ($active as $job): ?>
    <div class="alert alert-info" role="status"><?= e(Portal\DirectoryController::label($job['type'])) ?> is <?= e($job['status']) ?>.
      <a href="<?= e(route('job', ['id' => $job['id']])) ?>">Follow progress</a></div>
  <?php endforeach; ?>
  <div class="actions">
    <?php if ($perm['sync']): ?>
      <form method="post" action="<?= e(route('directory-run')) ?>" class="inline"><?= csrf_field() ?><input type="hidden" name="op" value="sync">
        <button type="submit" class="button-primary"<?= empty($s['enabled']) ? ' disabled' : '' ?>>Sync now</button></form>
    <?php endif; ?>
    <?php if ($perm['manage']): ?>
      <form method="post" action="<?= e(route('directory-run')) ?>" class="inline"><?= csrf_field() ?><input type="hidden" name="op" value="preview">
        <button type="submit" class="button">Preview changes</button></form>
      <form method="post" action="<?= e(route('directory-test')) ?>" class="inline"><?= csrf_field() ?>
        <button type="submit" class="button">Test connection</button></form>
    <?php endif; ?>
    <?php if ($perm['jobs']): ?><a class="button-link toolbar-end" href="<?= e(route('jobs')) ?>">Sync history</a><?php endif; ?>
  </div>
  <?php if (null !== $test): ?>
    <div class="alert alert-<?= $test['ok'] ? 'success' : 'error' ?>" role="status"><?= e($test['message']) ?></div>
    <?php if ([] !== $test['log']): ?><pre class="log"><?= e(implode("\n", $test['log'])) ?></pre><?php endif; ?>
  <?php endif; ?>
</section>

<form method="post" action="<?= e(route('directory-save')) ?>" class="form settings-form">
  <?= csrf_field() ?>
  <?php if (!$perm['manage']): ?><div class="alert alert-info" role="status">Read only: your role cannot change directory settings.</div><?php endif; ?>

  <fieldset>
    <legend>Connection</legend>
    <label class="choice"><input type="checkbox" name="enabled" value="1"<?= $checked('enabled') . $ro ?>><span>Use this directory (sync users and check directory passwords)</span></label>
    <label>Directory type
      <select name="server_type"<?= $ro ?>>
        <?php foreach (Portal\Directory::TYPES as $value => $label): ?>
          <option value="<?= (int) $value ?>"<?= (int) $s['server_type'] === $value ? ' selected' : '' ?>><?= e($label) ?></option>
        <?php endforeach; ?>
      </select>
    </label>
    <label>Domain controllers / LDAP servers <input name="domain_controllers" value="<?= e($s['domain_controllers']) ?>" placeholder="dc1.corp.example dc2.corp.example"<?= $ro ?>>
      <small>Host names separated by spaces; the next one is tried if the first does not answer.</small></label>
    <div class="row">
      <label>Port <input name="port" value="<?= e($s['port']) ?>" inputmode="numeric"<?= $ro ?>></label>
      <label>Timeout (s) <input name="network_timeout" value="<?= e($s['network_timeout']) ?>" inputmode="numeric"<?= $ro ?>></label>
    </div>
    <label class="choice"><input type="checkbox" name="ssl" value="1"<?= $checked('ssl') . $ro ?>><span>LDAPS (TLS, usually port 636). Strongly recommended.</span></label>
    <label>Server certificate check
      <select name="tls_reqcert"<?= $ro ?>>
        <?php foreach (['demand' => 'Verify (recommended)', 'auto' => 'System default', 'never' => 'Do not verify (testing only)'] as $value => $label): ?>
          <option value="<?= e($value) ?>"<?= $s['tls_reqcert'] === $value ? ' selected' : '' ?>><?= e($label) ?></option>
        <?php endforeach; ?>
      </select>
    </label>
    <label>Base DN <input name="base_dn" value="<?= e($s['base_dn']) ?>" placeholder="DC=corp,DC=example"<?= $ro ?>></label>
    <label>Bind DN (service account) <input name="bind_dn" value="<?= e($s['bind_dn']) ?>" placeholder="CN=svc-sohobotp,OU=Service,DC=corp,DC=example"<?= $ro ?>>
      <small>Use a dedicated read-only account.</small></label>
    <label>Bind password <input type="password" name="bind_password" autocomplete="new-password" placeholder="<?= $hasPassword ? 'Stored encrypted — leave empty to keep' : 'Not set' ?>"<?= $ro ?>>
      <small>Never shown again. Stored encrypted by the portal and given to the SohobOTP engine only while a test or sync runs.</small></label>
    <label>Account suffix (AD) <input name="account_suffix" value="<?= e($s['account_suffix']) ?>" placeholder="@corp.example"<?= $ro ?>></label>
  </fieldset>

  <fieldset>
    <legend>Which users</legend>
    <label>Users OU / DN <input name="users_dn" value="<?= e($s['users_dn']) ?>" placeholder="OU=Staff,DC=corp,DC=example"<?= $ro ?>>
      <small>Optional. Several OUs separated by “;”. Empty = the whole base DN.</small></label>
    <label>Only members of these groups <input name="in_groups" value="<?= e($s['in_groups']) ?>" placeholder="MFA-Users, VPN-Users"<?= $ro ?>>
      <small>Group names, comma separated. Active Directory only; for generic LDAP use the LDAP filter below.</small></label>
    <label class="choice"><input type="checkbox" name="recursive_groups" value="1"<?= $checked('recursive_groups') . $ro ?>><span>Include members of nested groups</span></label>
    <label>LDAP filter (advanced) <input name="ldap_filter" value="<?= e($s['ldap_filter']) ?>" placeholder="(&amp;(objectClass=posixAccount)({cn_identifier}={username})(memberOf=CN=MFA,OU=Groups,DC=corp,DC=example))"<?= $ro ?>>
      <small>Replaces the default user filter. Placeholders: {cn_identifier}, {username}, {groups_filtering}.</small></label>
    <label>Groups that sign in without 2FA <input name="without2fa_groups" value="<?= e($s['without2fa_groups']) ?>"<?= $ro ?>>
      <small>Members only need their directory password. Keep empty unless strictly needed.</small></label>
    <label class="choice"><input type="checkbox" name="opt_in_2fa" value="1"<?= $checked('opt_in_2fa') . $ro ?>><span>2FA opt-in: users in a without-2FA group switch to 2FA once they enrol a token</span></label>
  </fieldset>

  <fieldset>
    <legend>Attribute mapping</legend>
    <p class="hint">Leave empty to use the defaults of the directory type (AD: sAMAccountName / memberOf / cn; LDAP: uid / memberOf / cn).</p>
    <div class="row">
      <label>Username attribute <input name="cn_identifier" value="<?= e($s['cn_identifier']) ?>"<?= $ro ?>></label>
      <label>Synced name attribute <input name="synced_user_attribute" value="<?= e($s['synced_user_attribute']) ?>"<?= $ro ?>></label>
    </div>
    <div class="row">
      <label>Group membership attribute <input name="group_attribute" value="<?= e($s['group_attribute']) ?>"<?= $ro ?>></label>
      <label>Group name attribute <input name="group_cn_identifier" value="<?= e($s['group_cn_identifier']) ?>"<?= $ro ?>></label>
    </div>
    <label>Language attribute <input name="language_attribute" value="<?= e($s['language_attribute']) ?>"<?= $ro ?>></label>
  </fieldset>

  <fieldset>
    <legend>New and changed users</legend>
    <label>Token type for new users
      <select name="default_algorithm"<?= $ro ?>>
        <?php foreach (['totp' => 'TOTP authenticator app (recommended)', 'hotp' => 'HOTP (counter-based)', 'without2fa' => 'No 2FA (directory password only)'] as $value => $label): ?>
          <option value="<?= e($value) ?>"<?= $s['default_algorithm'] === $value ? ' selected' : '' ?>><?= e($label) ?></option>
        <?php endforeach; ?>
      </select>
    </label>
    <label class="choice"><input type="checkbox" name="request_ldap_password" value="1"<?= $checked('request_ldap_password') . $ro ?>><span>Users type their directory password followed by the code (password + OTP)</span></label>
    <label class="choice"><input type="checkbox" name="dont_auto_disable" value="1"<?= $checked('dont_auto_disable') . $ro ?>><span>Keep SohobOTP accounts enabled when the user is disabled or removed in the directory (not recommended)</span></label>
    <label class="choice"><input type="checkbox" name="dont_auto_enable" value="1"<?= $checked('dont_auto_enable') . $ro ?>><span>Do not re-enable accounts automatically when the user is enabled again in the directory</span></label>
    <label>Delete accounts missing from the directory after (days) <input name="delete_retention_days" value="<?= e($s['delete_retention_days']) ?>" inputmode="numeric"<?= $ro ?>>
      <small>Users that leave the directory scope are disabled at the next sync, then deleted after this many days. 0 = never delete.</small></label>
  </fieldset>

  <fieldset>
    <legend>Schedule</legend>
    <label class="choice"><input type="checkbox" name="schedule_enabled" value="1"<?= $checked('schedule_enabled') . $ro ?>><span>Sync automatically</span></label>
    <label>Every (minutes) <input name="schedule_minutes" value="<?= e($s['schedule_minutes']) ?>" inputmode="numeric"<?= $ro ?>></label>
    <p class="hint">Runs in the background worker (<code>portal/bin/worker.php</code>), not in the browser.</p>
  </fieldset>

  <?php if ($perm['manage']): ?>
    <div class="actions"><button type="submit" class="button-primary">Save settings</button></div>
  <?php endif; ?>
</form>
