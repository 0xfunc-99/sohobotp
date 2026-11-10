<?php defined('PORTAL_ROOT') || exit; ?>
<?php $p = $input['policy']; $on = static fn (string $k): string => !empty($p[$k]) ? ' checked' : ''; ?>
<p><a href="<?= e(route('radius')) ?>">← RADIUS servers</a></p>
<form method="post" action="<?= e(route('radius-group', null === $group ? [] : ['id' => $group['id']])) ?>" class="form narrow">
  <?= csrf_field() ?>
  <label>Name <input name="name" value="<?= e($input['name']) ?>" required maxlength="64" placeholder="VPN gateways"></label>
  <label>Description <input name="description" value="<?= e($input['description']) ?>" maxlength="255"></label>
  <fieldset>
    <legend>How users enter their code</legend>
    <label class="choice"><input type="checkbox" name="challenge_response" value="1"<?= $on('challenge_response') ?>>
      <span><strong>Challenge-response</strong>: the user first types the password (or PIN), then the server asks for the code. The device must support RADIUS Access-Challenge.</span></label>
    <label>Challenge text <input name="text_token_challenge" value="<?= e($p['text_token_challenge']) ?>" maxlength="200"></label>
    <label class="choice"><input type="checkbox" name="sms_challenge" value="1"<?= $on('sms_challenge') ?>><span>Send the code by SMS during the challenge (needs an SMS provider)</span></label>
    <label>SMS challenge text <input name="text_sms_challenge" value="<?= e($p['text_sms_challenge']) ?>" maxlength="200"></label>
    <label class="choice"><input type="checkbox" name="force_no_prefix_pin" value="1"<?= $on('force_no_prefix_pin') ?>><span>Ignore PIN / directory-password prefixes for these servers (code only)</span></label>
  </fieldset>
  <fieldset>
    <legend>Result caching</legend>
    <label class="choice"><input type="checkbox" name="cache_result" value="1"<?= $on('cache_result') ?>><span>Accept the same successful login again without a new code for a while (for devices that re-authenticate often, e.g. Wi-Fi roaming). Weakens 2FA: use only when needed.</span></label>
    <label>Cache duration (seconds) <input name="cache_timeout" value="<?= (int) $p['cache_timeout'] ?>" inputmode="numeric"></label>
  </fieldset>
  <fieldset>
    <legend>Reply</legend>
    <label class="choice"><input type="checkbox" name="dont_send_groups" value="1"<?= $on('dont_send_groups') ?>><span>Do not send the user's multiOTP group in the RADIUS reply</span></label>
  </fieldset>
  <fieldset>
    <legend>Who may sign in</legend>
    <label>Only users in these user groups (comma separated; empty: every user)
      <input name="allowed_groups" value="<?= e((string) ($p['allowed_groups'] ?? '')) ?>" maxlength="2000" placeholder="VPN-Users, IT-Admins"></label>
    <p class="hint">Checked before the code: users in none of these groups are refused, also with the right code.
      It uses the user's group in SohobOTP (from the directory sync: <em>Directory → groups</em>, with several groups per user when “multiple groups” is on).
      <?php if ([] !== ($knownGroups ?? [])): ?>Groups in use: <?= e(implode(', ', $knownGroups)) ?>.<?php endif; ?></p>
  </fieldset>
  <fieldset>
    <legend>Symantec VIP migration</legend>
    <label class="choice"><input type="checkbox" name="vip_forward" value="1"<?= $on('vip_forward') ?>>
      <span><strong>Forward users who are not on SohobOTP yet</strong> to the Symantec VIP Enterprise Gateway. Users on SohobOTP are checked here; all others (also users SohobOTP does not know) are sent, unchanged, to Symantec VIP. <a href="<?= e(route('radius-vip')) ?>">Symantec VIP servers</a></span></label>
  </fieldset>
  <div class="actions">
    <button type="submit" class="button-primary">Save group</button>
    <a class="button-link" href="<?= e(route('radius')) ?>">Cancel</a>
  </div>
</form>
