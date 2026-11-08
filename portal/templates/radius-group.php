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
  <p class="hint">Not yet available: limiting which user groups may sign in through a server group (needs an engine change; planned).</p>
  <div class="actions">
    <button type="submit" class="button-primary">Save group</button>
    <a class="button-link" href="<?= e(route('radius')) ?>">Cancel</a>
  </div>
</form>
