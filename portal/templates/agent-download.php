<?php defined('PORTAL_ROOT') || exit; ?>
<?php $missing = array_keys(array_filter($programs, static fn (?array $p): bool => null === $p)); ?>
<form method="post" action="<?= e(route('agent-download')) ?>" class="form narrow">
  <?= csrf_field() ?>
  <fieldset>
    <legend>1. Who is it for</legend>
    <p class="hint">Each download carries its own new enrolment token. The token lets machines join this endpoint group, within the limits below.</p>
    <label>Endpoint group
      <select name="group_id"><?php foreach ($groups as $g): ?><option value="<?= e($g['id']) ?>"<?= $g['id'] === $values['group_id'] ? ' selected' : '' ?>><?= e($g['name']) ?></option><?php endforeach; ?></select></label>
    <label>Label <input name="label" maxlength="100" value="<?= e($values['label']) ?>" placeholder="Paris office laptops"><small>Shown in the token list (Endpoints → Enrol endpoints), where the token can be revoked.</small></label>
    <label>Valid for (hours) <input name="hours" value="<?= e($values['hours']) ?>" inputmode="numeric"></label>
    <label>Maximum machines <input name="max_uses" value="<?= e($values['max_uses']) ?>" inputmode="numeric"><small>How many machines may enrol with this download.</small></label>
    <label>New machines
      <select name="approval">
        <?php foreach (Portal\Endpoints::APPROVAL as $value => $label): ?><option value="<?= e($value) ?>"<?= $value === $values['approval'] ? ' selected' : '' ?>><?= e($label) ?></option><?php endforeach; ?>
      </select>
      <small>With approval, a copied download cannot add an unknown machine.</small></label>
  </fieldset>

  <fieldset>
    <legend>2. How machines reach this portal</legend>
    <label>Portal address <input name="portal" value="<?= e($values['portal']) ?>" maxlength="300" autocapitalize="none" spellcheck="false" required>
      <small>The address the machines will use, not only the one in your browser now. It must match the portal's certificate.</small></label>
    <label>CA certificate of the portal (PEM)
      <textarea name="ca_pem" rows="7" spellcheck="false" autocapitalize="none" placeholder="Leave empty when the portal's certificate comes from a public authority"><?= e($values['ca_pem']) ?></textarea>
      <small><?= '' !== $values['ca_pem']
        ? 'Filled in for you: the certificate agents need to trust this portal. Replace it if the portal uses a certificate from your own authority.'
        : 'Empty: the portal\'s certificate looks publicly trusted. If it comes from your own authority, paste that authority\'s certificate here.' ?></small></label>
    <p>Portal key pin, built in as well (the agent refuses any other portal): <code><?= e(implode(' ', str_split($pin, 16))) ?></code></p>
  </fieldset>

  <fieldset>
    <legend>3. Download</legend>
    <div class="actions">
      <?php foreach (Portal\AgentBundle::DOWNLOADS as $key => [$platform, $format, $label]): $program = $programs[$platform]; ?>
        <button type="submit" name="platform" value="<?= e($key) ?>" class="<?= 'program' === $format && str_starts_with($platform, 'linux/') ? 'button' : 'button-primary' ?>"<?= null === $program ? ' disabled' : '' ?>><?= 'deb' === $format ? 'Download' : 'Download for' ?> <?= e($label) ?></button>
      <?php endforeach; ?>
    </div>
    <ul class="hint">
      <?php foreach (Portal\AgentBundle::PLATFORMS as $platform => $label): $program = $programs[$platform]; ?>
        <li><?= e($label) ?>: <?= null === $program ? 'no agent program on this portal yet' : e('agent ' . ('' !== $program['version'] ? $program['version'] . ', ' : '') . $program['source'] . ', ' . number_format($program['size'] / 1048576, 1) . ' MB') ?></li>
      <?php endforeach; ?>
    </ul>
    <?php if ([] !== $missing): ?>
      <p class="hint">To add an agent program: <code>portal-admin.php agent-program-add --file=sohobotp-agent-linux-amd64 --os=linux --arch=amd64</code> on the portal server (Windows: <code>--os=windows</code>, the <code>.exe</code>; ARM: <code>--arch=arm64</code>).</p>
    <?php endif; ?>
  </fieldset>
</form>

<section class="panel">
  <h2>On the machine</h2>
  <ul>
    <li><strong>Windows:</strong> double-click the downloaded file and allow it to run as administrator, or run <code>sohobotp-agent-….exe install</code> from an administrator prompt. Install SohobOTP Sign-in as well for the code on the sign-in screen (Windows on ARM: its ARM64 installer).</li>
    <li><strong>Debian, Ubuntu, Raspberry Pi OS:</strong> <code>sudo apt install ./sohobotp-agent-…_amd64.deb</code> (or <code>_arm64.deb</code>). It enrols and starts the agent, then deletes the token from the machine. If enrolment fails (network, expired token), fix it and run <code>sudo dpkg --configure -a</code>. <code>sudo apt remove sohobotp-agent</code> undoes the PAM changes and removes the agent.</li>
    <li><strong>Other Linux:</strong> <code>chmod +x sohobotp-agent-… &amp;&amp; sudo ./sohobotp-agent-… install</code></li>
  </ul>
  <p class="hint">The download contains the enrolment token: send it only to whoever installs it, and delete it afterwards. The installed agent does not keep the token. A download that went astray is stopped by revoking its token under <a href="<?= e(route('endpoint-enrol')) ?>">Enrol endpoints</a>.</p>
</section>
