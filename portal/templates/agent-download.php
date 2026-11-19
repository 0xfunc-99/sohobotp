<?php defined('PORTAL_ROOT') || exit; ?>
<?php $missing = array_keys(array_filter($programs, static fn (?array $p): bool => null === $p)); ?>
<?php if (null !== $link): ?>
  <section class="panel" id="install-link">
    <h2>Install link for <?= e($link['label']) ?></h2>
    <p>On the Linux machine (computer policy <strong><?= e($link['group']) ?></strong>), paste these two lines in the terminal. The link works <strong>once</strong>, until <?= e(format_time($link['expires_at'])) ?>.</p>
    <pre><code><?= e(implode("\n", $link['commands'])) ?></code></pre>
    <ul class="hint">
      <li>The first line downloads the agent<?= str_contains($link['commands'][0], '--no-check-certificate') ? ' (the portal uses its own certificate, so wget is told not to check it)' : '' ?>; the second checks its SHA-256 before installing it, so a file changed on the way is never installed.</li>
      <li>No <code>sudo</code> on the machine? Use <code>su -c "<?= e('deb' === $link['format'] ? 'apt install $PWD/sohobotp-agent.deb' : '$PWD/sohobotp-agent install') ?>"</code> for the install part.</li>
      <?php if ('none' !== $link['approval']): ?><li>New machines from this link wait for approval (Computers): approve it after the install.</li><?php endif; ?>
      <li>This page shows the link only now. A link that went astray: revoke its token under <a href="<?= e(route('endpoint-enrol')) ?>">Enrol endpoints</a>.</li>
    </ul>
    <p class="hint">The link alone: <code><?= e($link['url']) ?></code></p>
  </section>
<?php endif; ?>
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
    <p class="hint">Or let a Linux machine fetch the agent itself: you get a one-time link and two lines to paste in its terminal.</p>
    <div class="actions">
      <?php foreach (Portal\AgentBundle::DOWNLOADS as $key => [$platform, $format, $label]): if (!str_starts_with($platform, 'linux/')) { continue; } $program = $programs[$platform]; ?>
        <button type="submit" name="link" value="<?= e($key) ?>" class="button"<?= null === $program ? ' disabled' : '' ?>>Install link: <?= e($label) ?></button>
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

<?php if ([] !== $openLinks): ?>
  <section class="panel">
    <h2>Install links not used yet</h2>
    <div class="table-wrap">
      <table class="table">
        <thead><tr><th>Label</th><th>For</th><th>Made by</th><th>Made</th><th>Expires</th></tr></thead>
        <tbody>
          <?php foreach ($openLinks as $l): ?>
            <tr><td><?= e($l['label']) ?></td><td><?= e($l['platform'] . ('deb' === $l['format'] ? ' (.deb)' : '')) ?></td><td><?= e($l['created_by']) ?></td><td class="nowrap"><?= e(format_time($l['created_at'])) ?></td><td class="nowrap"><?= e(format_time($l['expires_at'])) ?></td></tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>
    <p class="hint">Each link works once. To stop one, revoke its token under <a href="<?= e(route('endpoint-enrol')) ?>">Enrol endpoints</a> (same label).</p>
  </section>
<?php endif; ?>

<section class="panel" id="gpo">
  <h2>Many Windows computers at once: Group Policy kit</h2>
  <p>For computers in Active Directory. The kit is a folder you copy to a network share and name as a <strong>computer startup script</strong> in a Group Policy: every computer of the OU then installs the agent by itself the next time it starts. The steps are in the kit's README.txt.</p>
  <?php if (null === $programs['windows/amd64'] && null === $programs['windows/arm64']): ?>
    <p class="muted">The portal has no Windows agent program yet (see the list above).</p>
  <?php else: ?>
    <form method="post" action="<?= e(route('gpo-kit')) ?>" class="form narrow">
      <?= csrf_field() ?>
      <label>Computer policy
        <select name="group_id"><?php foreach ($groups as $g): ?><option value="<?= e($g['id']) ?>"<?= $g['id'] === $values['group_id'] ? ' selected' : '' ?>><?= e($g['name']) ?></option><?php endforeach; ?></select>
        <small>Tip: a policy with <strong>Install and update SohobOTP Sign-in automatically</strong> (nothing else to deploy) and <strong>Tamper protection</strong> (users who are administrators of their computer cannot remove it).</small></label>
      <label>Label <input name="label" maxlength="100" value="" placeholder="Group Policy kit, head office"></label>
      <label>The kit works for (days) <input name="days" value="90" inputmode="numeric"><small>1 to 365. After that, new computers need a new kit; computers already enrolled are not affected.</small></label>
      <label>Maximum computers <input name="max_uses" value="500" inputmode="numeric"><small>Up to 10000.</small></label>
      <label>New computers
        <select name="approval">
          <?php foreach (Portal\Endpoints::APPROVAL as $value => $label): ?><option value="<?= e($value) ?>"<?= 'directory' === $value ? ' selected' : '' ?>><?= e($label) ?></option><?php endforeach; ?>
        </select>
        <small>Every domain user can read a startup script, and so the kit's token. With approval, a copied token cannot add an unknown machine.</small></label>
      <label>Portal address <input name="portal" value="<?= e($values['portal']) ?>" maxlength="300" autocapitalize="none" spellcheck="false" required></label>
      <label>CA certificate of the portal (PEM)
        <textarea name="ca_pem" rows="4" spellcheck="false" autocapitalize="none" placeholder="Leave empty when the portal's certificate comes from a public authority"><?= e($values['ca_pem']) ?></textarea></label>
      <div class="actions"><button type="submit" class="button-primary">Download the Group Policy kit (.zip)</button></div>
    </form>
  <?php endif; ?>
</section>

<section class="panel">
  <h2>On the machine</h2>
  <ul>
    <li><strong>Windows:</strong> double-click the downloaded file and allow it to run as administrator, or run <code>sohobotp-agent-….exe install</code> from an administrator prompt. For the code on the sign-in screen it also needs SohobOTP Sign-in: with <strong>Install and update SohobOTP Sign-in automatically</strong> in the computer policy, the agent installs it by itself (installers: <a href="<?= e(route('signin-packages')) ?>">Windows sign-in installers</a>); otherwise install it by hand (Windows on ARM: its ARM64 installer).</li>
    <li><strong>Debian, Ubuntu, Raspberry Pi OS:</strong> <code>sudo apt install ./sohobotp-agent-…_amd64.deb</code> (or <code>_arm64.deb</code>). It enrols and starts the agent, then deletes the token from the machine. If enrolment fails (network, expired token), fix it and run <code>sudo dpkg --configure -a</code>. <code>sudo apt remove sohobotp-agent</code> undoes the PAM changes and removes the agent.</li>
    <li><strong>Other Linux:</strong> <code>chmod +x sohobotp-agent-… &amp;&amp; sudo ./sohobotp-agent-… install</code></li>
  </ul>
  <p class="hint">The download contains the enrolment token: send it only to whoever installs it, and delete it afterwards. The installed agent does not keep the token. A download that went astray is stopped by revoking its token under <a href="<?= e(route('endpoint-enrol')) ?>">Enrol endpoints</a>.</p>
</section>
