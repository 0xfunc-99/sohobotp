<?php defined('PORTAL_ROOT') || exit; ?>
<?php
  $signinCount = count(array_filter(array_keys($packages), static fn (string $k): bool => str_starts_with($k, 'signin/')));
  $newest = '';
  foreach (['signin/amd64', 'signin/arm64'] as $k) {
      if (isset($packages[$k]) && strnatcmp($packages[$k]['version'], $newest) > 0) {
          $newest = $packages[$k]['version'];
      }
  }
?>
<p class="back"><a href="<?= e(route('endpoints')) ?>">← Computers</a></p>
<p class="page-intro">On Windows, the code on the sign-in screen comes from <strong>SohobOTP Sign-in</strong>. Put its installers here once, and tick <strong>Install and update SohobOTP Sign-in automatically</strong> in a computer policy: a double-click on the agent from <a href="<?= e(route('agent-download')) ?>">Add a computer</a> then installs the agent, the Visual C++ runtime (if missing) and SohobOTP Sign-in for the computer's processor, with its settings. Add a newer Sign-in here later and those computers update by themselves at their next check-in.</p>

<?php if (null !== $error): ?><div class="alert alert-error" role="alert"><?= e($error) ?></div><?php endif; ?>

<section class="panel">
  <div class="panel-head">
    <div><h2>Installers on this portal</h2><p class="panel-sub">The agent installs only installers signed with the release key built into it (kept offline, never on this portal), and checks each download against the size and SHA-256 shown here.</p></div>
    <span class="status <?= $signinCount > 0 ? 'status-success' : '' ?>"><?= $signinCount > 0 ? 'ready' : 'none yet' ?></span>
  </div>
  <table>
    <thead><tr><th>Installer</th><th>Version</th><th>Size</th><th>Added</th><th>SHA-256</th></tr></thead>
    <tbody>
      <?php foreach (Portal\SigninPackages::KINDS as $kind => $meta): $p = $packages[$kind] ?? null; ?>
        <tr>
          <td><strong><?= e($meta['label']) ?></strong><br><span class="muted"><?= e(['signin/amd64' => 'SohobOTPSignIn.msi: most PCs and servers', 'signin/arm64' => 'SohobOTPSignIn_arm64.msi: Snapdragon laptops, Windows in Parallels/UTM/VMware on a Mac', 'vcredist' => "vc_redist.x64.exe from Microsoft: needed by Sign-in, installed only where missing"][$kind]) ?></span></td>
          <?php if (null === $p): ?>
            <td colspan="4"><span class="status">not added</span><?= 'vcredist' === $kind ? ' <span class="muted">computers without the runtime cannot get Sign-in automatically</span>' : '' ?></td>
          <?php else: ?>
            <td><?= e($p['version']) ?><?php if ('' === $p['signature']): ?> <span class="status status-failure" title="Added before installers had to be signed: computers do not get it. Add it again with its signature file.">not signed</span><?php endif; ?></td>
            <td><?= e(number_format($p['size'] / 1048576, 1)) ?> MB</td>
            <td><?= $p['added_at'] > 0 ? e(format_time($p['added_at'])) : '—' ?></td>
            <td><code title="<?= e($p['sha256']) ?>"><?= e(substr($p['sha256'], 0, 16)) ?>…</code></td>
          <?php endif; ?>
        </tr>
      <?php endforeach; ?>
    </tbody>
  </table>
</section>

<section class="panel">
  <h2>Where it is used</h2>
  <?php if ([] === $autoGroups): ?>
    <div class="alert alert-info" role="status">No computer policy installs Sign-in automatically yet. Open a policy under <a href="<?= e(route('endpoint-groups')) ?>">Computer policies</a> and tick <strong>Install and update SohobOTP Sign-in automatically</strong> (Windows section).</div>
  <?php else: ?>
    <p>Installed automatically for the computers in: <?php foreach ($autoGroups as $i => $g): ?><?= $i > 0 ? ', ' : '' ?><a href="<?= e(route('endpoint-group', ['id' => $g['id']])) ?>"><?= e($g['name']) ?></a><?php endforeach; ?>.</p>
  <?php endif; ?>
  <?php if ([] === $versions): ?>
    <p class="muted">No Windows computer has checked in yet.</p>
  <?php else: ?>
    <table>
      <thead><tr><th>SohobOTP Sign-in on the Windows computers</th><th>Computers</th></tr></thead>
      <tbody>
        <?php foreach ($versions as $version => $count): ?>
          <tr><td><?= e($version) ?><?php if ('not installed' === $version): ?> <span class="muted">— no code at sign-in on these</span><?php elseif ('' !== $newest && strnatcmp($version, $newest) < 0): ?> <span class="status">older than <?= e($newest) ?></span><?php elseif ($version === $newest): ?> <span class="status status-success">newest</span><?php endif; ?></td><td><?= (int) $count ?></td></tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  <?php endif; ?>
</section>

<form method="post" action="<?= e(route('signin-packages')) ?>" enctype="multipart/form-data" class="form narrow">
  <?= csrf_field() ?>
  <fieldset>
    <legend>Add or replace an installer</legend>
    <label>File <input type="file" name="installer" accept=".msi,.exe" required>
      <small>From the setup kit: <code>windows-signin/SohobOTPSignIn.msi</code> (Intel/AMD) or <code>windows-signin/arm64/SohobOTPSignIn_arm64.msi</code> (ARM). The Visual C++ runtime: <code>vc_redist.x64.exe</code> from Microsoft (https://aka.ms/vs/17/release/vc_redist.x64.exe).</small></label>
    <label>Signature file <input type="file" name="signature" accept=".json" required>
      <small>Made on the computer that keeps the release key: <code>sohobotp-agent release sign-package --key release-private.key --file SohobOTPSignIn.msi --kind signin --arch amd64 --version 1.0.2.0 --out SohobOTPSignIn.msi.sig.json</code> (Visual C++ runtime: <code>--kind vcredist</code> and its file version). It names the installer and its version. A computer never gets a version older than the one it has.</small></label>
    <div class="actions"><button type="submit" class="button-primary">Add installer</button></div>
  </fieldset>
</form>

<details class="panel">
  <summary>From the command line (portal server)</summary>
  <pre><code>A="sudo docker exec sohobotp php /usr/local/bin/multiotp/portal/bin/portal-admin.php"
sudo docker cp SohobOTPSignIn.msi sohobotp:/tmp/ &amp;&amp; sudo docker cp SohobOTPSignIn.msi.sig.json sohobotp:/tmp/
$A signin-package-add --file=/tmp/SohobOTPSignIn.msi --signature=/tmp/SohobOTPSignIn.msi.sig.json
(the same for SohobOTPSignIn_arm64.msi and vc_redist.x64.exe, each with its .sig.json)
$A signin-package-list</code></pre>
</details>
