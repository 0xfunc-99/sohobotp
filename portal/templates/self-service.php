<?php defined('PORTAL_ROOT') || exit; ?>
<?php $open = $settings['enabled'] && null !== $settings['until'] && $settings['until'] > time(); ?>
<p class="back"><a href="<?= e(route('users')) ?>">← Users</a></p>
<p class="page-intro">Users scan their own QR code on a web page, instead of one by one at the help desk. Open it before you push the agent to computers, send the link, and watch who has finished.</p>

<?php if (!$directoryEnabled): ?>
  <div class="alert alert-info" role="status">Only users from Active Directory (or LDAP) can use it: they sign in with their directory password. <a href="<?= e(route('directory')) ?>">Connect Active Directory first.</a></div>
<?php endif; ?>

<section class="panel">
  <div class="panel-head">
    <div><h2>The page for your users</h2><p class="panel-sub"><?= $open ? 'Open until ' . e(format_time($settings['until'])) : 'Closed: users who open the link are told to ask IT' ?></p></div>
    <span class="status <?= $open ? 'status-success' : '' ?>"><?= $open ? 'open' : 'closed' ?></span>
  </div>
  <p class="secret"><code><?= e($link) ?></code></p>
  <p class="hint">Send this link by email or Teams, or put it on the intranet. Users sign in with their usual work user name and password, scan the QR code, and type the first code.</p>
</section>

<form method="post" action="<?= e(route('self-service')) ?>" class="form narrow">
  <?= csrf_field() ?>
  <fieldset>
    <legend>Open or close it</legend>
    <label class="choice"><input type="checkbox" name="enabled" value="1"<?= $open ? ' checked' : '' ?>><span><strong>Open the self-service page</strong></span></label>
    <label>Keep it open for (days) <input name="days" value="<?= $open ? max(1, (int) ceil(($settings['until'] - time()) / 86400)) : 14 ?>" inputmode="numeric">
      <small>It closes by itself afterwards. 1 to <?= Portal\SelfEnrol::MAX_DAYS ?> days; a short window is safer.</small></label>
    <label>Only from these networks (optional)
      <textarea name="networks" rows="3" spellcheck="false" placeholder="10.0.0.0/8&#10;192.168.1.0/24"><?= e(implode("\n", $settings['networks'])) ?></textarea>
      <small>One address or network per line. Empty: from anywhere. Listing your office and VPN networks keeps it away from the internet.</small></label>
    <div class="actions"><button type="submit" class="button-primary">Save</button></div>
  </fieldset>
</form>

<section class="panel">
  <h2>Who has set up a code</h2>
  <p class="hint"><?= (int) $counts['self'] ?> by themselves on this page, <?= (int) $counts['admin'] ?> by an administrator (Users → user → Enrol new authenticator).</p>
  <?php if ([] === $recent): ?>
    <p class="muted">Nobody yet.</p>
  <?php else: ?>
    <div class="table-wrap">
      <table class="table">
        <thead><tr><th>User</th><th>How</th><th>When</th><th>From</th></tr></thead>
        <tbody>
          <?php foreach ($recent as $r): ?>
            <tr><td><a href="<?= e(route('user', ['u' => $r['user']])) ?>"><?= e($r['user']) ?></a></td><td><?= 'self' === $r['via'] ? 'by the user' : 'by ' . e($r['ip']) ?></td><td class="nowrap"><?= e(format_time($r['at'])) ?></td><td><?= 'self' === $r['via'] ? e($r['ip']) : '' ?></td></tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  <?php endif; ?>
</section>

<section class="panel">
  <h2>Who can use it</h2>
  <ul>
    <li>Users from Active Directory, enabled, without a key fob.</li>
    <li>Only once: users who already sign in with a code, or set one up here or with an administrator, are refused. A stolen password is not enough to replace someone's code.</li>
    <li>New phone: open the user's page and press <strong>Allow a new self-service set-up</strong>.</li>
    <li>Wrong passwords and codes are limited per address, like the portal sign-in. Everything is in the audit trail.</li>
  </ul>
</section>
