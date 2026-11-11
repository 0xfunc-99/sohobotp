<?php defined('PORTAL_ROOT') || exit; ?>
<?php if (null !== $active): ?>
  <div class="alert alert-info" role="status">The data is being moved to the database. <a href="<?= e(route('job', ['id' => $active['id']])) ?>">Follow progress</a></div>
<?php endif; ?>
<section class="panel">
  <h2>Where SohobOTP keeps its data</h2>
  <dl class="details">
    <dt>Now</dt>
    <dd><?php if ('files' === $dbNow['backend']): ?>Files on this appliance (fine for hundreds of users and machines)
      <?php else: ?><strong>MariaDB / MySQL</strong>: <code><?= e($dbNow['server']) ?></code>, database <code><?= e($dbNow['database']) ?></code>, user <code><?= e($dbNow['user']) ?></code><?= $dbNow['local'] ? ' (on this appliance)' : '' ?><?php endif; ?></dd>
    <dt>Users, tokens, RADIUS devices, groups</dt>
    <dd><?= (int) $counts['users'] ?>, <?= (int) $counts['tokens'] ?>, <?= (int) $counts['devices'] ?>, <?= (int) $counts['groups'] ?></dd>
    <dt>MariaDB on this appliance</dt>
    <dd><?= $helper['available'] ? e(str_replace("\n", ' · ', $helper['output'])) : 'not available (' . e($helper['output']) . ')' ?></dd>
  </dl>
  <p class="hint">A database is needed for many users (thousands to 100,000) and for two appliances with replication.
    Moving copies users, tokens, RADIUS devices and groups, checks the counts, and keeps the files as a backup;
    if anything fails, SohobOTP stays on the files. Administrators, endpoints and portal settings stay in the portal's own files.</p>
</section>

<?php if ('files' === $dbNow['backend'] && null === $active): ?>
<?php if (null !== $error): ?><div class="alert alert-error" role="alert"><?= e($error) ?></div><?php endif; ?>
<section class="panel">
  <h2>MariaDB on this appliance</h2>
  <p>Creates the database <code>sohobotp</code> and its user (random password, local connections only), starts MariaDB at boot, then moves the data.</p>
  <form method="post" action="<?= e(route('database')) ?>" class="inline" data-confirm="Move all users, tokens, RADIUS devices and groups to MariaDB on this appliance? RADIUS keeps working during the move.">
    <?= csrf_field() ?><input type="hidden" name="op" value="local">
    <button type="submit" class="button-primary">Use MariaDB on this appliance</button>
  </form>
</section>

<section class="panel">
  <h2>Another MariaDB / MySQL server</h2>
  <?php if (null !== $test): ?><div class="alert alert-<?= $test['ok'] ? 'success' : 'error' ?>" role="status"><?= e($test['message']) ?></div><?php endif; ?>
  <form method="post" action="<?= e(route('database')) ?>" class="form narrow" autocomplete="off">
    <?= csrf_field() ?>
    <label>Server (IP address or host name) <input name="host" value="<?= e($input['host']) ?>" maxlength="253" required></label>
    <label>Port <input name="port" value="<?= e((string) $input['port']) ?>" maxlength="5" inputmode="numeric"></label>
    <label>Database <input name="database" value="<?= e($input['database']) ?>" maxlength="64" required></label>
    <label>User <input name="user" value="<?= e($input['user']) ?>" maxlength="80" required></label>
    <label>Password <input type="password" name="password" maxlength="256" autocomplete="new-password" required></label>
    <label class="choice"><input type="checkbox" name="tls" value="1"<?= $input['tls'] ? ' checked' : '' ?>><span>Encrypt the connection (TLS)</span></label>
    <div class="actions">
      <button type="submit" name="op" value="test" class="button">Test the connection</button>
      <button type="submit" name="op" value="external" class="button-primary" data-confirm="Move all users, tokens, RADIUS devices and groups to this database?">Test and move the data</button>
    </div>
  </form>
</section>
<?php endif; ?>
