<?php defined('PORTAL_ROOT') || exit; ?>
<?php $role = $state['role'] ?? 'none'; ?>
<?php if (null !== $error): ?><div class="alert alert-error" role="alert"><?= e($error) ?></div><?php endif; ?>
<section class="panel">
  <h2>Two appliances</h2>
  <p>The <strong>primary</strong> keeps its data in MariaDB and replicates it to a <strong>secondary</strong> (encrypted, the
    primary's database certificate pinned). Point your VPNs and other RADIUS devices to both appliances. While the primary
    is up, the secondary answers logins with the primary's database and copies its RADIUS configuration every minute.
    If the primary fails, <strong>promote</strong> the secondary (or let it promote itself after some minutes): it then
    answers with its own copy of the data. Portal administrators, endpoints and settings stay on each appliance.</p>
  <dl class="details">
    <dt>This appliance</dt>
    <dd><?= match ($role) { 'primary' => '<strong>Primary</strong>, paired with ' . e((string) $state['secondary_ip']), 'secondary' => '<strong>Secondary</strong> of ' . e((string) $state['primary_ip']), 'promoted' => '<strong>Promoted</strong> to primary (' . e(format_time($state['promoted_at'] ?? null)) . ', by ' . e((string) ($state['promoted_by'] ?? '')) . ')', default => 'Not paired' } ?></dd>
    <dt>Database</dt><dd><?= 'mysql' === $db['backend'] ? 'MariaDB ' . e($db['server']) : 'files' ?></dd>
    <?php if ($helper['available'] && 'none' !== $role): ?>
      <dt>Replication</dt><dd><code><?= e(str_replace("\n", ' · ', $helper['output'])) ?></code></dd>
    <?php endif; ?>
    <?php if ('primary' === $role): ?>
      <dt>Last copy by the secondary</dt><dd><?= e(format_time($state['served_at'] ?? null)) ?></dd>
    <?php endif; ?>
    <?php if ('secondary' === $role): ?>
      <dt>Last RADIUS configuration copy</dt><dd><?= e(format_time($state['last_sync_at'] ?? null)) ?><?= '' !== ($state['last_sync_error'] ?? '') ? ' — <span class="status status-failure">' . e($state['last_sync_error']) . '</span>' : '' ?></dd>
      <dt>Primary database</dt><dd><?= null === ($state['primary_down_since'] ?? null) ? 'reachable' : '<span class="status status-failure">unreachable since ' . e(format_time($state['primary_down_since'])) . '</span>' ?></dd>
    <?php endif; ?>
  </dl>
</section>

<?php if ('none' === $role): ?>
<section class="panel">
  <h2>Make this appliance the primary</h2>
  <?php if ('mysql' !== $db['backend'] || !$db['local']): ?>
    <p>First move the data to MariaDB on this appliance (<a href="<?= e(route('database')) ?>">Database</a>).</p>
  <?php else: ?>
    <form method="post" action="<?= e(route('ha')) ?>" class="form narrow">
      <?= csrf_field() ?><input type="hidden" name="op" value="pair">
      <label>This appliance's IP address (as the secondary reaches it) <input name="primary_ip" maxlength="15" required></label>
      <label>The secondary's IP address <input name="secondary_ip" maxlength="15" required></label>
      <label>This portal's address for the secondary <input name="portal_url" value="https://<?= e($host) ?>" maxlength="255" required></label>
      <p class="hint">Opens MariaDB (port 3306) to the secondary's address only, with TLS. Allow TCP 3306 and 443 between the two appliances.</p>
      <div class="actions"><button type="submit" class="button-primary">Create the pairing code</button></div>
    </form>
  <?php endif; ?>
</section>
<section class="panel">
  <h2>Join as secondary</h2>
  <p>On a <strong>fresh</strong> appliance (its users and RADIUS data are replaced by the primary's): paste the pairing code from the primary.</p>
  <form method="post" action="<?= e(route('ha')) ?>" class="form" data-confirm="Join the primary? This appliance's users and RADIUS configuration are replaced by the primary's.">
    <?= csrf_field() ?><input type="hidden" name="op" value="join">
    <label>Pairing code <textarea name="code" rows="4" required autocomplete="off"></textarea></label>
    <div class="actions"><button type="submit" class="button-primary">Join</button></div>
  </form>
</section>
<?php endif; ?>

<?php if ('secondary' === $role): ?>
<section class="panel">
  <h2>If the primary fails</h2>
  <form method="post" action="<?= e(route('ha')) ?>" class="inline" data-confirm="Promote this appliance to primary? Do it only when the primary is really down: afterwards the two appliances are no longer in sync.">
    <?= csrf_field() ?><input type="hidden" name="op" value="promote">
    <button type="submit" class="button-primary">Promote to primary now</button>
  </form>
  <form method="post" action="<?= e(route('ha')) ?>" class="form narrow">
    <?= csrf_field() ?><input type="hidden" name="op" value="auto">
    <label>Promote automatically after the primary's database is unreachable for (minutes, 0 = never)
      <input name="minutes" value="<?= (int) ($state['auto_promote_minutes'] ?? 0) ?>" maxlength="4" inputmode="numeric"></label>
    <p class="hint">Automatic promotion keeps logins working without anyone, but if only the network between the appliances fails, both act as primary until you repair it.</p>
    <div class="actions"><button type="submit" class="button">Save</button></div>
  </form>
  <form method="post" action="<?= e(route('ha')) ?>" class="inline"><?= csrf_field() ?><input type="hidden" name="op" value="sync"><button type="submit" class="button-small">Copy the RADIUS configuration now</button></form>
</section>
<?php endif; ?>
