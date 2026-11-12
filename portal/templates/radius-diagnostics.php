<?php defined('PORTAL_ROOT') || exit; ?>
<p class="back"><a href="<?= e(route('radius')) ?>">← VPNs and devices</a></p>

<section class="panel">
  <h2>FreeRADIUS</h2>
  <?php if (!$status['available']): ?>
    <div class="alert alert-error" role="alert"><?= e($status['output']) ?></div>
  <?php else: ?>
    <dl class="details">
      <dt>Service</dt><dd><span class="status status-<?= $status['running'] ? 'success' : 'denied' ?>"><?= $status['running'] ? 'running' : 'stopped' ?></span></dd>
      <dt>Portal clients</dt><dd><?= str_contains($status['output'], 'portal_clients=included') ? 'included in clients.conf' : 'not applied yet' ?></dd>
      <dt>Changes waiting</dt><dd><?= $state['pending'] ? 'yes — apply the configuration' : 'no' ?></dd>
    </dl>
    <?php if ($status['default_client']): ?>
      <div class="alert alert-error" role="alert">
        The install-time catch-all client is active: <strong>any IP address</strong> can send RADIUS requests with the
        well-known secret “myfirstpass”. Disable it once your servers are added.
        <?php if ($canManage): ?>
          <form method="post" action="<?= e(route('radius-diagnostics')) ?>" class="inline" data-confirm="Disable the catch-all client? Devices still using it will stop working.">
            <?= csrf_field() ?><input type="hidden" name="op" value="disable-default-client">
            <button type="submit" class="button">Disable it</button>
          </form>
        <?php endif; ?>
      </div>
    <?php endif; ?>
  <?php endif; ?>
  <?php if (null !== $state['last_apply']): ?>
    <h3>Last apply (<?= e(format_time($state['last_apply']['at'])) ?>, <?= e($state['last_apply']['status']) ?>)</h3>
    <pre class="log"><?= e($state['last_apply']['output']) ?></pre>
  <?php endif; ?>
</section>

<?php if ($canManage): ?>
<section class="panel">
  <h2>Test login</h2>
  <p class="hint">Sends a real RADIUS request through FreeRADIUS, as a VPN or firewall would. Counts as a real login attempt (failed tests can lock the user).</p>
  <?php if (null !== $test): ?>
    <div class="alert alert-<?= 'accepted' === $test['result'] ? 'success' : 'error' ?>" role="status">
      <?= e($test['user']) ?>: <strong><?= e(['accepted' => 'Access-Accept', 'rejected' => 'Access-Reject', 'challenge' => 'Access-Challenge', 'timeout' => 'no answer', 'error' => 'error'][$test['result']] ?? $test['result']) ?></strong>
      <?= '' !== $test['reply_message'] ? '— “' . e($test['reply_message']) . '”' : '' ?>
      <?= null !== $test['error'] ? '— ' . e($test['error']) : '' ?>
    </div>
  <?php endif; ?>
  <form method="post" action="<?= e(route('radius-diagnostics')) ?>" class="toolbar">
    <?= csrf_field() ?><input type="hidden" name="op" value="test-login">
    <label>User <input name="user" required autocomplete="off"></label>
    <label>Password / code <input type="password" name="password" required autocomplete="off"></label>
    <button type="submit" class="button-primary">Test</button>
  </form>
</section>
<?php endif; ?>

<section class="panel">
  <h2>Recent logins</h2>
  <form method="get" action="index.php" class="filters">
    <input type="hidden" name="r" value="radius-diagnostics">
    <label>User <input name="user" value="<?= e($filterUser) ?>"></label>
    <label>Result
      <select name="result">
        <?php foreach (['' => 'Any', 'accepted' => 'Accepted', 'rejected' => 'Rejected'] as $value => $label): ?>
          <option value="<?= e($value) ?>"<?= $filterResult === $value ? ' selected' : '' ?>><?= e($label) ?></option>
        <?php endforeach; ?>
      </select>
    </label>
    <button type="submit" class="button">Filter</button>
  </form>
  <div class="table-wrap">
    <table class="table">
      <thead><tr><th>Time</th><th>User</th><th>Result</th><th>Message</th></tr></thead>
      <tbody>
        <?php foreach ($logins as $l): ?>
          <tr>
            <td class="nowrap"><?= e($l['time']) ?></td>
            <td><?= e($l['user']) ?></td>
            <td><span class="status status-<?= $l['ok'] ? 'success' : 'failure' ?>"><?= $l['ok'] ? 'accepted' : 'rejected' ?></span></td>
            <td><?= e($l['message']) ?></td>
          </tr>
        <?php endforeach; ?>
        <?php if ([] === $logins): ?><tr><td colspan="4" class="muted">No login events in the SohobOTP log (logging may be disabled).</td></tr><?php endif; ?>
      </tbody>
    </table>
  </div>
</section>

<?php if ([] !== $forwarded): ?>
<section class="panel">
  <h2>Forwarded to Symantec VIP, refused by user group</h2>
  <p class="hint">Logins of users not on SohobOTP yet, answered by the Symantec VIP Enterprise Gateway (<a href="<?= e(route('radius-vip')) ?>">migration settings</a>), and logins refused because the user is in none of the server group's allowed user groups.</p>
  <div class="table-wrap">
    <table class="table">
      <thead><tr><th>Time</th><th>User</th><th>Result</th><th>From server</th></tr></thead>
      <tbody>
        <?php foreach ($forwarded as $f): ?>
          <tr>
            <td class="nowrap"><?= e($f['time']) ?></td>
            <td><?= e($f['user']) ?></td>
            <td><span class="status status-<?= 'accept' === $f['result'] ? 'success' : 'failure' ?>"><?= match ($f['result']) { 'accept' => 'accepted by Symantec', 'reject' => 'rejected by Symantec', default => 'refused: user group not allowed' } ?></span></td>
            <td><code><?= e($f['server']) ?></code></td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
</section>
<?php endif; ?>
