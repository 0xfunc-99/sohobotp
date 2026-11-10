<?php defined('PORTAL_ROOT') || exit; ?>
<?php
  $r = $job['result'] ?? null;
  $names = static function (array $list): string {
      $shown = array_slice($list, 0, 100);
      return e(implode(', ', $shown)) . (count($list) > 100 ? ' … and ' . (count($list) - 100) . ' more' : '');
  };
  $active = in_array($job['status'], Portal\Jobs::ACTIVE, true);
?>
<?php if (str_starts_with($job['type'], 'endpoints.')): ?>
<p><a href="<?= e(route('endpoints')) ?>">← Endpoints</a> · <a href="<?= e(route('endpoint-groups')) ?>">Endpoint groups and AD rules</a></p>
<?php elseif (str_starts_with($job['type'], 'radius.')): ?>
<p><a href="<?= e(route('radius')) ?>">← RADIUS servers</a> · <a href="<?= e(route('radius-diagnostics')) ?>">Diagnostics</a></p>
<?php else: ?>
<p><a href="<?= e(route('directory')) ?>">← Directory</a> · <a href="<?= e(route('jobs')) ?>">All jobs</a></p>
<?php endif; ?>

<section class="panel"<?= $active ? ' data-job-poll="' . e(route('job-status', ['id' => $job['id']])) . '"' : '' ?>>
  <dl class="details">
    <dt>Status</dt><dd><span class="status status-<?= e(['succeeded' => 'success', 'failed' => 'failure', 'cancelled' => 'denied'][$job['status']] ?? 'info') ?>" data-job-status><?= e($job['status']) ?></span></dd>
    <dt>Progress</dt><dd data-job-progress><?= e($job['progress']) ?></dd>
    <?php if ($active): ?><dt>Engine</dt><dd data-job-engine><?= e($engine ?: '—') ?></dd><?php endif; ?>
    <dt>Requested</dt><dd><?= e(format_time($job['created_at'])) ?> by <?= e($job['requested_by']) ?></dd>
    <dt>Started</dt><dd><?= e(format_time($job['started_at'])) ?></dd>
    <dt>Finished</dt><dd><?= e(format_time($job['finished_at'])) ?></dd>
  </dl>
  <?php if ($active): ?>
    <p class="hint">This page refreshes by itself. The job keeps running if you leave it.
      <?php if ('queued' === $job['status']): ?>If it stays queued, check that the background worker is running.<?php endif; ?></p>
  <?php endif; ?>
  <?php if ($canCancel): ?>
    <form method="post" action="<?= e(route('job-cancel')) ?>" class="inline" data-confirm="Stop this job?">
      <?= csrf_field() ?><input type="hidden" name="id" value="<?= e($job['id']) ?>">
      <button type="submit" class="button">Stop</button>
    </form>
  <?php endif; ?>
</section>

<?php if (null !== $job['error']): ?>
  <div class="alert alert-error" role="alert"><?= e($job['error']) ?></div>
<?php endif; ?>

<?php if ('directory.sync' === $job['type'] && is_array($r)): ?>
  <section class="cards">
    <div class="card"><span class="card-label">Created</span><span class="card-value"><?= count($r['created']) ?></span></div>
    <div class="card<?= [] !== $r['disabled'] ? ' card-warning' : '' ?>"><span class="card-label">Disabled</span><span class="card-value"><?= count($r['disabled']) ?></span></div>
    <div class="card"><span class="card-label">Re-enabled</span><span class="card-value"><?= count($r['enabled']) ?></span></div>
    <div class="card<?= [] !== $r['deleted'] ? ' card-warning' : '' ?>"><span class="card-label">Deleted</span><span class="card-value"><?= count($r['deleted']) ?></span></div>
    <div class="card"><span class="card-label">Users after sync</span><span class="card-value"><?= (int) $r['local_users'] ?></span></div>
  </section>
  <?php foreach (['created' => 'Created', 'disabled' => 'Disabled', 'enabled' => 'Re-enabled', 'deleted' => 'Deleted'] as $key => $label): ?>
    <?php if ([] !== $r[$key]): ?><p><strong><?= e($label) ?>:</strong> <?= $names($r[$key]) ?></p><?php endif; ?>
  <?php endforeach; ?>
<?php endif; ?>

<?php if ('endpoints.directory' === $job['type'] && is_array($r)): ?>
  <section class="cards">
    <div class="card"><span class="card-label">Machines checked</span><span class="card-value"><?= (int) $r['checked'] ?></span></div>
    <div class="card"><span class="card-label">Found in AD</span><span class="card-value"><?= (int) $r['found'] ?></span></div>
    <div class="card"><span class="card-label">Approved</span><span class="card-value"><?= count($r['approved']) ?></span></div>
    <div class="card"><span class="card-label">Moved by rules</span><span class="card-value"><?= count($r['moved']) ?></span></div>
  </section>
  <?php if ([] !== $r['not_found']): ?><p><strong>No computer account:</strong> <?= $names($r['not_found']) ?></p><?php endif; ?>
<?php endif; ?>

<?php if ('directory.preview' === $job['type'] && is_array($r) && !empty($r['ok'])): ?>
  <p><?= (int) $r['found'] ?> user(s) found in the directory with the current settings. Nothing was changed.</p>
  <section class="cards">
    <div class="card"><span class="card-label">Would be created</span><span class="card-value"><?= count($r['create']) ?></span></div>
    <div class="card"><span class="card-label">Already synced</span><span class="card-value"><?= count($r['update']) ?></span></div>
    <div class="card<?= [] !== $r['disable'] ? ' card-warning' : '' ?>"><span class="card-label">Would be disabled</span><span class="card-value"><?= count($r['disable']) ?></span></div>
    <div class="card"><span class="card-label">Would be re-enabled</span><span class="card-value"><?= count($r['reenable']) ?></span></div>
    <div class="card<?= [] !== $r['missing'] ? ' card-warning' : '' ?>"><span class="card-label">Synced users no longer found</span><span class="card-value"><?= count($r['missing']) ?></span></div>
  </section>
  <?php if ([] !== $r['missing']): ?>
    <p class="hint">Users no longer found are <?= $r['auto_disable'] ? 'disabled' : 'kept enabled (auto-disable is off)' ?> by the sync<?= $r['retention'] > 0 ? ', then deleted after ' . (int) $r['retention'] . ' days' : '' ?>.</p>
  <?php endif; ?>
  <?php foreach (['create' => 'Would be created', 'disable' => 'Would be disabled', 'reenable' => 'Would be re-enabled'] as $key => $label): ?>
    <?php if ([] !== $r[$key]): ?>
      <h2><?= e($label) ?></h2>
      <div class="table-wrap"><table class="table">
        <thead><tr><th>User</th><th>Name</th><th>Email</th><th>Groups</th></tr></thead>
        <tbody><?php foreach (array_slice($r[$key], 0, 200) as $row): ?>
          <tr><td><?= e($row['user']) ?></td><td><?= e($row['name']) ?></td><td><?= e($row['email']) ?></td><td><?= e($row['groups']) ?></td></tr>
        <?php endforeach; ?></tbody>
      </table></div>
    <?php endif; ?>
  <?php endforeach; ?>
  <?php if ([] !== $r['missing']): ?>
    <h2>Synced users no longer found</h2>
    <p><?= $names(array_column($r['missing'], 'user')) ?></p>
  <?php endif; ?>
<?php endif; ?>

<?php if ('radius.vip_seed' === $job['type'] && is_array($r) && isset($r['marked'])): ?>
  <p><?= (int) $r['marked'] ?> user(s) already using SohobOTP were moved to SohobOTP.
    In all, <?= (int) $r['on_sohobotp'] ?> user(s) sign in with SohobOTP; <?= (int) $r['sent_back'] ?> were sent back to Symantec VIP by hand.
    Everyone else is forwarded to Symantec VIP on server groups with forwarding on. <a href="<?= e(route('radius-vip')) ?>">Symantec VIP migration</a></p>
<?php endif; ?>

<?php if (is_array($r) && !empty($r['log'])): ?>
  <h2>Engine messages</h2>
  <pre class="log"><?= e(implode("\n", $r['log'])) ?></pre>
<?php endif; ?>
