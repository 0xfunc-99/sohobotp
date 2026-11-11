<?php defined('PORTAL_ROOT') || exit; ?>
<p class="back"><a href="<?= e(route('directory')) ?>">← Directory</a></p>
<div class="table-wrap">
  <table class="table">
    <thead><tr><th>Job</th><th>Requested</th><th>By</th><th>Status</th><th>Duration</th><th>Result</th></tr></thead>
    <tbody>
      <?php foreach ($jobs as $job): ?>
        <?php $r = $job['result'] ?? []; ?>
        <tr>
          <td><a href="<?= e(route('job', ['id' => $job['id']])) ?>"><?= e(Portal\DirectoryController::label($job['type'])) ?></a></td>
          <td class="nowrap"><?= e(format_time($job['created_at'])) ?></td>
          <td><?= e($job['requested_by']) ?></td>
          <td><span class="status status-<?= e(['succeeded' => 'success', 'failed' => 'failure', 'cancelled' => 'denied'][$job['status']] ?? 'info') ?>"><?= e($job['status']) ?></span></td>
          <td><?= null !== $job['finished_at'] && null !== $job['started_at'] ? (int) ($job['finished_at'] - $job['started_at']) . ' s' : '—' ?></td>
          <td>
            <?php if ('directory.sync' === $job['type'] && is_array($r) && isset($r['created'])): ?>
              <?= count($r['created']) ?> created, <?= count($r['disabled']) ?> disabled, <?= count($r['enabled']) ?> re-enabled, <?= count($r['deleted']) ?> deleted
            <?php elseif ('directory.preview' === $job['type'] && !empty($r['ok'])): ?>
              <?= (int) $r['found'] ?> in directory, <?= count($r['create']) ?> to create
            <?php else: ?><?= e($job['error'] ?? '') ?><?php endif; ?>
          </td>
        </tr>
      <?php endforeach; ?>
      <?php if ([] === $jobs): ?><tr><td colspan="6" class="empty">No jobs yet. Syncs and previews you start appear here.</td></tr><?php endif; ?>
    </tbody>
  </table>
</div>
