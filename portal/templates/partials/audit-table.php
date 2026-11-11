<?php defined('PORTAL_ROOT') || exit; ?>
<div class="table-wrap">
  <table class="table">
    <thead>
      <tr><th>Time (UTC)</th><th>Who</th><th>Action</th><th>Target</th><th>Result</th><th>From</th><th>Details</th></tr>
    </thead>
    <tbody>
      <?php foreach ($entries as $entry): ?>
        <tr>
          <td class="nowrap"><?= e(str_replace(['T', 'Z'], [' ', ''], $entry['time'])) ?></td>
          <td><?= e($entry['actor']) ?><?php if ('' !== $entry['role']): ?> <span class="muted">(<?= e($entry['role']) ?>)</span><?php endif; ?></td>
          <td><code><?= e($entry['action']) ?></code></td>
          <td><?= e($entry['target']) ?></td>
          <td><span class="status status-<?= e($entry['result']) ?>"><?= e($entry['result']) ?></span></td>
          <td><?= e($entry['ip']) ?></td>
          <td class="details-cell"><?= [] === $entry['details'] ? '' : '<code>' . e(json_encode($entry['details'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) . '</code>' ?></td>
        </tr>
      <?php endforeach; ?>
      <?php if ([] === $entries): ?>
        <tr><td colspan="7" class="empty">No entries match.</td></tr>
      <?php endif; ?>
    </tbody>
  </table>
</div>
