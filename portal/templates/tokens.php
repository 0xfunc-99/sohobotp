<?php defined('PORTAL_ROOT') || exit; ?>
<?php if ($canManage): ?>
<section class="panel">
  <h2>Import tokens</h2>
  <p class="hint">PSKC (RFC 6030, plain or encrypted), multiOTP CSV, Yubico CSV, Alpine XML/DAT and Authenex SQL files, as supported by multiOTP. Maximum 5 MB.</p>
  <form method="post" action="<?= e(route('token-import')) ?>" enctype="multipart/form-data" class="toolbar subform">
    <?= csrf_field() ?>
    <label>Token file <input type="file" name="token_file" required></label>
    <label>File password (encrypted PSKC only) <input type="password" name="password" autocomplete="off"></label>
    <button type="submit" class="button-primary">Import</button>
  </form>
</section>
<?php endif; ?>

<div class="toolbar">
  <input type="search" class="search" placeholder="Search tokens" data-filter-table="tokens-table" aria-label="Search tokens">
</div>
<div class="table-wrap">
  <table class="table" id="tokens-table">
    <thead><tr><th>Serial</th><th>Manufacturer</th><th>Type</th><th>Digits</th><th>Assigned to</th><th>Description</th><?php if ($canManage): ?><th></th><?php endif; ?></tr></thead>
    <tbody>
      <?php foreach ($tokens as $t): ?>
        <tr>
          <td><code><?= e($t['serial']) ?></code></td>
          <td><?= e($t['manufacturer']) ?></td>
          <td><?= e(strtoupper($t['algorithm'])) ?></td>
          <td><?= (int) $t['digits'] ?></td>
          <td><?php foreach ($t['users'] as $u): ?><a href="<?= e(route('user', ['u' => $u])) ?>"><?= e($u) ?></a> <?php endforeach; ?><?= [] === $t['users'] ? '<span class="muted">free</span>' : '' ?></td>
          <td><?= e($t['description']) ?></td>
          <?php if ($canManage): ?>
            <td><?php if ([] === $t['users']): ?>
              <form method="post" action="<?= e(route('token-action')) ?>" class="inline" data-confirm="Delete token <?= e($t['serial']) ?>?">
                <?= csrf_field() ?><input type="hidden" name="op" value="delete"><input type="hidden" name="serial" value="<?= e($t['serial']) ?>">
                <button type="submit" class="button-small button-danger">Delete</button>
              </form>
            <?php endif; ?></td>
          <?php endif; ?>
        </tr>
      <?php endforeach; ?>
      <?php if ([] === $tokens): ?><tr><td colspan="7" class="empty">No hardware tokens yet.<?= $canManage ? ' Import a token file above to add some.' : '' ?></td></tr><?php endif; ?>
    </tbody>
  </table>
</div>
