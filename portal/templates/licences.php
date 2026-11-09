<?php defined('PORTAL_ROOT') || exit; ?>
<?php
  $md = (string) @file_get_contents(dirname(PORTAL_ROOT) . '/LICENSES.md');
  $rows = [];
  foreach (preg_split('/\R/', $md) as $line) {
      if (preg_match('/^\| (?!Component|Program|---)(.+?) \|(.*)\|\s*$/', $line, $m)) {
          $cells = array_map(static fn (string $c): string => trim(str_replace('`', '', $c)), explode('|', $m[1] . '|' . $m[2]));
          // "Used by the appliance" rows have two columns: program and licence
          $rows[] = 2 === count($cells) ? [$cells[0], 'appliance (separate program)', $cells[1], ''] : $cells;
      }
  }
?>
<p><?= e(Portal\Config::brandName()) ?> is a product of <?= e(Portal\Config::companyName()) ?>. It contains and uses open-source software; the notices below and the licence texts stay available as those licences require.</p>
<div class="table-wrap">
  <table class="table">
    <thead><tr><th>Component</th><th>Where</th><th>Licence</th><th>Copyright</th></tr></thead>
    <tbody>
      <?php foreach ($rows as $r): ?>
        <tr><?php foreach (array_pad(array_slice($r, 0, 4), 4, '') as $cell): ?><td><?= e($cell) ?></td><?php endforeach; ?></tr>
      <?php endforeach; ?>
    </tbody>
  </table>
</div>
<p class="hint">Full texts: LICENSES.md, COPYING and COPYING.LESSER in the SohobOTP source, and each component's files.</p>
