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
<p class="hint">Open-source components included in <?= e(Portal\Config::brandName()) ?>, kept here as their licences require.</p>
<ul class="notices">
  <?php foreach ($rows as $r): [$component, , $licence, $holder] = array_pad(array_slice($r, 0, 4), 4, ''); ?>
    <li><span class="notice-name"><?= e($component) ?></span><span class="notice-meta"><?= e($licence) ?><?= '' !== $holder ? ' · © ' . e($holder) : '' ?></span></li>
  <?php endforeach; ?>
</ul>
<p class="hint">Full licence texts: LICENSES.md, COPYING and COPYING.LESSER in the source, and each component's files.</p>
