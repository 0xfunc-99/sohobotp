<?php defined('PORTAL_ROOT') || exit; ?>
<p><a href="<?= e(route('endpoints')) ?>">← Endpoints</a></p>
<section class="panel">
  <div class="toolbar">
    <h2>Endpoint groups</h2>
    <?php if ($canManage): ?><a class="button" href="<?= e(route('endpoint-group')) ?>">New group</a><?php endif; ?>
  </div>
  <p class="hint">A group sets the policy for every endpoint in it: which Linux logins and Windows sign-ins need a code, exclusions, offline cache.</p>
  <div class="table-wrap">
    <table class="table">
      <thead><tr><th>Group</th><th>Endpoints</th><th>Linux</th><th>Windows</th><?php if ($canManage): ?><th></th><?php endif; ?></tr></thead>
      <tbody>
        <?php foreach ($groups as $g): $l = $g['policy']['linux']; $w = $g['policy']['windows']; ?>
          <tr>
            <td><strong><?= e($g['name']) ?></strong><?php if ('' !== $g['description']): ?><br><span class="muted"><?= e($g['description']) ?></span><?php endif; ?></td>
            <td><?= (int) $g['endpoints'] ?></td>
            <td><?= $l['enabled'] ? e(implode(', ', array_map(static fn (string $s): string => Portal\Endpoints::LINUX_SERVICES[$s] ?? $s, $l['services']))) . ' · RADIUS group ' . e($radiusNames[$l['radius_group_id']] ?? '?') : 'off' ?></td>
            <td>sign-in: <?= e(Portal\Endpoints::CP_MODES[$w['cpus_logon'][0]] ?? $w['cpus_logon']) ?><?= $w['cache_enabled'] ? ' · offline cache ' . (int) $w['cache_days'] . ' days' : '' ?></td>
            <?php if ($canManage): ?>
              <td class="row-actions">
                <a class="button-small" href="<?= e(route('endpoint-group', ['id' => $g['id']])) ?>">Edit</a>
                <?php if (0 === (int) $g['endpoints']): ?>
                  <form method="post" action="<?= e(route('endpoint-group-delete')) ?>" class="inline" data-confirm="Delete group <?= e($g['name']) ?>?">
                    <?= csrf_field() ?><input type="hidden" name="id" value="<?= e($g['id']) ?>"><button type="submit" class="button-small">Delete</button>
                  </form>
                <?php endif; ?>
              </td>
            <?php endif; ?>
          </tr>
        <?php endforeach; ?>
        <?php if ([] === $groups): ?><tr><td colspan="5" class="muted">No endpoint groups yet.</td></tr><?php endif; ?>
      </tbody>
    </table>
  </div>
</section>
