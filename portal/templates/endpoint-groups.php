<?php defined('PORTAL_ROOT') || exit; ?>
<p class="back"><a href="<?= e(route('endpoints')) ?>">← Computers</a></p>
<section class="panel">
  <div class="toolbar">
    <h2>Endpoint groups</h2>
    <?php if ($canManage): ?><a class="button-primary" href="<?= e(route('endpoint-group')) ?>">+ New group</a><?php endif; ?>
  </div>
  <p class="hint">A group sets the policy for every endpoint in it: which Linux logins and Windows sign-ins need a code, exclusions, offline cache.</p>
  <div class="table-wrap">
    <table class="table">
      <thead><tr><th>Group</th><th>Computers</th><th>Linux</th><th>Windows</th><?php if ($canManage): ?><th></th><?php endif; ?></tr></thead>
      <tbody>
        <?php foreach ($groups as $g): $l = $g['policy']['linux']; $w = $g['policy']['windows']; ?>
          <tr>
            <td><strong><?= e($g['name']) ?></strong><?php if ('' !== $g['description']): ?><br><span class="muted"><?= e($g['description']) ?></span><?php endif; ?></td>
            <td><?= (int) $g['endpoints'] ?><?php if ('' !== ($g['policy']['agent_version'] ?? '')): ?><br><span class="muted">agent <?= e($g['policy']['agent_version']) ?></span><?php endif; ?></td>
            <td><?= $l['enabled'] ? e(implode(', ', array_map(static fn (string $s): string => Portal\Endpoints::LINUX_SERVICES[$s] ?? $s, $l['services']))) . ' · RADIUS group ' . e($radiusNames[$l['radius_group_id']] ?? '?') : 'off' ?></td>
            <td>sign-in: <?= e(Portal\Endpoints::CP_MODES[$w['cpus_logon'][0]] ?? $w['cpus_logon']) ?><?= (int) ($w['timeout_reconnect'] ?? 0) > 0 ? ' · reconnect without a new code for ' . (int) $w['timeout_reconnect'] . ' min' : '' ?><?= '3' !== (string) ($w['cpus_credui'][0] ?? '3') ? ' · <strong>code in credential prompts</strong>' : '' ?><?= $w['cache_enabled'] ? ' · offline cache ' . (int) $w['cache_days'] . ' days' : '' ?><?= !empty($w['signin_auto']) ? ' · Sign-in installed by the agent' : '' ?></td>
            <?php if ($canManage): ?>
              <td class="row-actions">
                <a class="button-small" href="<?= e(route('endpoint-group', ['id' => $g['id']])) ?>">Edit</a>
                <?php if (0 === (int) $g['endpoints']): ?>
                  <form method="post" action="<?= e(route('endpoint-group-delete')) ?>" class="inline" data-confirm="Delete group <?= e($g['name']) ?>?">
                    <?= csrf_field() ?><input type="hidden" name="id" value="<?= e($g['id']) ?>"><button type="submit" class="button-small button-danger">Delete</button>
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

<section class="panel">
  <div class="toolbar">
    <h2>Assignment from Active Directory</h2>
    <?php if ($canManage && $adReady && [] !== $rules): ?>
      <form method="post" action="<?= e(route('endpoint-rules')) ?>" class="inline"><?= csrf_field() ?><input type="hidden" name="op" value="check"><button type="submit" class="button">Check AD now</button></form>
    <?php endif; ?>
  </div>
  <p class="hint">Rules put each machine in a group from its computer account: the first matching rule wins. They are re-checked every 15 minutes and when a machine enrols, so moving a computer to another OU or group changes its policy. Machines an administrator moved by hand are left alone.</p>
  <?php if (!$adReady): ?>
    <div class="alert alert-info" role="status">Configure Active Directory on the <a href="<?= e(route('directory')) ?>">Directory</a> page first (the service account reads computer accounts).</div>
  <?php endif; ?>
  <div class="table-wrap">
    <table class="table">
      <thead><tr><th>#</th><th>When</th><th>Then group</th><?php if ($canManage): ?><th></th><?php endif; ?></tr></thead>
      <tbody>
        <?php foreach ($rules as $i => $rule): ?>
          <tr>
            <td><?= $i + 1 ?></td>
            <td><?= e(Portal\Endpoints::RULE_TYPES[$rule['type']]) ?>: <code><?= e($rule['value']) ?></code></td>
            <td><?= e($names[$rule['group_id']] ?? '?') ?></td>
            <?php if ($canManage): ?>
              <td class="row-actions">
                <?php foreach (['up' => '↑', 'down' => '↓'] as $op => $arrow): ?>
                  <form method="post" action="<?= e(route('endpoint-rules')) ?>" class="inline"><?= csrf_field() ?><input type="hidden" name="op" value="<?= e($op) ?>"><input type="hidden" name="id" value="<?= e($rule['id']) ?>"><button type="submit" class="button-small" aria-label="Move <?= e($op) ?>"><?= $arrow ?></button></form>
                <?php endforeach; ?>
                <form method="post" action="<?= e(route('endpoint-rules')) ?>" class="inline" data-confirm="Delete this rule?"><?= csrf_field() ?><input type="hidden" name="op" value="delete"><input type="hidden" name="id" value="<?= e($rule['id']) ?>"><button type="submit" class="button-small button-danger">Delete</button></form>
              </td>
            <?php endif; ?>
          </tr>
        <?php endforeach; ?>
        <?php if ([] === $rules): ?><tr><td colspan="4" class="muted">No rules: machines stay in the group of their enrolment token.</td></tr><?php endif; ?>
      </tbody>
    </table>
  </div>
  <?php if ($canManage && [] !== $groups): ?>
    <form method="post" action="<?= e(route('endpoint-rules')) ?>" class="filters">
      <?= csrf_field() ?><input type="hidden" name="op" value="add">
      <label>When
        <select name="type"><?php foreach (Portal\Endpoints::RULE_TYPES as $value => $label): ?><option value="<?= e($value) ?>"><?= e($label) ?></option><?php endforeach; ?></select></label>
      <label>OU or group <input name="value" placeholder="OU=Laptops,DC=example,DC=com" maxlength="512"></label>
      <label>Then group
        <select name="group_id"><?php foreach ($groups as $g): ?><option value="<?= e($g['id']) ?>"><?= e($g['name']) ?></option><?php endforeach; ?></select></label>
      <button type="submit" class="button-small">Add rule</button>
    </form>
  <?php endif; ?>
  <?php if (null !== $lastCheck): ?><p class="muted">Last check: <a href="<?= e(route('job', ['id' => $lastCheck['id']])) ?>"><?= e(format_time($lastCheck['created_at'])) ?> — <?= e($lastCheck['status']) ?></a></p><?php endif; ?>
</section>
