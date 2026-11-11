<?php defined('PORTAL_ROOT') || exit; ?>
<p class="back"><a href="<?= e(route('endpoints')) ?>">← Endpoints</a></p>
<section class="panel">
  <h2>New enrolment token</h2>
  <p class="hint">The agent uses a token once to register the machine. Give it to whoever installs the agent; it is shown only once.</p>
  <form method="post" action="<?= e(route('endpoint-enrol')) ?>" class="form narrow">
    <?= csrf_field() ?><input type="hidden" name="op" value="create">
    <label>Endpoint group
      <select name="group_id"><?php foreach ($groups as $g): ?><option value="<?= e($g['id']) ?>"><?= e($g['name']) ?></option><?php endforeach; ?></select></label>
    <label>Label <input name="label" maxlength="100" placeholder="Paris office laptops, GPO rollout"></label>
    <label>Valid for (hours) <input name="hours" value="24" inputmode="numeric"></label>
    <label>Maximum machines <input name="max_uses" value="1" inputmode="numeric"><small>Use a higher number for a mass rollout (GPO, Ansible), with a short validity.</small></label>
    <label>New machines
      <select name="approval">
        <?php foreach (Portal\Endpoints::APPROVAL as $value => $label): ?><option value="<?= e($value) ?>"<?= 'directory' === $value ? ' selected' : '' ?>><?= e($label) ?></option><?php endforeach; ?>
      </select>
      <small>A token deployed with Group Policy can be read by any domain user (SYSVOL). With approval, a copied token cannot add an unknown machine: the computer must exist and be enabled in Active Directory, and its DNS name must resolve to the address it enrols from.</small></label>
    <div class="actions"><button type="submit" class="button-primary">Create token</button></div>
  </form>
  <p>Portal key pin (agents check it at install): <code><?= e(implode(' ', str_split($pin, 16))) ?></code></p>
</section>
<section class="panel">
  <h2>Tokens</h2>
  <div class="table-wrap">
    <table class="table">
      <thead><tr><th>Label</th><th>Group</th><th>Approval</th><th>Used</th><th>Expires</th><th>Created by</th><th>State</th><th></th></tr></thead>
      <tbody>
        <?php foreach ($tokens as $t): ?>
          <tr>
            <td><?= e($t['label'] ?: '—') ?> <span class="muted"><code><?= e($t['id']) ?></code></span></td>
            <td><?= e($names[$t['group_id']] ?? '?') ?></td>
            <td><?= e(['none' => 'none', 'manual' => 'administrator', 'directory' => 'Active Directory'][$t['approval'] ?? 'none'] ?? '') ?></td>
            <td><?= (int) $t['uses'] ?> / <?= (int) $t['max_uses'] ?></td>
            <td class="nowrap"><?= e(format_time($t['expires_at'])) ?></td>
            <td><?= e($t['created_by']) ?></td>
            <td><?= $t['usable'] ? '<span class="status status-success">usable</span>' : '<span class="status status-denied">' . ($t['revoked'] ? 'revoked' : ($t['uses'] >= $t['max_uses'] ? 'used up' : 'expired')) . '</span>' ?></td>
            <td><?php if ($t['usable']): ?>
              <form method="post" action="<?= e(route('endpoint-enrol')) ?>" class="inline" data-confirm="Revoke this token?">
                <?= csrf_field() ?><input type="hidden" name="op" value="revoke"><input type="hidden" name="id" value="<?= e($t['id']) ?>"><button type="submit" class="button-small button-danger">Revoke</button></form>
            <?php endif; ?></td>
          </tr>
        <?php endforeach; ?>
        <?php if ([] === $tokens): ?><tr><td colspan="8" class="muted">No tokens yet.</td></tr><?php endif; ?>
      </tbody>
    </table>
  </div>
</section>
