<?php defined('PORTAL_ROOT') || exit; ?>
<section class="panel">
  <h2>REST API</h2>
  <p>Automation and other applications use the API at <code>https://<?= e((string) ($_SERVER['HTTP_HOST'] ?? 'portal')) ?>/portal/api.php/v1/…</code>
    with <code>Authorization: Bearer &lt;key&gt;</code>. Every change made with a key is in the audit trail as <code>api:&lt;key name&gt;</code>.
    Calls: <code>GET /v1/users</code>, <code>GET|PATCH|DELETE /v1/users/{user}</code>, <code>POST /v1/users</code>,
    <code>POST /v1/users/{user}/unlock|enroll|route</code>, <code>POST /v1/auth/check</code>, <code>GET /v1/endpoints</code>,
    <code>GET /v1/radius/servers</code>, <code>GET /v1/audit</code>, <code>GET /v1/me</code>, <code>GET /v1/health</code> (portal/README.md).</p>
</section>

<section class="panel">
  <h2>Keys</h2>
  <div class="table-wrap">
    <table class="table">
      <thead><tr><th>Name</th><th>Permissions</th><th>Allowed from</th><th>Expires</th><th>Rate / min</th><th>Last used</th><th></th></tr></thead>
      <tbody>
        <?php foreach ($keys as $k): ?>
          <tr>
            <td><strong><?= e($k['name']) ?></strong><br><span class="muted">by <?= e($k['created_by']) ?>, <?= e(format_time($k['created_at'])) ?></span></td>
            <td><?= e(implode(', ', $k['scopes'])) ?></td>
            <td><?= [] === $k['networks'] ? 'anywhere' : '<code>' . e(implode(', ', $k['networks'])) . '</code>' ?></td>
            <td class="nowrap"><?= null === $k['expires_at'] ? 'never' : e(format_time($k['expires_at'])) . ($k['expires_at'] < time() ? ' <span class="status status-failure">expired</span>' : '') ?></td>
            <td><?= (int) $k['rate'] ?></td>
            <td class="nowrap"><?= e(format_time($k['last_used_at'])) ?><?= '' !== $k['last_ip'] ? '<br><span class="muted">' . e($k['last_ip']) . '</span>' : '' ?></td>
            <td class="row-actions">
              <form method="post" action="<?= e(route('api-keys')) ?>" class="inline" data-confirm="Revoke the API key <?= e($k['name']) ?>? Programs using it stop working at once.">
                <?= csrf_field() ?><input type="hidden" name="op" value="revoke"><input type="hidden" name="id" value="<?= e($k['id']) ?>">
                <button type="submit" class="button-small">Revoke</button>
              </form>
            </td>
          </tr>
        <?php endforeach; ?>
        <?php if ([] === $keys): ?><tr><td colspan="7" class="muted">No API keys yet.</td></tr><?php endif; ?>
      </tbody>
    </table>
  </div>
</section>

<section class="panel">
  <h2>New key</h2>
  <?php if (null !== $error): ?><div class="alert alert-error" role="alert"><?= e($error) ?></div><?php endif; ?>
  <form method="post" action="<?= e(route('api-keys')) ?>" class="form narrow">
    <?= csrf_field() ?><input type="hidden" name="op" value="create">
    <label>Name (the program or team using it) <input name="name" value="<?= e($input['name']) ?>" required maxlength="64" placeholder="HR onboarding"></label>
    <fieldset>
      <legend>Permissions (give only what the program needs)</legend>
      <?php foreach (Portal\ApiKeys::SCOPES as $scope => $label): ?>
        <label class="choice"><input type="checkbox" name="scopes[]" value="<?= e($scope) ?>"<?= in_array($scope, $input['scopes'], true) ? ' checked' : '' ?>>
          <span><code><?= e($scope) ?></code> — <?= e($label) ?></span></label>
      <?php endforeach; ?>
    </fieldset>
    <label>Allowed from (IP addresses or networks, comma separated; empty: anywhere)
      <input name="networks" value="<?= e($input['networks']) ?>" maxlength="2000" placeholder="10.0.0.0/24, 192.0.2.7"></label>
    <label>Valid for (days; empty: no expiry) <input name="expires_days" value="<?= e($input['expires_days']) ?>" inputmode="numeric" maxlength="4"></label>
    <label>Rate limit (requests per minute) <input name="rate" value="<?= e($input['rate']) ?>" inputmode="numeric" maxlength="4"></label>
    <div class="actions"><button type="submit" class="button-primary">Create key</button></div>
  </form>
</section>
