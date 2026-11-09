<?php defined('PORTAL_ROOT') || exit; ?>
<div class="alert alert-info" role="status">
  Shown only once. Valid until <?= e(format_time($token['expires_at'])) ?> for <?= (int) $token['max_uses'] ?> machine(s), group <strong><?= e($group['name'] ?? '?') ?></strong>.
</div>
<p class="secret"><code><?= e($plain) ?></code></p>
<h2>Install on Linux (as root)</h2>
<pre><code>sohobotp-agent install --portal <?= e($portal) ?> --token <?= e($plain) ?> --pin <?= e($pin) ?></code></pre>
<h2>Install on Windows (administrator PowerShell)</h2>
<pre><code>.\sohobotp-agent.exe install --portal <?= e($portal) ?> --token <?= e($plain) ?> --pin <?= e($pin) ?></code></pre>
<p class="hint">If the portal uses a self-signed certificate, add <code>--ca-file</code> with the path of its CA certificate. The pin makes the agent refuse any other portal.</p>
<div class="actions"><a class="button" href="<?= e(route('endpoint-enrol')) ?>">Done</a></div>
