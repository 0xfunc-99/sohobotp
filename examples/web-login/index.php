<?php
/**
 * SohobOTP example: a website that asks for a SohobOTP code at login, through the portal's
 * REST API. It stands in for any web application you want to protect (a management console,
 * a dashboard): your application checks its own password, then asks SohobOTP about the code.
 *
 *   SOHOBOTP_PORTAL   https://portal-address            (no trailing slash)
 *   SOHOBOTP_API_KEY  sohob_...                        API key with "auth.check" (+ "users.read" for /users)
 *   SOHOBOTP_API_KEY_FILE  or: a file for the key; while it does not exist the page asks for the key once
 *   SOHOBOTP_CA       path to the portal's CA certificate (PEM), when it is not publicly trusted
 *   SOHOBOTP_INSECURE 1 = do not check the portal certificate (a test portal only, never in production)
 *   DEMO_PASSWORD     the password this demo application accepts for every user (its "own" password)
 *
 * Run:  php -S 0.0.0.0:8090 -t examples/web-login
 * The API calls each page makes are shown at the bottom ("What happened"), without the key.
 */
declare(strict_types=1);

session_set_cookie_params(['httponly' => true, 'samesite' => 'Strict', 'secure' => !empty($_SERVER['HTTPS'])]);
session_start();
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'self'; style-src 'unsafe-inline'");

$portal = rtrim((string) getenv('SOHOBOTP_PORTAL'), '/');
$key = (string) getenv('SOHOBOTP_API_KEY');
$keyFile = (string) getenv('SOHOBOTP_API_KEY_FILE');
if ('' === $key && '' !== $keyFile && is_file($keyFile)) {
    $key = trim((string) file_get_contents($keyFile));
}
$demoPassword = (string) (getenv('DEMO_PASSWORD') ?: 'demo');
$calls = []; // shown on the page: method, path, sent body, HTTP status, answer

function e(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
}

/** Call the SohobOTP API. @return array{0: int, 1: array} HTTP status and the JSON answer */
function api(string $method, string $path, ?array $body = null): array
{
    global $portal, $key, $calls;
    $ch = curl_init($portal . '/portal/api.php' . $path);
    $options = [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $key, 'Content-Type: application/json', 'Accept: application/json'],
    ];
    if (null !== $body) {
        $options[CURLOPT_POSTFIELDS] = json_encode($body);
    }
    if ('' !== (string) getenv('SOHOBOTP_CA')) {
        $options[CURLOPT_CAINFO] = (string) getenv('SOHOBOTP_CA');
    }
    if ('1' === getenv('SOHOBOTP_INSECURE')) {
        $options[CURLOPT_SSL_VERIFYPEER] = false;
        $options[CURLOPT_SSL_VERIFYHOST] = 0;
    }
    curl_setopt_array($ch, $options);
    $raw = curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $answer = false === $raw ? ['error' => 'connection', 'message' => curl_error($ch)] : (json_decode((string) $raw, true) ?? ['error' => 'not_json', 'message' => substr((string) $raw, 0, 200)]);
    curl_close($ch);
    $shown = $body;
    if (isset($shown['code'])) {
        $shown['code'] = str_repeat('•', strlen((string) $shown['code'])); // never show codes, even in a demo
    }
    $calls[] = [$method, '/portal/api.php' . $path, $shown, $status, $answer];
    return [$status, $answer];
}

function csrf(): string
{
    $_SESSION['csrf'] ??= bin2hex(random_bytes(16));
    return '<input type="hidden" name="csrf" value="' . e($_SESSION['csrf']) . '">';
}

function csrfOk(): bool
{
    return is_string($_POST['csrf'] ?? null) && hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf']);
}

$page = trim((string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH), '/');
$message = '';
$configured = '' !== $portal && '' !== $key;

// First run: the administrator pastes the API key once; it is kept in SOHOBOTP_API_KEY_FILE
if (!$configured && '' !== $keyFile && !is_file($keyFile) && 'POST' === ($_SERVER['REQUEST_METHOD'] ?? '') && 'setup' === ($_POST['step'] ?? '') && csrfOk()) {
    $pasted = trim((string) ($_POST['key'] ?? ''));
    if (1 === preg_match('/^sohob_[A-Za-z0-9_-]{8,200}$/', $pasted)) {
        file_put_contents($keyFile, $pasted . "\n", LOCK_EX);
        chmod($keyFile, 0600);
        header('Location: /');
        exit;
    }
    $message = 'That is not a SohobOTP API key (it starts with sohob_).';
}

if ('logout' === $page) {
    session_regenerate_id(true);
    $_SESSION = [];
    header('Location: /');
    exit;
}

// Step 1: the application's own password (here: one demo password for everyone)
if ('POST' === ($_SERVER['REQUEST_METHOD'] ?? '') && 'login' === ($_POST['step'] ?? '') && csrfOk()) {
    $user = trim((string) ($_POST['user'] ?? ''));
    if ('' === $user || !hash_equals($demoPassword, (string) ($_POST['password'] ?? ''))) {
        $message = 'Wrong user name or password.';
    } else {
        $_SESSION['pending_user'] = $user; // password fine: now the code
    }
}

// Step 2: the SohobOTP code, checked by the portal
if ('POST' === ($_SERVER['REQUEST_METHOD'] ?? '') && 'code' === ($_POST['step'] ?? '') && csrfOk() && isset($_SESSION['pending_user'])) {
    [$status, $answer] = api('POST', '/v1/auth/check', ['user' => $_SESSION['pending_user'], 'code' => trim((string) ($_POST['code'] ?? ''))]);
    $result = 200 === $status ? (string) ($answer['result'] ?? '') : '';
    if ('accepted' === $result) {
        session_regenerate_id(true);
        $_SESSION['user'] = $_SESSION['pending_user'];
        unset($_SESSION['pending_user']);
    } else {
        $message = match ($result) {
            'rejected' => 'Wrong code. Type the code your app shows now.',
            'locked' => 'Too many wrong codes: this user is locked for a while (or an administrator unlocks it).',
            'disabled' => 'This user is disabled in SohobOTP.',
            'unknown' => 'SohobOTP has no user with this name.',
            default => 'SohobOTP could not check the code (' . ($answer['error'] ?? 'HTTP ' . $status) . ': ' . ($answer['message'] ?? '') . ').',
        };
        if (in_array($result, ['unknown', 'disabled'], true)) {
            unset($_SESSION['pending_user']); // start again
        }
    }
}
if ('POST' === ($_SERVER['REQUEST_METHOD'] ?? '') && 'cancel' === ($_POST['step'] ?? '') && csrfOk()) {
    unset($_SESSION['pending_user']);
}

$users = null;
if ('users' === $page && isset($_SESSION['user'])) {
    [$status, $answer] = api('GET', '/v1/users?per_page=100');
    $users = 200 === $status ? ($answer['users'] ?? []) : null;
    if (null === $users) {
        $message = 'The user list needs an API key with "Read users" (' . ($answer['message'] ?? 'HTTP ' . $status) . ').';
    }
}
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Demo Cloud Console</title>
<style>
  :root { --bg: #f4f6fb; --card: #fff; --text: #172033; --muted: #5b6478; --accent: #1b5fd1; --bad: #b42318; --ok: #0f7b4b; --code: #0f172a; }
  * { box-sizing: border-box; }
  body { margin: 0; font: 16px/1.5 system-ui, -apple-system, Segoe UI, sans-serif; background: var(--bg); color: var(--text); }
  header { background: #1d2b4f; color: #fff; padding: 14px 24px; display: flex; justify-content: space-between; align-items: center; }
  header a { color: #cfe0ff; margin-left: 16px; }
  main { max-width: 860px; margin: 32px auto; padding: 0 16px; }
  .card { background: var(--card); border-radius: 12px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,.08); margin-bottom: 24px; }
  label { display: block; margin: 12px 0 4px; font-weight: 600; }
  input[type=text], input[type=password] { width: 100%; padding: 10px 12px; border: 1px solid #c8cfdc; border-radius: 8px; font: inherit; }
  button { margin-top: 16px; padding: 10px 18px; border: 0; border-radius: 8px; background: var(--accent); color: #fff; font: inherit; font-weight: 600; cursor: pointer; }
  button.secondary { background: #e4e8f1; color: var(--text); }
  .msg { padding: 10px 14px; border-radius: 8px; background: #fde8e7; color: var(--bad); margin-bottom: 16px; }
  .ok { color: var(--ok); font-weight: 700; }
  .muted { color: var(--muted); }
  table { width: 100%; border-collapse: collapse; } th, td { text-align: left; padding: 8px; border-bottom: 1px solid #e4e8f1; }
  pre { background: var(--code); color: #e2e8f0; padding: 12px; border-radius: 8px; overflow-x: auto; font-size: 13px; white-space: pre-wrap; word-break: break-all; }
</style>
</head>
<body>
<header>
  <strong>Demo Cloud Console</strong>
  <nav><?php if (isset($_SESSION['user'])): ?>Signed in as <strong><?= e($_SESSION['user']) ?></strong><a href="/">Home</a><a href="/users">Users (API)</a><a href="/logout">Sign out</a><?php else: ?><span class="muted" style="color:#cfe0ff">protected by SohobOTP</span><?php endif; ?></nav>
</header>
<main>
<?php if (!$configured && '' !== $portal && '' !== $keyFile && !is_file($keyFile)): ?>
  <div class="card">
    <h2>First run: connect to SohobOTP</h2>
    <p>In the SohobOTP portal, open <strong>API keys</strong>, create a key with the permissions <strong>Check a user's code</strong> and <strong>Read users</strong>, and paste it here. It is kept by this demo only (<?= e($keyFile) ?>).</p>
    <form method="post"><?= csrf() ?><input type="hidden" name="step" value="setup">
      <label for="key">API key</label><input type="password" id="key" name="key" autocomplete="off" required>
      <button type="submit">Save</button>
    </form>
  </div>
<?php elseif (!$configured): ?>
  <div class="card"><div class="msg">Not configured: set SOHOBOTP_PORTAL and SOHOBOTP_API_KEY (see the top of index.php).</div></div>
<?php endif; ?>
<?php if ('' !== $message): ?><div class="msg"><?= e($message) ?></div><?php endif; ?>

<?php if (isset($_SESSION['user'])): ?>
  <?php if (null !== $users): ?>
    <div class="card">
      <h2>Users in SohobOTP (GET /v1/users)</h2>
      <table>
        <thead><tr><th>User</th><th>Name</th><th>State</th><th>Authenticator</th><th>From AD</th></tr></thead>
        <tbody>
        <?php foreach ($users as $u): ?>
          <tr>
            <td><strong><?= e((string) ($u['user'] ?? '')) ?></strong></td>
            <td><?= e((string) ($u['display_name'] ?? '')) ?></td>
            <td><?= !empty($u['locked']) ? 'locked' : (!empty($u['enabled']) ? 'enabled' : 'disabled') ?></td>
            <td><?= e('' !== (string) ($u['token'] ?? '') ? (string) $u['token'] : 'none yet') ?></td>
            <td><?= !empty($u['synchronized']) ? 'yes' : 'no' ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  <?php else: ?>
    <div class="card">
      <h2>Welcome, <?= e($_SESSION['user']) ?></h2>
      <p class="ok">You signed in with your password and your SohobOTP code.</p>
      <p class="muted">This page stands in for your real console (virtual machines, dashboards...). Open <a href="/users">Users (API)</a> to see the list read from SohobOTP.</p>
    </div>
  <?php endif; ?>
<?php elseif (isset($_SESSION['pending_user'])): ?>
  <div class="card">
    <h2>Step 2 of 2: your code</h2>
    <p>Hello <strong><?= e($_SESSION['pending_user']) ?></strong>. Type the 6-digit code from your authenticator app.</p>
    <form method="post"><?= csrf() ?><input type="hidden" name="step" value="code">
      <label for="code">Code</label><input type="text" id="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="8" required autofocus>
      <button type="submit">Sign in</button>
    </form>
    <form method="post"><?= csrf() ?><input type="hidden" name="step" value="cancel"><button type="submit" class="secondary">Cancel</button></form>
  </div>
<?php else: ?>
  <div class="card">
    <h2>Step 1 of 2: sign in</h2>
    <p class="muted">Use your SohobOTP user name. The password of this demo is <code><?= e($demoPassword) ?></code> for everyone (your real application checks its own passwords).</p>
    <form method="post"><?= csrf() ?><input type="hidden" name="step" value="login">
      <label for="user">User name</label><input type="text" id="user" name="user" autocomplete="username" required autofocus>
      <label for="password">Password</label><input type="password" id="password" name="password" autocomplete="current-password" required>
      <button type="submit">Next</button>
    </form>
  </div>
<?php endif; ?>

<?php if ([] !== $calls): ?>
  <div class="card">
    <h3>What happened (the API calls this page made)</h3>
    <?php foreach ($calls as [$m, $p, $b, $s, $a]): ?>
<pre><?= e($m . ' ' . $p . "\nAuthorization: Bearer sohob_…(the API key)" . (null !== $b ? "\n\n" . json_encode($b, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : '') . "\n\n→ HTTP " . $s . "\n" . json_encode($a, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) ?></pre>
    <?php endforeach; ?>
  </div>
<?php endif; ?>
</main>
</body>
</html>
