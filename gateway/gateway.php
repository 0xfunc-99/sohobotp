<?php
/**
 * SohobOTP login gateway: a sign-in page in front of web sites that have no login of their own,
 * or none you can change (Prometheus, Alertmanager, Grafana, a VMware console...).
 *
 * nginx asks this script about every request (auth_request, action "check"): a request with a
 * valid gateway session for this site goes through to the site; any other is sent to the sign-in
 * page (action "page": /_sohobotp/login), which checks the user's SohobOTP code with the portal's
 * REST API (POST /v1/auth/check) and then sets the session cookie.
 *
 * Session cookie "sohobotp_<site>": base64url(JSON {u: user, s: site, e: expiry, i: issued}) . "."
 * . base64url(HMAC-SHA256 with the gateway key, /data/gateway.key). Nothing is kept on the server;
 * a user removed from the site's allowed list, or a new gateway key, ends the sessions.
 *
 * Configuration: /etc/sohobotp-gateway/runtime.json (written at container start from the
 * environment, see entrypoint.sh) and sites.json (see README.md).
 */
declare(strict_types=1);

const CONFIG_DIR = '/etc/sohobotp-gateway';
const DATA_DIR = '/data';
const MAX_FAILURES = 10;      // wrong codes from one address ...
const FAILURE_WINDOW = 900;   // ... within 15 minutes: that address waits 15 minutes

header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

$runtime = json_decode((string) @file_get_contents(getenv('SOHOBOTP_GATEWAY_RUNTIME') ?: CONFIG_DIR . '/runtime.json'), true) ?: [];
$sites = json_decode((string) @file_get_contents(getenv('SOHOBOTP_GATEWAY_SITES') ?: CONFIG_DIR . '/sites.json'), true) ?: [];
$siteId = (string) ($_SERVER['SOHOBOTP_SITE'] ?? '');
$site = null;
foreach ($sites as $s) {
    if (is_array($s) && ($s['id'] ?? null) === $siteId) {
        $site = $s;
    }
}
if (null === $site) {
    http_response_code(500);
    exit('Gateway: unknown site.');
}
$action = (string) ($_SERVER['SOHOBOTP_ACTION'] ?? '');
$cookieName = 'sohobotp_' . $site['id'];

if ('check' === $action) {
    $user = session_user($site, $cookieName);
    if (null === $user) {
        http_response_code(401);
        exit;
    }
    header('X-SohobOTP-User: ' . $user);
    http_response_code(204);
    exit;
}

$path = (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'");

if ('/_sohobotp/logout' === $path) {
    set_cookie($cookieName, '', 1, '/');
    page($site, 'Signed out', '<p>You are signed out of <strong>' . e($site['name']) . '</strong>.</p><p><a href="/">Sign in again</a></p>');
}
if ('/_sohobotp/login' !== $path) {
    http_response_code(404);
    page($site, 'Not found', '<p>Nothing here.</p>');
}

$next = safe_next((string) ($_SERVER['QUERY_STRING'] ?? ''));
$ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
$message = '';
$csrfName = 'sohobotp_csrf_' . $site['id'];

if (null !== session_user($site, $cookieName)) {
    redirect($next); // already signed in (e.g. a second tab)
}

if ('POST' === ($_SERVER['REQUEST_METHOD'] ?? '')) {
    $sent = (string) ($_POST['csrf'] ?? '');
    $user = mb_strtolower(trim(mb_substr((string) ($_POST['user'] ?? ''), 0, 128)));
    $code = preg_replace('/\s+/', '', (string) ($_POST['code'] ?? '')) ?? '';
    if ('' === $sent || !hash_equals((string) ($_COOKIE[$csrfName] ?? ''), $sent)) {
        $message = 'The page expired. Please try again.';
    } elseif (blocked($ip)) {
        $message = 'Too many wrong codes from your address. Wait 15 minutes, then try again.';
    } elseif ('' === $user || !preg_match('/^[0-9]{6,8}$/', $code)) {
        $message = 'Type your user name and the 6-digit code from your authenticator app.';
    } else {
        [$result, $error] = check_code($runtime, $user, $code);
        if ('accepted' === $result && allowed($site, $user)) {
            failures($ip, false);
            $now = time();
            $expires = $now + 3600 * max(1, min(24, (int) ($site['hours'] ?? 8)));
            set_cookie($cookieName, sign(['u' => $user, 's' => $site['id'], 'e' => $expires, 'i' => $now]), $expires, '/');
            set_cookie($csrfName, '', 1, '/_sohobotp/');
            log_line("signed in: $user from $ip to {$site['id']}");
            redirect($next);
        }
        if ('accepted' === $result) {
            log_line("refused (not allowed on this site): $user from $ip to {$site['id']}");
            $message = 'Your code is right, but you are not allowed to open ' . $site['name'] . '. Ask your administrator.';
        } elseif (null !== $error) {
            log_line("portal error: $error");
            $message = 'SohobOTP could not check the code right now. Try again in a minute; if it goes on, tell your administrator.';
        } else {
            failures($ip, true);
            log_line("refused ($result): $user from $ip to {$site['id']}");
            $message = match ($result) {
                'locked' => 'Too many wrong codes for this user: it is locked for a while (or an administrator unlocks it).',
                'disabled' => 'This user is disabled in SohobOTP.',
                default => 'Wrong user name or code.', // "unknown" too: does not tell which user names exist
            };
        }
    }
}

$csrf = rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '=');
set_cookie($csrfName, $csrf, 0, '/_sohobotp/');
page($site, 'Sign in', ('' !== $message ? '<div class="msg" role="alert">' . e($message) . '</div>' : '')
    . '<p>' . e($site['name']) . ' is protected by SohobOTP. Sign in with your user name and the code from your authenticator app.</p>'
    . '<form method="post" action="/_sohobotp/login?next=' . e($next) . '">'
    . '<input type="hidden" name="csrf" value="' . e($csrf) . '">'
    . '<label for="user">User name</label><input type="text" id="user" name="user" autocomplete="username" required autofocus value="' . e((string) ($_POST['user'] ?? '')) . '">'
    . '<label for="code">Code</label><input type="text" id="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="8" required>'
    . '<button type="submit">Sign in</button></form>');

// ---------------------------------------------------------------------------------------------

function e(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
}

function b64u(string $s): string
{
    return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
}

function gateway_key(): string
{
    static $key = null;
    if (null !== $key) {
        return $key;
    }
    $file = (getenv('SOHOBOTP_GATEWAY_DATA') ?: DATA_DIR) . '/gateway.key';
    $raw = @file_get_contents($file);
    if (false === $raw || 32 !== strlen($raw)) {
        http_response_code(500);
        exit('Gateway: key missing (' . $file . ').');
    }
    return $key = $raw;
}

function sign(array $claims): string
{
    $payload = b64u((string) json_encode($claims));
    return $payload . '.' . b64u(hash_hmac('sha256', $payload, gateway_key(), true));
}

/** The user of a valid session for this site, or null. */
function session_user(array $site, string $cookieName): ?string
{
    $value = (string) ($_COOKIE[$cookieName] ?? '');
    if (!preg_match('/^([A-Za-z0-9_-]{10,1000})\.([A-Za-z0-9_-]{43})$/', $value, $m)
        || !hash_equals(b64u(hash_hmac('sha256', $m[1], gateway_key(), true)), $m[2])) {
        return null;
    }
    $claims = json_decode((string) base64_decode(strtr($m[1], '-_', '+/'), true), true);
    if (!is_array($claims) || ($claims['s'] ?? null) !== $site['id'] || !is_int($claims['e'] ?? null) || $claims['e'] <= time()
        || !is_string($claims['u'] ?? null) || !allowed($site, $claims['u'])) {
        return null;
    }
    return $claims['u'];
}

/** sites.json "allow": user names, or "*" for every SohobOTP user. */
function allowed(array $site, string $user): bool
{
    $allow = array_map(static fn ($u): string => mb_strtolower(trim((string) $u)), (array) ($site['allow'] ?? []));
    return in_array('*', $allow, true) || in_array($user, $allow, true);
}

/** Where to go after signing in: a path on this site only (no other host, no scheme). */
function safe_next(string $query): string
{
    $next = str_starts_with($query, 'next=') ? substr($query, 5) : '/'; // the request URI as nginx got it (kept encoded)
    if (!str_starts_with($next, '/') || str_starts_with($next, '//') || str_contains($next, '\\') || preg_match('/[\x00-\x1f\x7f]/', $next)
        || str_starts_with($next, '/_sohobotp/')) {
        return '/';
    }
    return $next;
}

/** @return array{0: string, 1: ?string} the portal's result (accepted|rejected|locked|disabled|unknown) and an error */
function check_code(array $runtime, string $user, string $code): array
{
    $portal = rtrim((string) ($runtime['portal'] ?? ''), '/');
    $key = (string) ($runtime['api_key'] ?? '');
    if ('' !== (string) ($runtime['api_key_file'] ?? '') && '' === $key) {
        $key = trim((string) @file_get_contents((string) $runtime['api_key_file']));
    }
    if ('' === $portal || '' === $key) {
        return ['', 'SOHOBOTP_PORTAL or the API key is not set'];
    }
    $ch = curl_init($portal . '/portal/api.php/v1/auth/check');
    $options = [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode(['user' => $user, 'code' => $code]),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $key, 'Content-Type: application/json', 'Accept: application/json'],
    ];
    if ('' !== (string) ($runtime['ca'] ?? '')) {
        $options[CURLOPT_CAINFO] = (string) $runtime['ca'];
    }
    if (!empty($runtime['insecure'])) {
        $options[CURLOPT_SSL_VERIFYPEER] = false;
        $options[CURLOPT_SSL_VERIFYHOST] = 0;
    }
    curl_setopt_array($ch, $options);
    $raw = curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);
    if (false === $raw) {
        return ['', 'connection: ' . $curlError];
    }
    $answer = json_decode((string) $raw, true);
    $result = is_array($answer) ? (string) ($answer['result'] ?? '') : '';
    if (200 !== $status || !in_array($result, ['accepted', 'rejected', 'locked', 'disabled', 'unknown'], true)) {
        return ['', 'HTTP ' . $status . ' ' . (is_array($answer) ? (string) ($answer['error'] ?? '') . ' ' . (string) ($answer['message'] ?? '') : substr((string) $raw, 0, 100))];
    }
    return [$result, null];
}

/** Wrong codes per address (data/failures.json, locked while changed). */
function failures(string $ip, bool $failed): void
{
    $file = (getenv('SOHOBOTP_GATEWAY_DATA') ?: DATA_DIR) . '/failures.json';
    $h = fopen($file, 'c+');
    if (false === $h) {
        return;
    }
    flock($h, LOCK_EX);
    $data = json_decode((string) stream_get_contents($h), true) ?: [];
    $now = time();
    $data = array_filter($data, static fn ($list): bool => is_array($list) && [] !== array_filter($list, static fn ($t): bool => $t > $now - FAILURE_WINDOW));
    if ($failed) {
        $data[$ip][] = $now;
        $data[$ip] = array_slice(array_values(array_filter($data[$ip], static fn ($t): bool => $t > $now - FAILURE_WINDOW)), -MAX_FAILURES);
    } else {
        unset($data[$ip]);
    }
    ftruncate($h, 0);
    rewind($h);
    fwrite($h, (string) json_encode($data));
    flock($h, LOCK_UN);
    fclose($h);
}

function blocked(string $ip): bool
{
    $data = json_decode((string) @file_get_contents((getenv('SOHOBOTP_GATEWAY_DATA') ?: DATA_DIR) . '/failures.json'), true) ?: [];
    $recent = array_filter((array) ($data[$ip] ?? []), static fn ($t): bool => $t > time() - FAILURE_WINDOW);
    return count($recent) >= MAX_FAILURES;
}

function set_cookie(string $name, string $value, int $expires, string $path): void
{
    setcookie($name, $value, [
        'expires' => $expires, 'path' => $path, 'httponly' => true, 'samesite' => 'Lax',
        'secure' => 'https' === ($_SERVER['REQUEST_SCHEME'] ?? '') || !empty($_SERVER['HTTPS']),
    ]);
}

function redirect(string $to): never
{
    header('Location: ' . $to, true, 303);
    exit;
}

function log_line(string $line): void
{
    error_log('sohobotp-gateway: ' . $line);
}

function page(array $site, string $title, string $body): never
{
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<title>' . e($title . ' · ' . $site['name']) . '</title><style>'
        . ':root{--bg:#f4f6fb;--card:#fff;--text:#172033;--muted:#5b6478;--accent:#1b5fd1;--bad:#b42318}'
        . '@media (prefers-color-scheme:dark){:root{--bg:#0f1420;--card:#182031;--text:#e7ebf3;--muted:#9aa4b8;--accent:#5b8ff0;--bad:#ff8a80}}'
        . '*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--text);padding:16px}'
        . 'main{width:100%;max-width:380px;background:var(--card);border-radius:14px;padding:28px;box-shadow:0 2px 10px rgba(0,0,0,.08)}'
        . 'h1{font-size:20px;margin:0 0 4px}.site{color:var(--muted);margin:0 0 16px}label{display:block;margin:14px 0 4px;font-weight:600}'
        . 'input{width:100%;padding:10px 12px;border:1px solid #c8cfdc;border-radius:8px;font:inherit;background:var(--card);color:var(--text)}'
        . 'button{margin-top:18px;width:100%;padding:11px;border:0;border-radius:8px;background:var(--accent);color:#fff;font:inherit;font-weight:600;cursor:pointer}'
        . '.msg{padding:10px 12px;border-radius:8px;background:rgba(180,35,24,.1);color:var(--bad);margin-bottom:12px}a{color:var(--accent)}'
        . '</style></head><body><main><h1>' . e($title) . '</h1><p class="site">' . e($site['name']) . '</p>' . $body . '</main></body></html>';
    exit;
}
