<?php
// Runs inside the test network against the gateway (http://gateway:8081 and :8082).
declare(strict_types=1);
$failed = 0;
$total = 0;
function check(string $name, bool $ok, string $detail = ''): void
{
    global $failed, $total;
    $total++;
    if (!$ok) {
        $failed++;
    }
    echo ($ok ? 'ok   ' : 'FAIL ') . $name . ($ok || '' === $detail ? '' : "  [$detail]") . "\n";
}
/** @return array{status: int, headers: array<string, list<string>>, body: string} */
function req(string $method, string $url, array $cookies = [], array $post = [], array $headers = []): array
{
    $ch = curl_init($url);
    $h = $headers;
    if ([] !== $cookies) {
        $h[] = 'Cookie: ' . implode('; ', array_map(static fn ($k, $v) => "$k=$v", array_keys($cookies), $cookies));
    }
    $out = [];
    curl_setopt_array($ch, [CURLOPT_CUSTOMREQUEST => $method, CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => $h, CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_HEADERFUNCTION => static function ($c, string $line) use (&$out): int {
            if (str_contains($line, ':')) {
                [$k, $v] = explode(':', $line, 2);
                $out[strtolower(trim($k))][] = trim($v);
            }
            return strlen($line);
        }] + ([] !== $post ? [CURLOPT_POSTFIELDS => http_build_query($post)] : []));
    $body = (string) curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    return ['status' => $status, 'headers' => $out, 'body' => $body];
}
function cookies(array $r): array
{
    $c = [];
    foreach ($r['headers']['set-cookie'] ?? [] as $line) {
        [$pair] = explode(';', $line, 2);
        [$k, $v] = explode('=', $pair, 2) + [1 => ''];
        $c[$k] = $v;
    }
    return $c;
}
/** Login page then POST; returns the POST response. */
function login(string $base, string $user, string $code, string $next = '/'): array
{
    $page = req('GET', "$base/_sohobotp/login?next=$next");
    $csrf = cookies($page)['sohobotp_csrf_' . (str_ends_with($base, '8081') ? 'app' : 'other')] ?? '';
    return req('POST', "$base/_sohobotp/login?next=$next", ['sohobotp_csrf_' . (str_ends_with($base, '8081') ? 'app' : 'other') => $csrf], ['csrf' => $csrf, 'user' => $user, 'code' => $code]);
}

$app = 'http://gateway:8081';
$other = 'http://gateway:8082';

$r = req('GET', "$app/");
check('no session: sent to the sign-in page', 302 === $r['status'] && '/_sohobotp/login?next=/' === ($r['headers']['location'][0] ?? ''), json_encode($r['headers']['location'] ?? []));
$r = req('GET', "$app/graph?g0.expr=up&x=%2F1");
check('no session: the page asked for is kept for after sign-in', '/_sohobotp/login?next=/graph?g0.expr=up&x=%2F1' === ($r['headers']['location'][0] ?? ''), json_encode($r['headers']['location'] ?? []));
$r = req('GET', "$app/api/v1/query?query=up", [], [], ['X-WEBAUTH-USER: alice']);
check('no session: a forged user header does not get in', 302 === $r['status']);
$page = req('GET', "$app/_sohobotp/login?next=/");
check('sign-in page: form and CSRF cookie', 200 === $page['status'] && str_contains($page['body'], 'name="code"') && isset(cookies($page)['sohobotp_csrf_app']));
check('sign-in page: cannot be framed', str_contains(implode(' ', $page['headers']['content-security-policy'] ?? []), "frame-ancestors 'none'"));

$r = req('POST', "$app/_sohobotp/login?next=/", [], ['csrf' => 'x', 'user' => 'alice', 'code' => '123456']);
check('POST without the CSRF cookie refused', 200 === $r['status'] && str_contains($r['body'], 'page expired') && !isset(cookies($r)['sohobotp_app']));
$r = login($app, 'alice', '111111');
check('wrong code refused', 200 === $r['status'] && str_contains($r['body'], 'Wrong user name or code') && !isset(cookies($r)['sohobotp_app']));
$r = login($app, 'mallory', '123456');
check('unknown user: the same message as a wrong code', str_contains($r['body'], 'Wrong user name or code'));
$r = login($app, 'alice', '999999');
check('locked user told so', str_contains($r['body'], 'locked'));
$r = login($app, 'bob', '123456');
check('right code but not in the site\'s allowed list: refused', str_contains($r['body'], 'not allowed to open Test console') && '' === (cookies($r)['sohobotp_app'] ?? ''));

$r = login($app, 'Alice', '123456', '/graph?g0.expr=up');
$session = cookies($r)['sohobotp_app'] ?? '';
check('right code: session cookie, back to the page asked for', 303 === $r['status'] && '/graph?g0.expr=up' === ($r['headers']['location'][0] ?? '') && '' !== $session, $r['status'] . ' ' . substr($r['body'], 0, 200));
check('session cookie is HttpOnly and SameSite', (bool) preg_grep('/^sohobotp_app=.*HttpOnly.*SameSite=Lax/i', $r['headers']['set-cookie'] ?? []));

$r = req('GET', "$app/graph", ['sohobotp_app' => $session, 'theme' => 'dark'], [], ['X-WEBAUTH-USER: admin']);
$seen = json_decode($r['body'], true) ?: [];
check('with the session: the site is reached', 200 === $r['status'] && '/graph' === ($seen['path'] ?? ''), $r['status'] . ' ' . $r['body']);
check('the site gets the signed-in user (user_header), never a forged one', 'alice' === ($seen['webauth'] ?? '') && 'alice' === ($seen['sohobotp_user'] ?? ''), $r['body']);
check('the site never sees the gateway cookie, other cookies pass', !str_contains($seen['cookie'] ?? '', 'sohobotp_') && str_contains($seen['cookie'] ?? '', 'theme=dark'), $seen['cookie'] ?? '');

[$payload, $mac] = explode('.', $session);
$claims = json_decode(base64_decode(strtr($payload, '-_', '+/')), true);
$claims['u'] = 'bob';
$forged = rtrim(strtr(base64_encode(json_encode($claims)), '+/', '-_'), '=') . '.' . $mac;
check('changed session cookie refused', 302 === req('GET', "$app/", ['sohobotp_app' => $forged])['status']);
check('session of one site does not open another', 302 === req('GET', "$other/", ['sohobotp_other' => $session])['status']);

$r = login($app, 'alice', '123456', '//evil.example/x');
check('sign-in cannot send the user to another site', '/' === ($r['headers']['location'][0] ?? ''), json_encode($r['headers']['location'] ?? []));
$r = login($other, 'bob', '123456', '/');
check('site allowing every SohobOTP user ("*")', 303 === $r['status'] && '' !== (cookies($r)['sohobotp_other'] ?? ''));

$r = req('GET', "$app/_sohobotp/logout", ['sohobotp_app' => $session]);
check('sign-out clears the session cookie', (bool) preg_grep('/^sohobotp_app=(deleted|);/', $r['headers']['set-cookie'] ?? []), json_encode($r['headers']['set-cookie'] ?? []));

for ($i = 0; $i < 10; $i++) {
    login($other, 'bob', '00000' . $i);
}
$r = login($other, 'bob', '123456');
check('ten wrong codes from one address: that address waits', str_contains($r['body'], 'Too many wrong codes from your address') && '' === (cookies($r)['sohobotp_other'] ?? ''));

echo "\n" . ($total - $failed) . "/$total checks passed\n";
exit($failed > 0 ? 1 : 0);
