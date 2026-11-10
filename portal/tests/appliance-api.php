<?php
/**
 * REST API through the real appliance web server (nginx + PHP-FPM, HTTPS): the API location
 * comes before the rules that refuse legacy paths such as /users, PATH_INFO and the
 * Authorization header reach PHP. Run as the web server user:
 *   su -s /bin/sh www-data -c "php /usr/local/bin/multiotp/portal/tests/appliance-api.php"
 */
declare(strict_types=1);

if ('cli' !== PHP_SAPI) {
    exit;
}
define('PORTAL_ROOT', dirname(__DIR__));
require PORTAL_ROOT . '/src/bootstrap.php';
error_reporting(E_ALL & ~E_DEPRECATED);

$failures = 0;
$count = 0;
function check(string $name, bool $ok, string $detail = ''): void
{
    global $failures, $count;
    $count++;
    $failures += $ok ? 0 : 1;
    echo ($ok ? 'ok   ' : 'FAIL ') . $name . ($ok || '' === $detail ? '' : "  [$detail]") . "\n";
}
function call(string $method, string $path, string $key = '', ?string $body = null): array
{
    $headers = "Content-Type: application/json\r\n" . ('' !== $key ? "Authorization: Bearer $key\r\n" : '');
    $ctx = stream_context_create(['http' => ['method' => $method, 'header' => $headers, 'content' => (string) $body, 'ignore_errors' => true],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]]);
    $raw = @file_get_contents('https://localhost' . $path, false, $ctx);
    preg_match('{HTTP/\S+ (\d+)}', $http_response_header[0] ?? '', $m);
    return [(int) ($m[1] ?? 0), json_decode((string) $raw, true) ?? [], (string) $raw];
}

[$code, $json] = call('GET', '/portal/api.php/v1/health');
check('API health through nginx', 200 === $code && 'ok' === ($json['status'] ?? ''), (string) $code);
[$code] = call('GET', '/portal/api.php/v1/users');
check('API /v1/users reaches PHP (401 without a key, not refused by the legacy /users rule)', 401 === $code, (string) $code);
[$record, $key] = (new Portal\ApiKeys())->create(['name' => 'appliance-test', 'scopes' => ['users.read']], 'appliance-test');
[$code, $json] = call('GET', '/portal/api.php/v1/users?per_page=5', $key);
check('API key in the Authorization header accepted through nginx and PHP-FPM', 200 === $code && isset($json['total']), (string) $code);
[$code, $json] = call('GET', '/portal/api.php/v1/me', $key);
check('API PATH_INFO routing through nginx', 200 === $code && 'appliance-test' === ($json['name'] ?? ''), (string) $code);
[$code] = call('GET', '/portal/api.php/../src/App.php');
check('no source reachable through the API location', 404 === $code || 400 === $code, (string) $code);
(new Portal\ApiKeys())->revoke($record['id']);
[$code] = call('GET', '/portal/api.php/v1/me', $key);
check('revoked key refused', 401 === $code, (string) $code);

echo $failures > 0 ? "$failures API check(s) failed.\n" : "$count/$count appliance API checks passed.\n";
exit($failures > 0 ? 1 : 0);
