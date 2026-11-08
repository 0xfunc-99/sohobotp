<?php
/**
 * Checks run INSIDE the production appliance container (real nginx, PHP-FPM, FreeRADIUS,
 * sudo helper, background worker started by newvm.sh). Run as the web server user:
 *   su -s /bin/sh www-data -c "php /usr/local/bin/multiotp/portal/tests/appliance-radius.php"
 * See portal/tests/run-appliance-test.sh.
 */
declare(strict_types=1);

if ('cli' !== PHP_SAPI) {
    exit;
}
define('PORTAL_ROOT', dirname(__DIR__));
require PORTAL_ROOT . '/src/bootstrap.php';
error_reporting(E_ALL & ~E_DEPRECATED);

use Portal\Jobs;
use Portal\Radius;
use Portal\RadiusClient;
use Portal\Totp;
use Portal\Users;

$failures = 0;
$count = 0;
function check(string $name, bool $ok, string $detail = ''): void
{
    global $failures, $count;
    $count++;
    if (!$ok) {
        $failures++;
    }
    echo ($ok ? 'ok   ' : 'FAIL ') . $name . ($ok || '' === $detail ? '' : "  [$detail]") . "\n";
}

function wait_job(string $id, int $timeout = 120): array
{
    $until = time() + $timeout;
    do {
        $job = Jobs::find($id);
        if (null !== $job && !in_array($job['status'], Jobs::ACTIVE, true)) {
            return $job;
        }
        sleep(1);
    } while (time() < $until);
    return Jobs::find($id) ?? ['status' => 'missing'];
}

function next_code(string $secret, ?int &$lastStep): string
{
    while (null !== $lastStep && intdiv(time(), 30) <= $lastStep) {
        usleep(250_000);
    }
    $lastStep = intdiv(time(), 30);
    return Totp::code($secret, $lastStep);
}

check('running as the web server user', 'www-data' === (posix_getpwuid(posix_geteuid())['name'] ?? ''));
check('engine uses /etc/multiotp', Portal\Config::hasEtcDir());

// ---------------------------------------------------------------- helper and FreeRADIUS before any change
$status = Radius::status();
check('sudo helper available to www-data', $status['available'], $status['output']);
check('FreeRADIUS running at start', true === $status['running'], $status['output']);
check('install-time catch-all client detected', true === $status['default_client'], $status['output']);

// ---------------------------------------------------------------- user with a known seed
$users = new Users();
$name = 'radius.tester';
if ($users->exists($name)) {
    $users->delete($name);
}
$created = $users->create(['user' => $name, 'display_name' => 'RADIUS tester', 'token_serial' => '']);
parse_str((string) parse_url((string) $created['otpauth'], PHP_URL_QUERY), $query);
$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
$bits = '';
foreach (str_split((string) ($query['secret'] ?? '')) as $char) {
    $bits .= str_pad(decbin((int) strpos($alphabet, $char)), 5, '0', STR_PAD_LEFT);
}
$seed = '';
foreach (str_split($bits, 8) as $byte) {
    if (8 === strlen($byte)) {
        $seed .= chr(bindec($byte));
    }
}
check('test user created with a software token', 20 === strlen($seed));
$step = null;

// ---------------------------------------------------------------- groups, clients, apply through the worker
$radius = new Radius();
foreach ($radius->clients() as $client) {
    $radius->deleteClient($client['id']);
}
foreach ($radius->groups() as $group) {
    $radius->deleteGroup($group['id']);
}
$vpn = $radius->saveGroup(null, ['name' => 'VPN', 'cache_timeout' => '3600']);
$wifi = $radius->saveGroup(null, ['name' => 'Wi-Fi', 'challenge_response' => '1', 'cache_timeout' => '3600']);
[$vpnClient, $vpnSecret] = $radius->createClient(['name' => 'vpn-test', 'address' => '127.0.0.3', 'group_id' => $vpn['id'], 'nas_type' => 'other', 'require_message_authenticator' => '1']);
[$wifiClient, $wifiSecret] = $radius->createClient(['name' => 'wifi-test', 'address' => '127.0.0.4', 'group_id' => $wifi['id'], 'nas_type' => 'other', 'require_message_authenticator' => '1']);

$job = Jobs::enqueue('radius.apply', [], 'appliance-test');
$done = wait_job($job['id']);
check('apply job run by the background worker', 'succeeded' === $done['status'], ($done['status'] ?? '') . ' ' . json_encode($done['error'] ?? '') . ' ' . implode(' | ', $done['result']['log'] ?? []));
check('apply output shows the config check and restart', str_contains(implode("\n", $done['result']['log'] ?? []), 'freeradius=running'));
$state = $radius->state();
check('no pending changes after apply', false === $state['pending']);
$status = Radius::status();
check('portal clients included in clients.conf', str_contains($status['output'], 'portal_clients=included'), $status['output']);
check('FreeRADIUS running after apply', true === $status['running']);
$perms = fileperms('/etc/freeradius/3.0/multiotp-portal-clients.conf') & 0777;
check('generated file owned by root, not world-readable', 0 === fileowner('/etc/freeradius/3.0/multiotp-portal-clients.conf') && 0 === ($perms & 0007), sprintf('%o', $perms));

// ---------------------------------------------------------------- real RADIUS logins
$test = $radius->testLogin($name, next_code($seed, $step));
check('diagnostics test login: right code accepted', 'accepted' === $test['result'], json_encode($test));
$test = $radius->testLogin($name, '000000' === Totp::code($seed, intdiv(time(), 30)) ? '111111' : '000000');
check('diagnostics test login: wrong code rejected', 'rejected' === $test['result'], json_encode($test));
$reply = RadiusClient::authenticate('127.0.0.1', 1812, $vpnSecret, $name, next_code($seed, $step), '127.0.0.3');
check('VPN server (127.0.0.3, its own secret) accepted', 'accepted' === $reply['result'], json_encode($reply));
$reply = RadiusClient::authenticate('127.0.0.1', 1812, 'wrong-shared-secret-123', $name, next_code($seed, $step), '127.0.0.3');
check('wrong shared secret gets no valid answer', 'accepted' !== $reply['result'], json_encode($reply));
$reply = RadiusClient::authenticate('127.0.0.1', 1812, $vpnSecret, $name, next_code($seed, $step), '127.0.0.9');
check('unknown source address ignored by FreeRADIUS', 'accepted' !== $reply['result'], json_encode($reply));

// ---------------------------------------------------------------- secret rotation needs an apply
$oldSecret = $vpnSecret;
$vpnSecret = $radius->rotateSecret($vpnClient['id']);
$done = wait_job(Jobs::enqueue('radius.apply', [], 'appliance-test')['id']);
check('apply after secret rotation', 'succeeded' === $done['status']);
$reply = RadiusClient::authenticate('127.0.0.1', 1812, $oldSecret, $name, next_code($seed, $step), '127.0.0.3');
check('old secret no longer works', 'accepted' !== $reply['result'], json_encode($reply));
$reply = RadiusClient::authenticate('127.0.0.1', 1812, $vpnSecret, $name, next_code($seed, $step), '127.0.0.3');
check('new secret works', 'accepted' === $reply['result'], json_encode($reply));

// ---------------------------------------------------------------- catch-all client
$reply = RadiusClient::authenticate('127.0.0.1', 1812, 'myfirstpass', $name, next_code($seed, $step), '127.0.0.8');
check('before: catch-all client answers with "myfirstpass"', 'accepted' === $reply['result'], json_encode($reply));
$result = Radius::disableDefaultClient();
check('catch-all client disabled through the helper', $result['ok'], $result['output']);
$status = Radius::status();
check('helper reports catch-all inactive, FreeRADIUS running', false === $status['default_client'] && true === $status['running'], $status['output']);
$reply = RadiusClient::authenticate('127.0.0.1', 1812, 'myfirstpass', $name, next_code($seed, $step), '127.0.0.8', 3);
check('after: "myfirstpass" from any address no longer works', 'accepted' !== $reply['result'], json_encode($reply));
$reply = RadiusClient::authenticate('127.0.0.1', 1812, $vpnSecret, $name, next_code($seed, $step), '127.0.0.3');
check('portal clients still work', 'accepted' === $reply['result'], json_encode($reply));

// ---------------------------------------------------------------- challenge-response (Wi-Fi group): PIN first, then the code
$pin = $users->setLoginFormat($name, 'pin');
$reply = RadiusClient::authenticate('127.0.0.1', 1812, $wifiSecret, $name, (string) $pin, '127.0.0.4');
check('Wi-Fi group (challenge-response): PIN answered with a challenge', 'challenge' === $reply['result'], json_encode($reply));
if ('challenge' === $reply['result']) {
    $second = RadiusClient::authenticate('127.0.0.1', 1812, $wifiSecret, $name, next_code($seed, $step), '127.0.0.4', 10, $reply['state']);
    check('challenge answered with the code: accepted', 'accepted' === $second['result'], json_encode($second));
}
$reply = RadiusClient::authenticate('127.0.0.1', 1812, $vpnSecret, $name, $pin . next_code($seed, $step), '127.0.0.3');
check('VPN group (no challenge): PIN + code in one step accepted', 'accepted' === $reply['result'], json_encode($reply));

// ---------------------------------------------------------------- recent logins
$logins = Radius::recentLogins($name);
check('recent logins read from the multiOTP log', [] !== $logins, 'log enabled?');

echo "\n" . ($count - $failures) . "/$count appliance checks passed\n";
exit($failures > 0 ? 1 : 0);
