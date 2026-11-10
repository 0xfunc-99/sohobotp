<?php
/**
 * Symantec VIP migration through the real appliance (FreeRADIUS, sudo helper, worker):
 * users not on SohobOTP are forwarded by FreeRADIUS to a Symantec VIP Enterprise Gateway,
 * here the stand-in tests/fake-vip-radius.php on 127.0.0.1:18121, started by
 * run-appliance-test.sh. Run as the web server user:
 *   su -s /bin/sh www-data -c "php /usr/local/bin/multiotp/portal/tests/appliance-vip.php"
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
use Portal\VipMigration;

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

function user_with_seed(Users $users, string $name): string
{
    if ($users->exists($name)) {
        $users->delete($name);
    }
    $created = $users->create(['user' => $name, 'display_name' => $name, 'token_serial' => '']);
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
    return $seed;
}

$counter = '/tmp/fake-vip.count';
$forwarded = static fn (): int => (int) @file_get_contents($counter);
check('stand-in Symantec VIP gateway running', is_file($counter));
check('routing program installed root-owned', is_file('/usr/local/sbin/sohobotp-vip-route') && 0 === fileowner('/usr/local/sbin/sohobotp-vip-route') && is_executable('/usr/local/sbin/sohobotp-vip-route'));

$users = new Users();
$migration = new VipMigration();
$migrated = 'vip.migrated';
$seed = user_with_seed($users, $migrated);
$migration->set([$migrated], 'sohobotp', 'appliance-test', 'authenticator enrolled');
$already = 'vip.already';
$alreadySeed = user_with_seed($users, $already);
$step = null;

// ---------------------------------------------------------------- servers, groups, apply
$radius = new Radius();
$group = $radius->saveGroup(null, ['name' => 'Migrating VPN', 'vip_forward' => '1', 'cache_timeout' => '3600']);
$plain = $radius->saveGroup(null, ['name' => 'Not migrating', 'cache_timeout' => '3600']);
[$client, $secret] = $radius->createClient(['name' => 'vpn-migrating', 'address' => '127.0.0.6', 'group_id' => $group['id'], 'nas_type' => 'other', 'require_message_authenticator' => '1']);
[$plainClient, $plainSecret] = $radius->createClient(['name' => 'vpn-plain', 'address' => '127.0.0.7', 'group_id' => $plain['id'], 'nas_type' => 'other', 'require_message_authenticator' => '1']);
$radius->saveVip(['address_1' => '127.0.0.1', 'port_1' => '18121', 'secret_1' => 'Vip-Gateway-Secret-0123', 'response_window' => '5', 'message_authenticator' => 'yes']);
check('forwarding off before the apply (FreeRADIUS has no Symantec realm yet)', false === json_decode((string) @file_get_contents(VipMigration::routeFile()), true)['enabled']);
$job = Jobs::enqueue('radius.apply', [], 'appliance-test');
$done = wait_job($job['id']);
$log = implode("\n", $done['result']['log'] ?? []);
check('apply with Symantec VIP servers accepted by FreeRADIUS', 'succeeded' === $done['status'] && str_contains($log, '1 Symantec VIP server(s)'), $done['status'] . ' ' . $log);
$status = Radius::status();
check('forwarding module and site hooks installed', str_contains($status['output'], 'vip_forwarding=installed'), $status['output']);
check('Symantec VIP active after the apply', $radius->vipActive());
$route = json_decode((string) @file_get_contents(VipMigration::routeFile()), true);
check('routing file: forwarding on for the migrating VPN only', true === ($route['enabled'] ?? null) && isset($route['clients'][Radius::shortname($client)]) && !isset($route['clients'][Radius::shortname($plainClient)]));
check('routing file not readable by other users', 0 === (fileperms(VipMigration::routeFile()) & 0o007));
$proxyFile = '/etc/freeradius/3.0/sohobotp-vip-proxy.conf';
check('Symantec VIP secret file owned by root, not world-readable', is_file($proxyFile) ? (0 === fileowner($proxyFile) && 0 === (fileperms($proxyFile) & 0o007)) : true);

$login = static fn (string $user, string $password, string $from, string $sharedSecret, ?string $state = null): array
    => RadiusClient::authenticate('127.0.0.1', 1812, $sharedSecret, $user, $password, $from, 10, $state);

// ---------------------------------------------------------------- forwarded to Symantec VIP
$before = $forwarded();
$reply = $login('vip.only', 'VipPass-123456', '127.0.0.6', $secret);
check('user not on SohobOTP: accepted by Symantec VIP through SohobOTP', 'accepted' === $reply['result'] && str_contains($reply['reply_message'], 'Symantec VIP accepted') && $forwarded() === $before + 1, json_encode($reply, JSON_INVALID_UTF8_SUBSTITUTE));
$reply = $login('vip.only', 'wrong-password', '127.0.0.6', $secret);
check('user not on SohobOTP, wrong password: rejected by Symantec VIP', 'rejected' === $reply['result'] && $forwarded() === $before + 2, json_encode($reply, JSON_INVALID_UTF8_SUBSTITUTE));
$reply = $login('vip.challenge', 'VipPass-123456', '127.0.0.6', $secret);
check('Symantec VIP challenge passed back to the device', 'challenge' === $reply['result'] && str_contains($reply['reply_message'], 'VIP security code') && null !== $reply['state'], json_encode($reply, JSON_INVALID_UTF8_SUBSTITUTE));
$second = $login('vip.challenge', '246810', '127.0.0.6', $secret, $reply['state']);
check('answer to the Symantec VIP challenge forwarded with its State: accepted', 'accepted' === $second['result'], json_encode($second, JSON_INVALID_UTF8_SUBSTITUTE));

// ---------------------------------------------------------------- users on SohobOTP stay local
$before = $forwarded();
$reply = $login($migrated, next_code($seed, $step), '127.0.0.6', $secret);
check('user on SohobOTP: checked by SohobOTP, Symantec not asked', 'accepted' === $reply['result'] && $forwarded() === $before, json_encode($reply, JSON_INVALID_UTF8_SUBSTITUTE) . ' forwarded ' . ($forwarded() - $before));
$reply = $login($migrated, '000000' === Totp::code($seed, intdiv(time(), 30)) ? '111111' : '000000', '127.0.0.6', $secret);
check('user on SohobOTP, wrong code: rejected, not retried at Symantec', 'rejected' === $reply['result'] && $forwarded() === $before, json_encode($reply, JSON_INVALID_UTF8_SUBSTITUTE));
$reply = $login('CORP\\' . $migrated, '123456', '127.0.0.6', $secret);
check('DOMAIN\\user of a user on SohobOTP is not forwarded', $forwarded() === $before, 'forwarded ' . ($forwarded() - $before));

// ---------------------------------------------------------------- server group without forwarding
$reply = $login('vip.only', 'VipPass-123456', '127.0.0.7', $plainSecret);
check('server group without forwarding: Symantec users refused, Symantec not asked', 'rejected' === $reply['result'] && $forwarded() === $before, json_encode($reply, JSON_INVALID_UTF8_SUBSTITUTE));
$reply = $login($already, next_code($alreadySeed, $step), '127.0.0.7', $plainSecret);
check('a user signs in with SohobOTP on a server group without forwarding', 'accepted' === $reply['result'], json_encode($reply, JSON_INVALID_UTF8_SUBSTITUTE));

// ---------------------------------------------------------------- moved back, seed, diagnostics
$migration->set([$migrated], 'vip', 'appliance-test', 'by an administrator');
$reply = $login($migrated, next_code($seed, $step), '127.0.0.6', $secret);
check('user sent back to Symantec VIP: forwarded at once (no restart)', 'rejected' === $reply['result'] && $forwarded() === $before + 1, json_encode($reply, JSON_INVALID_UTF8_SUBSTITUTE));
$job = Jobs::enqueue('radius.vip_seed', [], 'appliance-test');
$done = wait_job($job['id']);
check('"users already using SohobOTP" job: the user who signed in is moved, the one sent back stays', 'succeeded' === $done['status']
    && $migration->isOnSohobotp($already) && !$migration->isOnSohobotp($migrated), json_encode($done['result'] ?? null));
$before = $forwarded();
$reply = $login($already, next_code($alreadySeed, $step), '127.0.0.6', $secret);
check('after the job, that user signs in with SohobOTP on the migrating VPN', 'accepted' === $reply['result'] && $forwarded() === $before, json_encode($reply, JSON_INVALID_UTF8_SUBSTITUTE));
$log = VipMigration::recentForwarded('vip.');
$results = array_map(static fn (array $l): string => $l['user'] . ':' . $l['result'], $log);
check('diagnostics list the forwarded logins and their results', in_array('vip.only:accept', $results, true) && in_array('vip.only:reject', $results, true) && in_array($migrated . ':reject', $results, true), implode(', ', array_slice($results, 0, 8)));

// ---------------------------------------------------------------- the gateway stops answering
foreach (explode("\n", trim((string) shell_exec('pgrep -f fake-vip-radius.php'))) as $pid) {
    if (ctype_digit($pid)) {
        posix_kill((int) $pid, SIGTERM);
    }
}
usleep(300_000);
$started = microtime(true);
$reply = $login('vip.only', 'VipPass-123456', '127.0.0.6', $secret);
$took = microtime(true) - $started;
check('Symantec VIP unreachable: forwarded users rejected (not let in)', 'accepted' !== $reply['result'], json_encode($reply, JSON_INVALID_UTF8_SUBSTITUTE));
$reply = $login($already, next_code($alreadySeed, $step), '127.0.0.6', $secret);
check('Symantec VIP unreachable: users on SohobOTP still sign in', 'accepted' === $reply['result'], json_encode($reply, JSON_INVALID_UTF8_SUBSTITUTE) . sprintf(' (forwarded try took %.1f s)', $took));

// ---------------------------------------------------------------- clean up
$radius->deleteClient($client['id']);
$radius->deleteClient($plainClient['id']);
$radius->deleteGroup($group['id']);
$radius->deleteGroup($plain['id']);
$radius->saveVip(['address_1' => '', 'secret_1' => '']);
$done = wait_job(Jobs::enqueue('radius.apply', [], 'appliance-test')['id']);
check('Symantec VIP servers removed again', 'succeeded' === $done['status'] && false === json_decode((string) file_get_contents(VipMigration::routeFile()), true)['enabled']);
foreach ([$migrated, $already] as $name) {
    $users->delete($name);
    $migration->forget($name);
}

echo $failures > 0 ? "$failures Symantec VIP check(s) failed.\n" : "$count/$count Symantec VIP checks passed.\n";
exit($failures > 0 ? 1 : 0);
