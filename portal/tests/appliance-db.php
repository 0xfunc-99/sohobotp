<?php
/**
 * Stage 6: users, tokens, RADIUS devices and groups moved from files to MariaDB on the
 * appliance (root helper sohobotp-db, worker job database.migrate), RADIUS through real
 * FreeRADIUS with the data in MariaDB, the SQL user search, and a load test with 100,000
 * users. Runs LAST in run-appliance-test.sh (the appliance stays on MariaDB). As www-data:
 *   su -s /bin/sh www-data -c "php /usr/local/bin/multiotp/portal/tests/appliance-db.php"
 */
declare(strict_types=1);

if ('cli' !== PHP_SAPI) {
    exit;
}
define('PORTAL_ROOT', dirname(__DIR__));
require PORTAL_ROOT . '/src/bootstrap.php';
error_reporting(E_ALL & ~E_DEPRECATED);

use Portal\Database;
use Portal\Jobs;
use Portal\MultiotpService;
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
    $failures += $ok ? 0 : 1;
    echo ($ok ? 'ok   ' : 'FAIL ') . $name . ($ok || '' === $detail ? '' : "  [$detail]") . "\n";
}
function wait_job(string $id, int $timeout = 600): array
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
function seed_of(array $created): string
{
    parse_str((string) parse_url((string) $created['otpauth'], PHP_URL_QUERY), $q);
    $bits = '';
    foreach (str_split((string) ($q['secret'] ?? '')) as $ch) {
        $bits .= str_pad(decbin((int) strpos('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', $ch)), 5, '0', STR_PAD_LEFT);
    }
    $seed = '';
    foreach (str_split($bits, 8) as $b) {
        if (8 === strlen($b)) {
            $seed .= chr(bindec($b));
        }
    }
    return $seed;
}
function next_code(string $seed, ?int &$last): string
{
    while (null !== $last && intdiv(time(), 30) <= $last) {
        usleep(250_000);
    }
    $last = intdiv(time(), 30);
    return Totp::code($seed, $last);
}
$timed = static function (callable $fn): array {
    $t = microtime(true);
    $r = $fn();
    return [$r, microtime(true) - $t];
};

// ---------------------------------------------------------------- before: files
$users = new Users();
if ($users->exists('db.tester')) {
    $users->delete('db.tester');
}
$seed = seed_of($users->create(['user' => 'db.tester', 'display_name' => 'Database tester', 'group' => 'VPN-Users', 'token_serial' => '']));
$step = null;
$radius = new Radius();
$group = $radius->saveGroup(null, ['name' => 'DB test', 'cache_timeout' => '3600']);
[$client, $secret] = $radius->createClient(['name' => 'vpn-db', 'address' => '127.0.0.15', 'group_id' => $group['id'], 'nas_type' => 'other', 'require_message_authenticator' => '1']);
$done = wait_job(Jobs::enqueue('radius.apply', [], 'appliance-test')['id'], 120);
check('RADIUS client applied (files)', 'succeeded' === $done['status']);
check('starts on files', 'files' === Database::current()['backend']);
$before = Database::counts();
check('data on files before the move', $before['users'] >= 1 && $before['devices'] >= 1, json_encode($before));
$status = Database::helper('status');
check('database helper available through sudo, MariaDB not started yet', $status['available'] && str_contains($status['output'], 'local=disabled'), $status['output']);

// ---------------------------------------------------------------- move to MariaDB on the appliance
$connection = Database::prepareLocal();
$status = Database::helper('status');
check('MariaDB on the appliance prepared and running', str_contains($status['output'], 'mariadb=running') && str_contains($status['output'], 'local=enabled'), $status['output']);
check('connection to the new database works', Database::test($connection)['ok'], Database::test($connection)['message']);
$job = Jobs::enqueue('database.migrate', ['connection' => Portal\Crypto::encrypt(json_encode($connection))], 'appliance-test');
$done = wait_job($job['id']);
check('migration job succeeded', 'succeeded' === $done['status'], json_encode($done['error'] ?? null) . ' ' . json_encode($done['result'] ?? null));
MultiotpService::reset();
$current = Database::current();
check('engine now on MariaDB on this appliance', 'mysql' === $current['backend'] && $current['local'], json_encode($current));
$after = Database::counts();
check('every user, token, RADIUS device and group is in the database', $after['users'] >= $before['users'] && $after['tokens'] >= $before['tokens'] && $after['devices'] >= $before['devices'] && $after['groups'] >= $before['groups'], json_encode(['before' => $before, 'after' => $after]));
check('the files are kept as a backup', is_dir('/etc/multiotp/users') && [] !== glob('/etc/multiotp/users/*.db'));
check('the password is not in the job record', !str_contains((string) json_encode(Jobs::find($job['id'])), $connection['password']));

// ---------------------------------------------------------------- RADIUS with the data in MariaDB
$code = next_code($seed, $step);
$reply = RadiusClient::authenticate('127.0.0.1', 1812, $secret, 'db.tester', $code, '127.0.0.15');
check('RADIUS login with the right code (data in MariaDB)', 'accepted' === $reply['result'], json_encode($reply, JSON_INVALID_UTF8_SUBSTITUTE));
$reply = RadiusClient::authenticate('127.0.0.1', 1812, $secret, 'db.tester', $code, '127.0.0.15');
check('the same code again is refused (replay protection stored in MariaDB)', 'rejected' === $reply['result'], json_encode($reply, JSON_INVALID_UTF8_SUBSTITUTE));
$users = new Users();
$found = $users->search('db.test', '', 1, 50);
check('user search in SQL', 1 === $found['total'] && 'db.tester' === ($found['users'][0]['user'] ?? ''), json_encode($found));
check('user details from the database', 'VPN-Users' === ($users->get('db.tester')['group'] ?? ''));

// ---------------------------------------------------------------- load test: 100,000 users
MultiotpService::reset();
$c = MultiotpService::get()->_config_data;
$db = new mysqli('127.0.0.1', $c['sql_username'], $c['sql_password'], $c['sql_database'], 3306);
$table = $c['sql_users_table'];
[$ok, $took] = $timed(static fn () => $db->query("INSERT INTO `$table` (`user`, `display_name`, `email`, `group`, `algorithm`, `desactivated`, `locked`)
    SELECT CONCAT('load', LPAD(seq, 6, '0')), CONCAT('Load user ', seq), CONCAT('load', seq, '@example.test'), IF(seq % 2, 'VPN-Users', 'Staff'), 'totp', 0, 0
    FROM seq_1_to_100000"));
check(sprintf('100,000 users inserted (%.1f s)', $took), (bool) $ok, $db->error);
[$page, $took] = $timed(static fn () => $users->search('', '', 1, 50));
check(sprintf('users page with 100,000 users: %.2f s (limit 2 s)', $took), $page['total'] >= 100000 && 50 === count($page['users']) && $took < 2.0, (string) $page['total']);
[$hit, $took] = $timed(static fn () => $users->search('load099999', '', 1, 50));
check(sprintf('search among 100,000 users: %.2f s (limit 2 s)', $took), 1 === $hit['total'] && $took < 2.0);
[$page, $took] = $timed(static fn () => $users->search('', 'enabled', 2000, 50));
check(sprintf('page 2000 of the enabled users: %.2f s (limit 2 s)', $took), 50 === count($page['users']) && $took < 2.0);
[$one, $took] = $timed(static fn () => $users->get('load054321'));
check(sprintf('one user read: %.2f s (limit 1 s)', $took), 'Load user 54321' === ($one['display_name'] ?? '') && $took < 1.0);
$times = [];
for ($i = 0; $i < 3; $i++) {
    $code = next_code($seed, $step);
    [$reply, $times[]] = $timed(static fn () => RadiusClient::authenticate('127.0.0.1', 1812, $secret, 'db.tester', $code, '127.0.0.15'));
    if ('accepted' !== $reply['result']) {
        break;
    }
}
check(sprintf('RADIUS logins with 100,000 users: %s s (limit 2 s each)', implode(', ', array_map(static fn (float $t): string => sprintf('%.2f', $t), $times))),
    'accepted' === $reply['result'] && max($times) < 2.0, json_encode($reply, JSON_INVALID_UTF8_SUBSTITUTE));
$db->query("DELETE FROM `$table` WHERE `user` LIKE 'load%'");
$db->close();

// ---------------------------------------------------------------- clean up (the appliance stays on MariaDB)
$radius->deleteClient($client['id']);
$radius->deleteGroup($group['id']);
$users->delete('db.tester');
wait_job(Jobs::enqueue('radius.apply', [], 'appliance-test')['id'], 120);

echo $failures > 0 ? "$failures database check(s) failed.\n" : "$count/$count database checks passed.\n";
exit($failures > 0 ? 1 : 0);
