<?php
/**
 * One side of the two-appliance test (portal/tests/run-ha-test.sh), run as www-data:
 *   php ha-node.php primary <primary ip> <secondary ip>   prepare A, write /tmp/ha-* for the test
 *   php ha-node.php join                                  B joins with /tmp/ha-code
 *   php ha-node.php add-user <name>                       on A: a user created after the pairing
 *   php ha-node.php check-replica <name>                  on B: is <name> in the local replica?
 *   php ha-node.php login <expect> [reuse]                on B: RADIUS login of ha.user (accepted|rejected)
 *   php ha-node.php promote                               on B: primary gone, promote
 */
declare(strict_types=1);

if ('cli' !== PHP_SAPI) {
    exit;
}
define('PORTAL_ROOT', dirname(__DIR__));
require PORTAL_ROOT . '/src/bootstrap.php';
error_reporting(E_ALL & ~E_DEPRECATED);

use Portal\Database;
use Portal\Ha;
use Portal\MultiotpService;
use Portal\Radius;
use Portal\RadiusClient;
use Portal\Totp;
use Portal\Users;

$failures = 0;
function check(string $name, bool $ok, string $detail = ''): void
{
    global $failures;
    $failures += $ok ? 0 : 1;
    echo ($ok ? 'ok   ' : 'FAIL ') . $name . ($ok || '' === $detail ? '' : "  [$detail]") . "\n";
}
function seed_of(string $otpauth): string
{
    parse_str((string) parse_url($otpauth, PHP_URL_QUERY), $q);
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

switch ($argv[1] ?? '') {
    case 'primary':
        [$primary, $secondary] = [$argv[2], $argv[3]];
        $connection = Database::prepareLocal();
        $result = Database::migrate($connection, static fn () => null);
        check('primary: data moved to MariaDB on the appliance', $result['ok'], (string) $result['error']);
        MultiotpService::reset();
        $users = new Users();
        $created = $users->create(['user' => 'ha.user', 'display_name' => 'HA tester', 'token_serial' => '']);
        file_put_contents('/tmp/ha-seed', bin2hex(seed_of((string) $created['otpauth'])));
        $radius = new Radius();
        $group = $radius->saveGroup(null, ['name' => 'HA VPN', 'cache_timeout' => '3600']);
        [, $secret] = $radius->createClient(['name' => 'vpn-ha', 'address' => '127.0.0.20', 'group_id' => $group['id'], 'nas_type' => 'other', 'require_message_authenticator' => '1']);
        file_put_contents('/tmp/ha-secret', $secret);
        $apply = $radius->apply();
        check('primary: RADIUS client applied', $apply['ok'], $apply['output']);
        $code = (new Ha())->pair($primary, $secondary, "https://$primary");
        file_put_contents('/tmp/ha-code', $code);
        check('primary: pairing code created', str_starts_with($code, 'SOHOBOTP-HA-'));
        $status = Database::helper('ha-status');
        check('primary: MariaDB configured as primary', str_contains($status['output'], 'ha_config=primary'), $status['output']);
        break;

    case 'join':
        $ha = new Ha();
        try {
            $ha->join((string) file_get_contents('/tmp/ha-code'));
            check('secondary: joined the primary', true);
        } catch (Throwable $e) {
            check('secondary: joined the primary', false, $e->getMessage());
            break;
        }
        $state = $ha->state();
        check('secondary: role secondary, RADIUS configuration copied', 'secondary' === $state['role'] && null !== $state['last_sync_at'] && '' === $state['last_sync_error'], json_encode($state));
        $status = Database::helper('ha-status');
        check('secondary: replication running with TLS', str_contains($status['output'], 'Slave_IO_Running=Yes') && str_contains($status['output'], 'Slave_SQL_Running=Yes') && str_contains($status['output'], 'read_only=1'), $status['output']);
        $clients = (string) @file_get_contents('/etc/freeradius/3.0/multiotp-portal-clients.conf');
        check('secondary: FreeRADIUS has the primary\'s RADIUS clients', str_contains($clients, 'ipaddr = 127.0.0.20/32'));
        $current = Database::current();
        check('secondary: engine uses the primary\'s database', 'mysql' === $current['backend'] && str_starts_with($current['server'], '172.'), json_encode($current));
        check('secondary: primary database reachable over pinned TLS', $ha->primaryReachable());
        break;

    case 'add-user':
        (new Users())->create(['user' => $argv[2], 'display_name' => 'After pairing', 'token_serial' => '']);
        check("primary: user {$argv[2]} created", true);
        break;

    case 'check-replica':
        $data = json_decode((string) file_get_contents(Portal\Config::dataDir() . '/ha.json'), true);
        $db = new mysqli('127.0.0.1', 'sohobotp', Portal\Crypto::decrypt((string) $data['local_password']), 'sohobotp', 3306);
        $found = 0;
        for ($i = 0; $i < 20 && 0 === $found; $i++) {
            $found = (int) ($db->query("SELECT COUNT(*) FROM multiotp_users WHERE user = '" . $db->real_escape_string($argv[2]) . "'")->fetch_row()[0] ?? 0);
            $found || sleep(1);
        }
        check("secondary: {$argv[2]} replicated into the local copy", 1 === $found);
        break;

    case 'login':
        $seed = hex2bin((string) file_get_contents('/tmp/ha-seed'));
        $last = @file_get_contents('/tmp/ha-last-step');
        $step = intdiv(time(), 30);
        if ('reuse' === ($argv[3] ?? '')) {
            $step = (int) $last;
        } else {
            while (false !== $last && $step <= (int) $last) {
                sleep(1);
                $step = intdiv(time(), 30);
            }
            file_put_contents('/tmp/ha-last-step', (string) $step);
        }
        $reply = RadiusClient::authenticate('127.0.0.1', 1812, trim((string) file_get_contents('/tmp/ha-secret')), 'ha.user', Totp::code($seed, $step), '127.0.0.20', 10);
        check("secondary: RADIUS login " . ($argv[3] ?? 'new code') . " -> {$argv[2]}", $argv[2] === $reply['result'] || ('rejected' === $argv[2] && 'accepted' !== $reply['result']), json_encode($reply, JSON_INVALID_UTF8_SUBSTITUTE));
        break;

    case 'promote':
        $ha = new Ha();
        check('secondary: primary database seen as unreachable', !$ha->primaryReachable());
        $ha->promote('ha-test');
        $status = Database::helper('ha-status');
        check('secondary promoted: replication stopped, writable', 'promoted' === $ha->state()['role'] && str_contains($status['output'], 'read_only=0') && !str_contains($status['output'], 'Slave_IO_Running=Yes'), $status['output']);
        check('secondary promoted: engine on its own database', Database::current()['local']);
        break;

    default:
        fwrite(STDERR, "usage: see the header\n");
        exit(2);
}
exit($failures > 0 ? 1 : 0);
