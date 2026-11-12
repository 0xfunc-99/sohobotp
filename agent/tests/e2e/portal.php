<?php
/**
 * Portal side of the Linux agent end-to-end test. Runs INSIDE the appliance as www-data:
 *   php portal.php setup                 groups, token, users; prints JSON
 *   php portal.php token                 a new single-use enrolment token
 *   php portal.php policy ssh-only|off   change the endpoint group
 *   php portal.php endpoint              the enrolled endpoint as JSON
 *   php portal.php radius-applied        yes when FreeRADIUS has the current clients
 */
declare(strict_types=1);
if ('cli' !== PHP_SAPI) { exit; }
define('PORTAL_ROOT', '/usr/local/bin/multiotp/portal');
require PORTAL_ROOT . '/src/bootstrap.php';
error_reporting(E_ALL & ~E_DEPRECATED);

use Portal\Endpoints;
use Portal\Radius;
use Portal\Users;

const GROUP = 'Linux e2e servers';

function form(array $over = []): array
{
    $radiusGroup = '';
    foreach ((new Radius())->groups() as $g) {
        $radiusGroup = 'Linux e2e' === $g['name'] ? $g['id'] : $radiusGroup;
    }
    return $over + [
        'name' => GROUP, 'checkin_interval' => '30', 'linux_enabled' => '1', 'linux_radius_group_id' => $radiusGroup,
        'linux_radius_servers' => '', 'linux_timeout' => '5', 'linux_services' => ['sshd', 'sudo'],
        'linux_excluded_users' => 'deploy', 'linux_excluded_groups' => 'mfa-breakglass', 'linux_ssh_keys_need_code' => '',
        'win_cpus_logon' => '0e', 'win_cpus_unlock' => '0e', 'win_cpus_credui' => '0e', 'win_excluded_account' => '',
        'win_cache_days' => '7', 'win_timeout_unlock' => '0', 'win_server_timeout' => '5',
    ];
}

function group(): array
{
    foreach ((new Endpoints())->groups() as $g) {
        if (GROUP === $g['name']) {
            return $g;
        }
    }
    throw new RuntimeException('group missing');
}

switch ($argv[1] ?? '') {
    case 'setup':
        (new Radius())->saveGroup(null, ['name' => 'Linux e2e', 'cache_timeout' => '3600']);
        $endpoints = new Endpoints();
        $group = $endpoints->saveGroup(null, form());
        [, $token] = $endpoints->createToken($group['id'], 'agent e2e', 1, 1, 'agent-e2e');
        $users = new Users();
        $seeds = [];
        foreach (['alice', 'bob', 'carol'] as $name) {
            if ($users->exists($name)) {
                $users->delete($name);
            }
            $created = $users->create(['user' => $name, 'display_name' => ucfirst($name), 'token_serial' => '']);
            parse_str((string) parse_url((string) $created['otpauth'], PHP_URL_QUERY), $q);
            $bits = '';
            foreach (str_split((string) $q['secret']) as $c) {
                $bits .= str_pad(decbin((int) strpos('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', $c)), 5, '0', STR_PAD_LEFT);
            }
            $seed = '';
            foreach (str_split($bits, 8) as $byte) {
                $seed .= 8 === strlen($byte) ? chr(bindec($byte)) : '';
            }
            $seeds[$name] = bin2hex($seed);
        }
        echo json_encode(['token' => $token, 'pin' => $endpoints->pin(), 'seeds' => $seeds]), "\n";
        break;
    case 'token':
        [, $token] = (new Endpoints())->createToken(group()['id'], 'agent e2e', 1, 1, 'agent-e2e');
        echo $token, "\n";
        break;
    case 'download':
        // what the portal's "Download agent" page sends: the agent program (argument 2) followed
        // by the settings block with a new token, the pin and the CA certificate (argument 3)
        $endpoints = new Endpoints();
        [, $plain] = $endpoints->createToken(group()['id'], 'agent e2e download', 1, 1, 'agent-e2e');
        readfile($argv[2]);
        echo Portal\AgentBundle::trailer(Portal\AgentBundle::validatePortal('https://portal.test'), $plain, $endpoints->pin(),
            Portal\AgentBundle::validateCa((string) file_get_contents($argv[3])));
        break;
    case 'radius-applied':
        // the last FreeRADIUS apply finished successfully and nothing is pending
        $job = Portal\Jobs::latest('radius.apply');
        $pending = (new Radius())->state()['pending'];
        echo (null !== $job && 'succeeded' === $job['status'] && !$pending) ? "yes\n" : "no\n";
        break;
    case 'delete-orphans':
        // endpoints that never checked in (e.g. the agent refused the portal's pin)
        $endpoints = new Endpoints();
        foreach ($endpoints->endpoints() as $e) {
            if (null === $e['last_seen']) {
                $endpoints->deleteEndpoint($e['id']);
                echo "deleted {$e['id']}\n";
            }
        }
        break;
    case 'policy':
        $presets = [
            'ssh-only' => ['linux_services' => ['sshd']],
            'update-0.3.0' => ['linux_services' => ['sshd'], 'agent_version' => '0.3.0'],
            'update-0.2.0' => ['linux_services' => ['sshd'], 'agent_version' => '0.2.0'],
            'update-0.4.0' => ['linux_services' => ['sshd'], 'agent_version' => '0.4.0'],
            'update-0.5.0' => ['linux_services' => ['sshd'], 'agent_version' => '0.5.0'],
            'off' => ['linux_enabled' => ''],
        ];
        $over = $presets[$argv[2] ?? ''] ?? throw new InvalidArgumentException('policy presets: ' . implode(', ', array_keys($presets)));
        $g = group();
        (new Endpoints())->saveGroup($g['id'], form($over));
        echo "policy saved\n";
        break;
    case 'endpoint':
        $g = group();
        foreach ((new Endpoints())->endpoints() as $e) {
            if ($e['group_id'] === $g['id'] && null !== $e['last_seen']) {
                echo json_encode($e), "\n";
                exit(0);
            }
        }
        echo "{}\n";
        break;
    default:
        fwrite(STDERR, "usage: setup | policy JSON | endpoint\n");
        exit(2);
}
