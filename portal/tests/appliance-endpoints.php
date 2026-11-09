<?php
/**
 * Stage 4 checks run INSIDE the production appliance container, as the web server user, after
 * appliance-radius.php: a simulated Linux agent enrols and checks in through nginx (HTTPS),
 * becomes a FreeRADIUS client, and the RADIUS secret it receives works against real FreeRADIUS.
 *   su -s /bin/sh www-data -c "php /usr/local/bin/multiotp/portal/tests/appliance-endpoints.php"
 */
declare(strict_types=1);

if ('cli' !== PHP_SAPI) {
    exit;
}
define('PORTAL_ROOT', dirname(__DIR__));
require PORTAL_ROOT . '/src/bootstrap.php';
require __DIR__ . '/AgentSim.php';
error_reporting(E_ALL & ~E_DEPRECATED);

use Portal\Endpoints;
use Portal\Jobs;
use Portal\Radius;
use Portal\RadiusClient;
use Portal\Totp;
use Portal\Users;

const SOURCE = '127.0.0.6'; // the simulated machine's address

$failures = 0;
$count = 0;
function check(string $name, bool $ok, string $detail = ''): void
{
    global $failures, $count;
    $count++;
    $failures += $ok ? 0 : 1;
    echo ($ok ? 'ok   ' : 'FAIL ') . $name . ($ok || '' === $detail ? '' : "  [$detail]") . "\n";
}

/** POST to the agent API through nginx, from SOURCE. @return array{0: int, 1: array} */
function agent_post(string $action, array $request, ?AgentSim $signer = null): array
{
    $body = json_encode($request);
    $uri = '/portal/agent.php?a=' . $action;
    $headers = ['Content-Type: application/json'];
    foreach (null === $signer ? [] : $signer->headers('POST', $uri, $body) as $name => $value) {
        $headers[] = "$name: $value";
    }
    $context = stream_context_create([
        'http' => ['method' => 'POST', 'header' => implode("\r\n", $headers), 'content' => $body, 'ignore_errors' => true],
        // the appliance certificate is self-signed; the real agent pins a CA file instead
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
        'socket' => ['bindto' => SOURCE . ':0'],
    ]);
    $reply = @file_get_contents('https://localhost' . $uri, false, $context);
    preg_match('{HTTP/\S+ (\d+)}', $http_response_header[0] ?? '', $m);
    return [(int) ($m[1] ?? 0), json_decode((string) $reply, true) ?? []];
}

function wait_latest_apply(int $after, int $timeout = 120): string
{
    $until = time() + $timeout;
    do {
        $job = Jobs::latest('radius.apply');
        if (null !== $job && $job['created_at'] >= $after && !in_array($job['status'], Jobs::ACTIVE, true)) {
            return $job['status'];
        }
        sleep(1);
    } while (time() < $until);
    return 'timeout';
}

function next_code(string $secret, ?int &$lastStep): string
{
    while (null !== $lastStep && intdiv(time(), 30) <= $lastStep) {
        usleep(250_000);
    }
    $lastStep = intdiv(time(), 30);
    return Totp::code($secret, $lastStep);
}

// ---------------------------------------------------------------- user with a known seed
$users = new Users();
$name = 'endpoint.tester';
if ($users->exists($name)) {
    $users->delete($name);
}
$created = $users->create(['user' => $name, 'display_name' => 'Endpoint tester', 'token_serial' => '']);
parse_str((string) parse_url((string) $created['otpauth'], PHP_URL_QUERY), $query);
$bits = '';
foreach (str_split((string) ($query['secret'] ?? '')) as $char) {
    $bits .= str_pad(decbin((int) strpos('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', $char)), 5, '0', STR_PAD_LEFT);
}
$seed = '';
foreach (str_split($bits, 8) as $byte) {
    $seed .= 8 === strlen($byte) ? chr(bindec($byte)) : '';
}
$step = null;

// ---------------------------------------------------------------- groups and token
$radius = new Radius();
$linuxRadius = $radius->saveGroup(null, ['name' => 'Linux endpoints ' . bin2hex(random_bytes(2)), 'cache_timeout' => '3600']);
$endpoints = new Endpoints();
$group = $endpoints->saveGroup(null, [
    'name' => 'Appliance test ' . bin2hex(random_bytes(2)), 'checkin_interval' => '60',
    'linux_enabled' => '1', 'linux_radius_group_id' => $linuxRadius['id'], 'linux_radius_servers' => '127.0.0.1',
    'linux_timeout' => '5', 'linux_services' => ['sshd'], 'linux_excluded_users' => '', 'linux_excluded_groups' => 'mfa-breakglass',
    'linux_ssh_keys_need_code' => '1', 'win_cpus_logon' => '0e', 'win_cpus_unlock' => '0e', 'win_cpus_credui' => '0e',
    'win_excluded_account' => '', 'win_cache_days' => '7', 'win_timeout_unlock' => '0', 'win_server_timeout' => '5',
]);
[, $token] = $endpoints->createToken($group['id'], 'appliance test', 1, 1, 'appliance-test');

// ---------------------------------------------------------------- enrol and check in through nginx
$agent = new AgentSim();
$inventory = ['hostname' => 'appliance-lin', 'os' => 'linux', 'os_name' => 'Debian GNU/Linux', 'os_version' => '12', 'ips' => [SOURCE], 'agent_version' => 'test'];
$started = time();
[$status, $reply] = agent_post('enroll', $agent->enrollRequest($token, $inventory));
$agent->id = $reply['endpoint_id'] ?? null;
check('enrolment through nginx (HTTPS)', 200 === $status && null !== $agent->id, "$status " . json_encode($reply));
$portalKey = (string) base64_decode((string) ($reply['portal_key'] ?? ''), true);
check('portal key matches the pin', hash('sha256', $portalKey) === $endpoints->pin());
[$status, $reply] = agent_post('checkin', ['inventory' => $inventory, 'applied' => ['version' => 0, 'status' => 'none', 'error' => '', 'at' => null]], $agent);
$config = null;
try {
    $config = $agent->openConfig($reply['config'] ?? [], $portalKey, 0, 'linux');
} catch (Throwable $error) {
    check('configuration opens', false, $error->getMessage());
}
check('signed check-in returns a configuration', 200 === $status && null !== $config, "$status " . json_encode($reply));
$record = $endpoints->endpoint((string) $agent->id);
$client = $radius->client((string) ($record['radius_client_id'] ?? ''));
check('endpoint is a RADIUS client at its source address', null !== $client && SOURCE . '/32' === $client['address'], json_encode($record['radius_error'] ?? ''));
check('FreeRADIUS apply queued by the enrolment succeeded', 'succeeded' === wait_latest_apply($started));

// ---------------------------------------------------------------- the pushed secret works against real FreeRADIUS
$secret = (string) ($config['secrets']['radius_secret'] ?? '');
$login = RadiusClient::authenticate('127.0.0.1', 1812, $secret, $name, next_code($seed, $step), SOURCE);
check('login from the endpoint with the pushed secret accepted', 'accepted' === $login['result'], json_encode($login));
$login = RadiusClient::authenticate('127.0.0.1', 1812, $secret, $name, '000000' === Totp::code($seed, intdiv(time(), 30)) ? '111111' : '000000', SOURCE);
check('wrong code from the endpoint rejected', 'rejected' === $login['result'], json_encode($login));

// ---------------------------------------------------------------- disabling the endpoint
$started = time();
$endpoints->setStatus((string) $agent->id, false);
[$status, $reply] = agent_post('checkin', ['applied' => ['version' => 1, 'status' => 'applied', 'error' => '', 'at' => time()]], $agent);
check('disabled endpoint refused by the API', 403 === $status && 'disabled' === ($reply['error'] ?? ''), "$status " . json_encode($reply));
check('FreeRADIUS apply after disabling succeeded', 'succeeded' === wait_latest_apply($started));
$login = RadiusClient::authenticate('127.0.0.1', 1812, $secret, $name, next_code($seed, $step), SOURCE, 3);
check('disabled endpoint can no longer use RADIUS', 'accepted' !== $login['result'], json_encode($login));

$endpoints->deleteEndpoint((string) $agent->id);
$users->delete($name);
echo "\n" . ($count - $failures) . "/$count appliance endpoint checks passed\n";
exit($failures > 0 ? 1 : 0);
