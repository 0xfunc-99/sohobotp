<?php
/**
 * Endpoints against the disposable Samba AD (run after e2e-ad.php, which configures the
 * directory over LDAPS): computer lookups, nested groups, approval from Active Directory,
 * assignment rules, administrator pinning. Invoked by MULTIOTP_TEST_AD=1 run-in-docker.sh.
 */
declare(strict_types=1);
if ('cli' !== PHP_SAPI) { exit; }
define('PORTAL_ROOT', dirname(__DIR__));
require PORTAL_ROOT . '/src/bootstrap.php';
require __DIR__ . '/AgentSim.php';
error_reporting(E_ALL & ~E_DEPRECATED);

use Portal\Directory;
use Portal\Endpoints;

$failures = 0;
function check(string $name, bool $ok, string $detail = ''): void
{
    global $failures;
    $failures += $ok ? 0 : 1;
    echo ($ok ? 'ok   ' : 'FAIL ') . $name . ($ok || '' === $detail ? '' : "  [$detail]") . "\n";
}

const BASE = 'DC=example,DC=test';
// Samba's DNS is not used by the test container: the resolver is replaced with the
// addresses the computers would have registered (the real resolver is dns_get_record()).
$dns = ['pc01.example.test' => ['10.99.0.11'], 'pc02.example.test' => ['10.99.0.12'], 'srv01.example.test' => ['10.99.0.21']];
$resolver = static fn (string $host): array => $dns[strtolower($host)] ?? [];

// ---------------------------------------------------------------- simulate domain joins
// samba-tool creates computer accounts disabled and without dNSHostName; a real join sets both.
$ad = ldap_connect('ldaps://dc.example.test:636');
ldap_set_option($ad, LDAP_OPT_PROTOCOL_VERSION, 3);
ldap_set_option($ad, LDAP_OPT_REFERRALS, 0);
check('fixture administrator bind', ldap_bind($ad, 'Administrator@EXAMPLE.TEST', 'Test-Admin-Password-42!'));
foreach (['PC01' => 'Laptops', 'PC02' => 'Laptops', 'SRV01' => 'Servers'] as $computer => $ou) {
    $joined = ldap_mod_replace($ad, "CN=$computer,OU=$ou," . BASE, [
        'userAccountControl' => 'PC02' === $computer ? '4098' : '4096', // PC02 stays disabled
        'dNSHostName' => strtolower($computer) . '.example.test',
    ]);
    check("$computer joined (enabled, DNS name)", $joined, ldap_error($ad));
}

// ---------------------------------------------------------------- computer lookups
$found = (new Directory())->computers(['PC01', 'srv01.example.test', 'ghost', 'bad name!']);
$pc01 = $found['pc01'] ?? null;
$srv01 = $found['srv01.example.test'] ?? null;
check('PC01 found in its OU', null !== $pc01 && 0 === strcasecmp('CN=PC01,OU=Laptops,' . BASE, $pc01['dn']) && $pc01['enabled'], json_encode($pc01));
check('computer DNS name read', null !== $pc01 && 'pc01.example.test' === $pc01['dns_host'], json_encode($pc01));
check('SRV01 groups include nested membership', null !== $srv01 && [] === array_diff(['All-Servers', 'MFA-Servers'], $srv01['groups']), json_encode($srv01));
check('unknown and invalid names not found', null === $found['ghost'] && null === $found['bad name!']);

// ---------------------------------------------------------------- groups, rules, token
$endpoints = new Endpoints();
$form = static fn (string $name): array => [
    'name' => $name, 'checkin_interval' => '60', 'linux_enabled' => '', 'linux_timeout' => '5', 'linux_services' => [],
    'linux_excluded_users' => '', 'linux_excluded_groups' => '', 'win_cpus_logon' => '0e', 'win_cpus_unlock' => '0e',
    'win_cpus_credui' => '0e', 'win_excluded_account' => '', 'win_cache_days' => '7', 'win_timeout_unlock' => '0', 'win_server_timeout' => '5',
];
$default = $endpoints->saveGroup(null, $form('Unsorted'));
$laptops = $endpoints->saveGroup(null, $form('AD laptops'));
$servers = $endpoints->saveGroup(null, $form('AD servers'));
$ouRule = $endpoints->addRule('ou', 'OU=Laptops, DC=example, DC=test', $laptops['id']);
$groupRule = $endpoints->addRule('group', 'All-Servers', $servers['id']);
[, $token] = $endpoints->createToken($default['id'], 'GPO rollout', 1, 10, 'ad-test', 'directory');

$machines = [];
$enrol = static function (string $hostname, string $ip) use ($endpoints, $token, &$machines): AgentSim {
    $agent = new AgentSim();
    $agent->id = $endpoints->enroll($agent->enrollRequest($token, ['hostname' => $hostname, 'os' => 'windows', 'domain' => 'EXAMPLE']), $ip, 'portal.example.test')['endpoint_id'];
    $machines[] = $agent;
    return $agent;
};

$pc = $enrol('PC01', '10.99.0.11');
$srv = $enrol('SRV01', '10.99.0.21');
$ghost = $enrol('GHOST', '10.99.0.31');
$disabled = $enrol('PC02', '10.99.0.12');
$impostor = $enrol('PC01', '10.99.0.99'); // copied the GPO token, claims to be PC01
check('all machines wait for approval', 'pending' === $endpoints->endpoint($pc->id)['status'] && 'pending' === $endpoints->endpoint($impostor->id)['status']);
check('AD check due right after enrolment', $endpoints->isDirectoryCheckDue(time()));

$summary = $endpoints->checkDirectory(null, $resolver);
$state = static fn (AgentSim $a): array => $endpoints->endpoint((string) $a->id);
check('check summary', 5 === $summary['checked'] && 4 === $summary['found'] && 2 === count($summary['approved']) && ['GHOST'] === $summary['not_found'], json_encode($summary));
check('PC01 approved from AD and moved by the OU rule', 'active' === $state($pc)['status'] && $laptops['id'] === $state($pc)['group_id'] && 'rule:' . $ouRule['id'] === $state($pc)['assigned_by']);
check('SRV01 approved and moved by the nested group rule', 'active' === $state($srv)['status'] && $servers['id'] === $state($srv)['group_id']);
check('unknown computer stays pending, with the reason', 'pending' === $state($ghost)['status'] && str_contains($state($ghost)['approval_note'], 'No computer account'));
check('computer disabled in AD stays pending', 'pending' === $state($disabled)['status'] && str_contains($state($disabled)['approval_note'], 'disabled'));
check('impostor claiming PC01 stays pending (address or duplicate)', 'pending' === $state($impostor)['status']
    && (str_contains($state($impostor)['approval_note'], 'does not resolve') || str_contains($state($impostor)['approval_note'], 'Another active endpoint')), $state($impostor)['approval_note']);

$none = ['version' => 0, 'status' => 'none', 'error' => '', 'at' => null];
$signedCheckin = static function (AgentSim $agent, string $ip, string $hostname) use ($endpoints, $none): array {
    $body = json_encode(['inventory' => ['hostname' => $hostname, 'os' => 'windows'], 'applied' => $none]);
    $uri = '/portal/agent.php?a=checkin';
    return $endpoints->checkin($endpoints->authenticate($agent->headers('POST', $uri, $body), 'POST', $uri, $body), json_decode($body, true), $ip);
};
check('approved machine receives its configuration', null !== $signedCheckin($pc, '10.99.0.11', 'PC01')['config']);
check('pending machine receives nothing', null === $signedCheckin($impostor, '10.99.0.99', 'PC01')['config']);

// a second machine for the same computer is never approved while the first is active
$copy = $enrol('PC01', '10.99.0.11');
$endpoints->checkDirectory(null, $resolver);
check('second endpoint for an active computer stays pending', 'pending' === $state($copy)['status'] && str_contains($state($copy)['approval_note'], 'Another active endpoint'), $state($copy)['approval_note']);

// an approved machine that starts reporting another name keeps its computer account
$signedCheckin($srv, '10.99.0.21', 'PC01');
$endpoints->checkDirectory(null, $resolver);
check('renamed report: still bound to SRV01, not PC01', 'srv01' === $state($srv)['ad_name'] && str_contains($state($srv)['directory']['dn'], 'CN=SRV01') && $servers['id'] === $state($srv)['group_id']);
$signedCheckin($srv, '10.99.0.21', 'SRV01');

// ---------------------------------------------------------------- rules follow AD changes
check('add PC01 to All-Servers in AD', ldap_mod_add($ad, 'CN=All-Servers,CN=Users,' . BASE, ['member' => 'CN=PC01,OU=Laptops,' . BASE]));
$endpoints->checkDirectory(null, $resolver);
check('first matching rule wins (OU rule before group rule)', $laptops['id'] === $state($pc)['group_id']);
$endpoints->moveRule($groupRule['id'], -1);
$summary = $endpoints->checkDirectory(null, $resolver);
check('rule order changed: PC01 moves to servers', $servers['id'] === $state($pc)['group_id'] && in_array((string) $pc->id, array_column($summary['moved'], 'endpoint'), true), json_encode($summary['moved']));

$endpoints->moveEndpoint((string) $srv->id, $default['id']);
$endpoints->checkDirectory(null, $resolver);
check('machine moved by an administrator is not moved back', $default['id'] === $state($srv)['group_id'] && 'admin' === $state($srv)['assigned_by']);
$endpoints->unlockGroup((string) $srv->id);
$endpoints->checkDirectory(null, $resolver);
check('after unlocking, the rules choose again', $servers['id'] === $state($srv)['group_id']);

check('remove PC01 from All-Servers in AD', ldap_mod_del($ad, 'CN=All-Servers,CN=Users,' . BASE, ['member' => 'CN=PC01,OU=Laptops,' . BASE]));
$endpoints->checkDirectory(null, $resolver);
check('membership removed: the OU rule applies again', $laptops['id'] === $state($pc)['group_id']);

foreach ($machines as $agent) {
    $endpoints->deleteEndpoint((string) $agent->id);
}
echo $failures > 0 ? "$failures endpoint AD check(s) failed.\n" : "All endpoint AD checks passed.\n";
exit($failures > 0 ? 1 : 0);
