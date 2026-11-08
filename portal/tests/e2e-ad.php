<?php
/** Disposable Samba AD integration checks. Invoked by MULTIOTP_TEST_AD=1 run-in-docker.sh. */
declare(strict_types=1);
if ('cli' !== PHP_SAPI) { exit; }
define('PORTAL_ROOT', dirname(__DIR__));
require PORTAL_ROOT . '/src/bootstrap.php';

use Portal\Audit;
use Portal\Config;
use Portal\Directory;
use Portal\Jobs;
use Portal\MultiotpService;
use Portal\Totp;

error_reporting(E_ALL & ~E_DEPRECATED);
const SERVICE_PASSWORD = 'Test-Service-Password-42!';
const USER_PASSWORD = 'Test-User-Password-42!';
const STAFF_DN = 'OU=Staff,DC=example,DC=test';

function check(string $name, bool $ok, string $detail = ''): void
{
    echo ($ok ? 'ok   ' : 'FAIL ') . $name . ($ok || '' === $detail ? '' : "  [$detail]") . "\n";
    if (!$ok) { $GLOBALS['failures'] = ($GLOBALS['failures'] ?? 0) + 1; }
}
function saveSettings(array $changes = [], ?string $password = null): void
{
    $directory = new Directory();
    $diff = $directory->save(array_replace($directory->settings(), $changes), $password);
    Audit::default()->record('directory.settings_update', 'success', '', $diff);
    MultiotpService::reset();
}
function job(string $type): array
{
    $queued = Jobs::enqueue('directory.' . $type, [], 'ad-test');
    // A real, separate worker process: verifies persisted settings and sealed credentials.
    passthru(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(PORTAL_ROOT . '/bin/worker.php') . ' --once', $status);
    $done = Jobs::find($queued['id']);
    if ('succeeded' !== ($done['status'] ?? '')) {
        fwrite(STDERR, json_encode($done, JSON_PRETTY_PRINT) . "\n");
    }
    check("$type job succeeded", 0 === $status && 'succeeded' === ($done['status'] ?? ''));
    MultiotpService::reset();
    return $done['result'];
}
function user(string $name): Multiotp
{
    MultiotpService::reset();
    $engine = MultiotpService::get();
    check("$name exists in engine", $engine->ReadUserData($name));
    return $engine;
}
function names(array $rows): array
{
    $names = array_column($rows, 'user');
    sort($names);
    return $names;
}
function enabled(string $name): bool
{
    return 1 === (int) user($name)->GetUserActivated();
}

// Each TLS probe must start a fresh process: libldap caches environment defaults.
if ('connection' === ($argv[1] ?? '')) {
    $result = (new Directory())->testConnection();
    exit($result['ok'] ? 0 : 1);
}
function connection(string $mode, string $ca, bool $expected): void
{
    saveSettings(['tls_reqcert' => $mode]);
    $command = 'LDAPTLS_CACERT=' . escapeshellarg($ca) . ' ' . escapeshellarg(PHP_BINARY)
        . ' ' . escapeshellarg(__FILE__) . ' connection';
    passthru($command, $status);
    check("LDAPS $mode / " . basename($ca) . ($expected ? ' accepted' : ' refused'), $expected ? 0 === $status : 1 === $status);
}

Audit::setActor('ad-test');
Audit::setIp('local');
saveSettings([
    'enabled' => 1, 'server_type' => 1, 'domain_controllers' => 'dc.example.test',
    'port' => '636', 'ssl' => 1, 'tls_reqcert' => 'demand',
    'base_dn' => 'DC=example,DC=test', 'users_dn' => STAFF_DN,
    'bind_dn' => 'svc-multiotp', 'account_suffix' => '@EXAMPLE.TEST',
    'in_groups' => '', 'ldap_filter' => '', 'recursive_groups' => 1,
    'cn_identifier' => 'sAMAccountName', 'group_attribute' => 'memberOf',
    'group_cn_identifier' => 'sAMAccountName', 'synced_user_attribute' => 'sAMAccountName',
    'default_algorithm' => 'totp', 'request_ldap_password' => 1,
    'dont_auto_disable' => 0, 'dont_auto_enable' => 0,
    'delete_retention_days' => 0, 'network_timeout' => 5, 'schedule_enabled' => 0,
], SERVICE_PASSWORD);
connection('never', '/etc/ssl/certs/ca-certificates.crt', true);
connection('demand', '/etc/ssl/certs/ca-certificates.crt', false);
connection('demand', '/ad-cert/ad.pem', true);

$preview = job('preview');
check('preview sees exactly five Staff accounts', 5 === $preview['found'] && names($preview['create']) === ['alice', 'bob', 'carol', 'dave', 'erin']);
check('preview leaves engine users unchanged', [] === Directory::snapshot());
$sync = job('sync');
$created = $sync['created']; sort($created);
check('sync creates exactly the Staff accounts (not service/admin accounts)', ['alice', 'bob', 'carol', 'dave', 'erin'] === $created);
foreach (['alice', 'bob', 'carol', 'dave', 'erin'] as $name) {
    $engine = user($name);
    check("$name DN", 0 === strcasecmp("CN=$name," . STAFF_DN, $engine->GetUserSynchronizedDn()));
    check("$name display name", "$name Example" === $engine->GetUserDisplayName(), $engine->GetUserDisplayName());
    check("$name email", "$name@example.test" === $engine->GetUserEmail(), $engine->GetUserEmail());
    check("$name synchronized via LDAP", $engine->IsUserSynchronized() && 'LDAP' === $engine->GetUserSynchronizedChannel());
}
check('disabled AD account erin is disabled locally', !enabled('erin'));

// Mutations go to the real directory over trusted LDAPS; the sync service stays read-only.
$ad = ldap_connect('ldaps://dc.example.test:636');
ldap_set_option($ad, LDAP_OPT_PROTOCOL_VERSION, 3);
ldap_set_option($ad, LDAP_OPT_REFERRALS, 0);
check('fixture administrator bind', ldap_bind($ad, 'Administrator@EXAMPLE.TEST', 'Test-Admin-Password-42!'));
check('disable bob in AD', ldap_mod_replace($ad, 'CN=bob,' . STAFF_DN, ['userAccountControl' => '514']));
$preview = job('preview');
check('preview predicts bob disabled', ['bob'] === names($preview['disable']));
job('sync');
check('bob disabled after sync', !enabled('bob'));
check('enable bob in AD', ldap_mod_replace($ad, 'CN=bob,' . STAFF_DN, ['userAccountControl' => '512']));
saveSettings(['dont_auto_enable' => 1]);
job('sync');
check('do not re-enable preserves bob disabled', !enabled('bob'));
saveSettings(['dont_auto_enable' => 0]);
$preview = job('preview');
check('preview predicts bob re-enabled', ['bob'] === names($preview['reenable']));
job('sync');
check('bob re-enabled after sync', enabled('bob'));

saveSettings(['in_groups' => 'MFA-Users']);
$preview = job('preview');
check('AD group preview finds only alice and bob', 2 === $preview['found'] && names($preview['update']) === ['alice', 'bob']);
job('sync');
check('MFA scope enables only alice and bob', enabled('alice') && enabled('bob') && !enabled('carol') && !enabled('dave') && !enabled('erin'));
saveSettings(['in_groups' => 'MFA-Users,VPN-Users']);
$preview = job('preview');
check('AD multiple-group list deduplicates nested users', 3 === $preview['found']);
saveSettings(['in_groups' => 'VPN-Users', 'recursive_groups' => 1]);
$preview = job('preview');
check('nested VPN group preview finds three users', 3 === $preview['found']);
job('sync');
check('VPN scope includes carol and nested MFA alice/bob', enabled('alice') && enabled('bob') && enabled('carol') && !enabled('dave'));
check('remove bob from MFA group in AD', ldap_mod_del($ad, 'CN=MFA-Users,CN=Users,DC=example,DC=test', ['member' => 'CN=bob,' . STAFF_DN]));
$preview = job('preview');
check('removed member appears missing in preview', in_array('bob', names($preview['missing']), true));
job('sync');
check('member removed from group scope is disabled', !enabled('bob'));

$engine = user('alice');
check('synced user requires directory password', 1 === (int) $engine->GetUserRequestLdapPassword());
$seed = hex2bin($engine->GetUserTokenSeed());
check('synced TOTP seed is usable', false !== $seed && '' !== $seed);
$code = Totp::code($seed, intdiv(time(), 30));
// Wrong password first, so a replay rejection cannot masquerade as password validation.
check('wrong directory password with valid fresh OTP refused', 0 !== $engine->CheckToken('Wrong-Password-42!' . $code));
check('directory password plus same OTP accepted', 0 === $engine->CheckToken(USER_PASSWORD . $code));

MultiotpService::reset();
check('service password absent from decoded engine config', '' === MultiotpService::get()->GetLdapServerPassword());
foreach (glob(Config::etcDir() . '/config/*') ?: [] as $file) {
    if (is_file($file)) { check('service password not in config ' . basename($file), !str_contains((string) file_get_contents($file), SERVICE_PASSWORD)); }
}
$sealed = (string) file_get_contents(Config::dataDir() . '/directory.json');
check('portal service password sealed at rest', !str_contains($sealed, SERVICE_PASSWORD));
$audit = (string) file_get_contents(Config::dataDir() . '/audit.jsonl');
check('audit contains real sync/preview events', str_contains($audit, 'directory.sync') && str_contains($audit, 'directory.preview'));
check('service password absent from audit trail', !str_contains($audit, SERVICE_PASSWORD));
if (!empty($GLOBALS['failures'])) {
    echo $GLOBALS['failures'] . " Samba AD check(s) failed.\n";
    exit(1);
}
echo "All Samba AD checks passed.\n";
