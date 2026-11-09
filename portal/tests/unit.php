<?php
/**
 * Portal unit checks (no framework). Run with writable folders, e.g.:
 *   MULTIOTP_ETC_DIR=/tmp/etc MULTIOTP_PORTAL_DATA=/tmp/portal MULTIOTP_LOG_DIR=/tmp/log php portal/tests/unit.php
 */
declare(strict_types=1);

if ('cli' !== PHP_SAPI) {
    exit;
}
define('PORTAL_ROOT', dirname(__DIR__));
require PORTAL_ROOT . '/src/bootstrap.php';

use Portal\AdminRepository;
use Portal\Audit;
use Portal\Config;
use Portal\Crypto;
use Portal\Mfa;
use Portal\MultiotpService;
use Portal\Passwords;
use Portal\Roles;
use Portal\Totp;
use Portal\ValidationException;

$failures = 0;
$count = 0;
function check(string $name, bool $ok): void
{
    global $failures, $count;
    $count++;
    if (!$ok) {
        $failures++;
    }
    echo ($ok ? 'ok   ' : 'FAIL ') . $name . "\n";
}
function throws(callable $fn, string $class = \Throwable::class): bool
{
    try {
        $fn();
    } catch (\Throwable $t) {
        return $t instanceof $class;
    }
    return false;
}

// --- TOTP: RFC 6238 SHA1 test vectors (last 6 digits of the 8-digit values)
$rfc = '12345678901234567890';
check('totp rfc t=59', '287082' === Totp::code($rfc, intdiv(59, 30)));
check('totp rfc t=1111111109', '081804' === Totp::code($rfc, intdiv(1111111109, 30)));
check('totp rfc t=1234567890', '005924' === Totp::code($rfc, intdiv(1234567890, 30)));
check('totp rfc t=2000000000', '279037' === Totp::code($rfc, intdiv(2000000000, 30)));
check('base32 rfc secret', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' === Totp::base32($rfc));
$now = 1_700_000_000;
$code = Totp::code($rfc, intdiv($now, 30));
check('totp verify current', intdiv($now, 30) === Totp::verify($rfc, $code, -1, $now));
check('totp verify with spaces', null !== Totp::verify($rfc, substr($code, 0, 3) . ' ' . substr($code, 3), -1, $now));
check('totp previous step accepted', null !== Totp::verify($rfc, Totp::code($rfc, intdiv($now, 30) - 1), -1, $now));
check('totp 2 steps old refused', null === Totp::verify($rfc, Totp::code($rfc, intdiv($now, 30) - 2), -1, $now));
check('totp replay refused', null === Totp::verify($rfc, $code, intdiv($now, 30), $now));
check('totp garbage refused', null === Totp::verify($rfc, '12ab56', -1, $now));
check('otpauth uri', str_starts_with(Totp::uri('Acme portal', 'alice', $rfc), 'otpauth://totp/Acme%20portal:alice?secret=GEZDGNBV'));

// --- Passwords
check('password too short', null !== Passwords::validate('short', 'alice'));
check('password containing username', null !== Passwords::validate('xx-ALICE-correct-horse', 'alice'));
check('password repetitive', null !== Passwords::validate('aaaaaaaaaaaaaaaa', 'alice'));
check('password ok', null === Passwords::validate('correct horse battery', 'alice'));
$hash = Passwords::hash('correct horse battery');
check('password verify', Passwords::verify('correct horse battery', $hash));
check('password wrong', !Passwords::verify('wrong', $hash));
check('password null hash', !Passwords::verify('anything', null));
check('temporary password format', 1 === preg_match('/^([A-Za-z2-9]{5}-){3}[A-Za-z2-9]{5}$/', Passwords::temporary()));

// --- Crypto
$sealed = Crypto::encrypt('top secret seed');
check('crypto round trip', 'top secret seed' === Crypto::decrypt($sealed));
check('crypto randomised', $sealed !== Crypto::encrypt('top secret seed'));
$raw = base64_decode(substr($sealed, 4));
$raw[30] = chr(ord($raw[30]) ^ 1);
check('crypto tamper detected', throws(static fn () => Crypto::decrypt('sb1:' . base64_encode($raw))));
check('portal.key is private', '0600' === substr(sprintf('%o', fileperms(Config::dataDir() . '/portal.key')), -4));

// --- Roles
check('superadmin manages admins', Roles::can('superadmin', 'admins.manage'));
check('admin cannot manage admins', !Roles::can('admin', 'admins.manage'));
check('helpdesk cannot read audit', !Roles::can('helpdesk', 'audit.view'));
check('auditor reads audit', Roles::can('auditor', 'audit.view'));
check('unknown role has nothing', !Roles::can('nobody', 'dashboard.view'));

// --- Audit trail
$file = Config::dataDir() . '/unit-audit.jsonl';
@unlink($file);
@unlink($file . '.state');
$audit = new Audit($file);
Audit::setActor('tester', 'superadmin');
Audit::setIp('192.0.2.1');
$audit->record('admin.create', 'success', 'bob', ['role' => 'helpdesk', 'password' => 'hunter2', 'nested' => ['token_seed' => 'abc', 'serial' => 'YK123']]);
$audit->record('auth.login', 'failure', 'bob', ['reason' => 'wrong password']);
$audit->record('auth.login', 'success', 'alice');
$text = (string) file_get_contents($file);
check('audit redacts secrets', !str_contains($text, 'hunter2') && !str_contains($text, '"abc"'));
check('audit keeps non-secrets', str_contains($text, 'YK123') && str_contains($text, 'helpdesk'));
check('audit chain verifies', $audit->verify()['ok'] && 3 === $audit->verify()['entries']);
check('audit search newest first', 'alice' === $audit->search([])['entries'][0]['target']);
check('audit filter action prefix', 2 === $audit->search(['action' => 'auth.'])['total']);
check('audit filter result', 1 === $audit->search(['result' => 'failure'])['total']);
check('audit filter text', 1 === $audit->search(['q' => 'wrong password'])['total']);
unlink($file . '.state');
$audit->record('auth.logout', 'success', 'alice');
check('audit state rebuilt from file', $audit->verify()['ok'] && 4 === $audit->verify()['entries']);
file_put_contents($file, str_replace('"bob"', '"eve"', $text) . implode('', array_slice(file($file), 3)));
$broken = $audit->verify();
check('audit tamper detected', !$broken['ok'] && 1 === $broken['broken_at']);

// --- Administrator repository
$repo = new AdminRepository(new Portal\JsonStore(Config::dataDir() . '/unit-admins.json'));
@unlink(Config::dataDir() . '/unit-admins.json');
$alice = $repo->create(['username' => 'Alice', 'role' => 'superadmin'], 'correct horse battery', true, 'unit');
check('username normalised', 'alice' === $alice['username']);
check('temporary password flagged', true === $alice['must_change_password'] && $alice['password_expires_at'] > time());
check('duplicate refused', throws(static fn () => $repo->create(['username' => 'ALICE', 'role' => 'admin'], 'x', false, 'unit'), ValidationException::class));
check('bad username refused', throws(static fn () => $repo->create(['username' => '../etc', 'role' => 'admin'], 'x', false, 'unit'), ValidationException::class));
check('bad role refused', throws(static fn () => $repo->create(['username' => 'bob', 'role' => 'root'], 'x', false, 'unit'), ValidationException::class));
check('find by username', null !== $repo->findByUsername(' ALICE '));
for ($i = 1; $i < Config::maxFailures(); $i++) {
    $repo->registerFailure($alice['id']);
}
check('not locked before limit', !AdminRepository::isLocked($repo->find($alice['id'])));
check('locked at limit', AdminRepository::isLocked($repo->registerFailure($alice['id'])));
check('one active superadmin', 1 === AdminRepository::activeSuperadmins($repo->all()));
check('none besides alice', 0 === AdminRepository::activeSuperadmins($repo->all(), $alice['id']));
check('admins.json is private', '0600' === substr(sprintf('%o', fileperms(Config::dataDir() . '/unit-admins.json')), -4));
check('no secret in admins.json', !str_contains((string) file_get_contents(Config::dataDir() . '/unit-admins.json'), 'correct horse'));

// --- Portal MFA enrolment
$secret = Totp::newSecret();
$mfa = new Mfa($repo);
check('enrol wrong code refused', !$mfa->enroll($alice['id'], $secret, '000000') || '000000' === Totp::code($secret, intdiv(time(), 30)));
$code = Totp::code($secret, intdiv(time(), 30));
check('enrol right code', $mfa->enroll($alice['id'], $secret, $code));
$alice = $repo->find($alice['id']);
check('seed stored encrypted', 'portal' === $alice['mfa_mode'] && str_starts_with($alice['mfa_secret'], 'sb1:'));
check('enrol code cannot be replayed', !$mfa->verify($alice, $code));

// --- multiOTP engine: TOTP maths agree, linked-user MFA, without2FA refused
$multiotp = MultiotpService::get();
$seed = random_bytes(20);
$step = intdiv(time(), 30);
check('portal totp equals multiOTP engine', Totp::code($seed, $step) === $multiotp->GenerateOathHotp($seed, $step, 6));
$multiotp->DeleteUser('unit-linked', true);
$multiotp->DeleteUser('unit-nomfa', true);
check('create multiOTP totp user', false !== $multiotp->CreateUser('unit-linked', 0, 'totp', bin2hex($seed), '', 6, 30));
check('create multiOTP without2fa user', false !== $multiotp->CreateUser('unit-nomfa', 0, 'without2fa'));
check('linkable user accepted', null === Mfa::checkLinkableUser('unit-linked'));
check('without2fa user refused', null !== Mfa::checkLinkableUser('unit-nomfa'));
check('missing user refused', null !== Mfa::checkLinkableUser('unit-missing'));
$linked = ['id' => 'x', 'mfa_mode' => 'multiotp', 'mfa_user' => 'unit-linked'];
$code = Totp::code($seed, intdiv(time(), 30));
check('linked user code accepted', $mfa->verify($linked, $code));
check('linked user replay refused', !$mfa->verify($linked, $code));
check('without2fa never verifies', !$mfa->verify(['id' => 'y', 'mfa_mode' => 'multiotp', 'mfa_user' => 'unit-nomfa'], ''));
check('unenrolled never verifies', !$mfa->verify(['id' => 'z', 'mfa_mode' => null], '123456'));

// --- RADIUS: addresses, secrets, generated FreeRADIUS file
use Portal\Radius;
use Portal\RadiusClient;

check('address host becomes /32', '10.0.0.5/32' === Radius::normaliseAddress('10.0.0.5'));
check('address network is aligned', '10.0.0.0/24' === Radius::normaliseAddress('10.0.0.77/24'));
check('ipv6 network aligned', '2001:db8::/64' === Radius::normaliseAddress('2001:db8::1234/64'));
check('catch-all network refused', throws(static fn () => Radius::normaliseAddress('0.0.0.0/0'), ValidationException::class));
check('/7 refused', throws(static fn () => Radius::normaliseAddress('10.0.0.0/7'), ValidationException::class));
check('host name refused', throws(static fn () => Radius::normaliseAddress('vpn.example.com'), ValidationException::class));
check('localhost reserved', throws(static fn () => Radius::normaliseAddress('127.0.0.1'), ValidationException::class));
check('generated secret 24 chars', 1 === preg_match('/^[A-Za-z2-9]{24}$/', Radius::newSecret()));
check('custom secret with quote refused', throws(static fn () => Radius::validSecret('abcdefghijklmnop"q'), ValidationException::class));
check('custom secret with $ refused', throws(static fn () => Radius::validSecret('abcdefghijklmnop${x}'), ValidationException::class));
check('custom secret too short refused', throws(static fn () => Radius::validSecret('short'), ValidationException::class));
check('custom secret accepted', 'Abc-def_ghi.jkl:mno!' === Radius::validSecret('Abc-def_ghi.jkl:mno!'));

@unlink(Config::dataDir() . '/unit-radius.json');
$radius = new Radius(new Portal\JsonStore(Config::dataDir() . '/unit-radius.json'));
$vpn = $radius->saveGroup(null, ['name' => 'VPN gateways', 'challenge_response' => '1', 'cache_timeout' => '3600']);
check('group created', 'VPN gateways' === $vpn['name'] && true === $vpn['policy']['challenge_response']);
check('duplicate group refused', throws(static fn () => $radius->saveGroup(null, ['name' => 'vpn gateways', 'cache_timeout' => '3600']), ValidationException::class));
[$fw, $fwSecret] = $radius->createClient(['name' => 'fw-paris', 'address' => '192.0.2.10', 'group_id' => $vpn['id'], 'nas_type' => 'other', 'require_message_authenticator' => '1']);
check('client created with secret', '192.0.2.10/32' === $fw['address'] && 24 === strlen($fwSecret) && !isset($fw['secret']));
check('duplicate address refused', throws(static fn () => $radius->createClient(['name' => 'fw-other', 'address' => '192.0.2.10/32', 'group_id' => $vpn['id']]), ValidationException::class));
check('secret sealed in radius.json', !str_contains((string) file_get_contents(Config::dataDir() . '/unit-radius.json'), $fwSecret));
Portal\MultiotpService::reset();
$device = Portal\MultiotpService::get();
check('engine device written', $device->ReadDeviceData($fw['id'], false, true) && Radius::shortname($fw) === $device->GetDeviceShortname() && 1 === (int) $device->GetDeviceChallengeEnabled());
$radius->saveGroup($vpn['id'], ['name' => 'VPN gateways', 'challenge_response' => '', 'cache_result' => '1', 'cache_timeout' => '600']);
Portal\MultiotpService::reset();
$device = Portal\MultiotpService::get();
$device->ReadDeviceData($fw['id'], false, true);
check('group policy change reaches device', 0 === (int) $device->GetDeviceChallengeEnabled() && 1 === (int) $device->GetDeviceCacheResultEnabled() && 600 === (int) $device->GetDeviceCacheTimeout());
check('group with servers cannot be deleted', throws(static fn () => $radius->deleteGroup($vpn['id']), ValidationException::class));
$rendered = $radius->render();
check('rendered file has client and secret', str_contains($rendered, 'client fw-paris-' . $fw['id'] . ' {') && str_contains($rendered, "secret = \"$fwSecret\"") && str_contains($rendered, 'ipaddr = 192.0.2.10/32'));
check('rendered file has diagnostics client', str_contains($rendered, 'ipaddr = 127.0.0.2/32'));
$newSecret = $radius->rotateSecret($fw['id']);
check('secret rotated', $newSecret !== $fwSecret && str_contains($radius->render(), $newSecret));
file_put_contents(sys_get_temp_dir() . '/unit-radius-candidate.conf', $radius->render());

// RADIUS PAP hiding (RFC 2865 5.2) round trip
$authenticator = random_bytes(16);
$hidden = RadiusClient::hidePassword('secret-password-longer-than-16', 'shared', $authenticator);
$plain = '';
$previous = $authenticator;
foreach (str_split($hidden, 16) as $block) {
    $plain .= $block ^ md5('shared' . $previous, true);
    $previous = $block;
}
check('PAP password hiding reversible', 'secret-password-longer-than-16' === rtrim($plain, "\0") && 0 === strlen($hidden) % 16);

$radius->deleteClient($fw['id']);
Portal\MultiotpService::reset();
check('client delete removes engine device', !Portal\MultiotpService::get()->ReadDeviceData($fw['id'], false, true));

// --- Endpoints: protocol vectors (generated with libsodium, docs/agent-protocol-vectors.json)
use Portal\AgentError;
use Portal\Endpoints;

require __DIR__ . '/AgentSim.php';
$v = json_decode((string) file_get_contents(PORTAL_ROOT . '/docs/agent-protocol-vectors.json'), true);
$b = static fn (string $s): string => (string) base64_decode($s, true);
check('vector: enrolment proof message', $v['enroll']['message'] === Endpoints::enrollMessage($v['enroll']['token'], $b($v['agent_sign_public']), $b($v['agent_box_public'])));
check('vector: enrolment proof verifies', sodium_crypto_sign_verify_detached($b($v['enroll']['proof']), $v['enroll']['message'], $b($v['agent_sign_public'])));
$r = $v['request'];
check('vector: request message', $r['message'] === Endpoints::requestMessage($r['method'], $r['uri'], $r['time'], $r['nonce'], $r['body']));
check('vector: request signature verifies', sodium_crypto_sign_verify_detached($b($r['signature']), $r['message'], $b($v['agent_sign_public'])));
$vectorPortal = sodium_crypto_sign_seed_keypair($b($v['portal_sign_seed']));
check('vector: portal public key from seed', $v['portal_sign_public'] === base64_encode(sodium_crypto_sign_publickey($vectorPortal)));
check('vector: pin is SHA-256 of the public key', $v['portal_key_pin'] === hash('sha256', $b($v['portal_sign_public'])));
check('vector: config signature reproduced', $v['config']['envelope']['signature'] === base64_encode(Endpoints::signConfig($v['config']['payload_json'], sodium_crypto_sign_secretkey($vectorPortal))));
$vectorBox = sodium_crypto_box_keypair_from_secretkey_and_publickey($b($v['agent_box_secret']), $b($v['agent_box_public']));
$payload = json_decode($v['config']['payload_json'], true);
check('vector: sealed secret opens', $v['config']['radius_secret_plain'] === sodium_crypto_box_seal_open($b($payload['secrets']['radius_secret']), $vectorBox));

// --- Endpoints: helpers
check('server: host name, default port', ['host' => 'radius.example.com', 'port' => 1812] === Endpoints::parseServer('radius.example.com'));
check('server: IPv4 with port', ['host' => '10.0.0.6', 'port' => 1645] === Endpoints::parseServer('10.0.0.6:1645'));
check('server: bracketed IPv6 with port', ['host' => '2001:db8::1', 'port' => 1812] === Endpoints::parseServer('[2001:db8::1]:1812'));
check('server: bare IPv6', ['host' => '2001:db8::1', 'port' => 1812] === Endpoints::parseServer('2001:db8::1'));
check('server: invalid host refused', null === Endpoints::parseServer('bad host!') && null === Endpoints::parseServer('10.0.0.1:70000'));
$inv = Endpoints::inventory(['hostname' => "lin\x01-01" . str_repeat('x', 300), 'os' => 'plan9', 'ips' => ['10.0.0.1', 'nope', ['x']], 'component' => 'bad']);
check('inventory: control characters removed, length capped', str_starts_with($inv['hostname'], 'lin -01') && 255 === mb_strlen($inv['hostname']));
check('inventory: unknown OS and bad IPs dropped', '' === $inv['os'] && ['10.0.0.1'] === $inv['ips'] && ['name' => '', 'version' => ''] === $inv['component']);

// --- Endpoints: groups, tokens, enrolment, check-in
$radius = new Radius();
$linuxRadius = $radius->saveGroup(null, ['name' => 'Linux servers', 'cache_timeout' => '3600']);
$form = static fn (array $over = []): array => $over + [
    'checkin_interval' => '60', 'linux_enabled' => '1', 'linux_radius_group_id' => $linuxRadius['id'], 'linux_radius_servers' => '',
    'linux_timeout' => '5', 'linux_services' => ['sshd', 'sudo'], 'linux_excluded_users' => 'deploy', 'linux_excluded_groups' => 'mfa-breakglass',
    'linux_ssh_keys_need_code' => '1', 'win_cpus_logon' => '0e', 'win_cpus_unlock' => '0e', 'win_cpus_credui' => '0e',
    'win_excluded_account' => 'PC01\\breakglass', 'win_cache_enabled' => '1', 'win_cache_days' => '7', 'win_timeout_unlock' => '0', 'win_server_timeout' => '5',
];
$endpoints = new Endpoints();
check('group: Linux 2FA needs a RADIUS group', throws(static fn () => $endpoints->saveGroup(null, ['name' => 'Bad'] + $form(['linux_radius_group_id' => ''])), ValidationException::class));
check('group: invalid Linux user name refused', throws(static fn () => $endpoints->saveGroup(null, ['name' => 'Bad'] + $form(['linux_excluded_users' => 'a;rm -rf'])), ValidationException::class));
check('group: invalid CP mode refused', throws(static fn () => $endpoints->saveGroup(null, ['name' => 'Bad'] + $form(['win_cpus_logon' => '9x'])), ValidationException::class));
check('group: cache lifetime capped at 30 days', throws(static fn () => $endpoints->saveGroup(null, ['name' => 'Bad'] + $form(['win_cache_days' => '90'])), ValidationException::class));
$servers = $endpoints->saveGroup(null, ['name' => 'Servers'] + $form());
$laptops = $endpoints->saveGroup(null, ['name' => 'Laptops'] + $form(['linux_enabled' => '']));
check('groups saved', true === $servers['policy']['linux']['enabled'] && false === $laptops['policy']['linux']['enabled']);

[$tok, $plainToken] = $endpoints->createToken($servers['id'], 'unit', 1, 1, 'unit');
check('token format id.secret', 1 === preg_match('/^[0-9a-f]{12}\.[A-Za-z0-9_-]{32}$/', $plainToken));
check('token stored hashed only', !str_contains((string) file_get_contents(Config::dataDir() . '/endpoints.json'), explode('.', $plainToken)[1]) && !isset($endpoints->tokens()[0]['hash']));

$agentError = static function (callable $fn): string {
    try {
        $fn();
    } catch (AgentError $e) {
        return $e->errorCode;
    }
    return 'none';
};
$lin = new AgentSim();
$linInventory = ['hostname' => 'lin-01', 'os' => 'linux', 'os_name' => 'Debian GNU/Linux', 'os_version' => '12', 'ips' => ['192.0.2.50'], 'agent_version' => '0.1.0', 'component' => ['name' => 'pam_radius', 'version' => '2.0.0']];
$bad = $lin->enrollRequest($plainToken, $linInventory);
$bad['proof'] = base64_encode(str_repeat("\0", 64));
check('enrol: bad key proof refused', 'bad_request' === $agentError(static fn () => $endpoints->enroll($bad, '192.0.2.50', 'portal.example.test')));
check('enrol: wrong token refused', 'bad_token' === $agentError(static fn () => $endpoints->enroll($lin->enrollRequest(explode('.', $plainToken)[0] . '.' . str_repeat('A', 32), $linInventory), '192.0.2.50', 'portal.example.test')));
$enrolled = $endpoints->enroll($lin->enrollRequest($plainToken, $linInventory), '192.0.2.50', 'portal.example.test');
$lin->id = $enrolled['endpoint_id'];
$portalKey = $endpoints->publicKey();
check('enrol: endpoint id and pinned portal key', 1 === preg_match('/^[0-9a-f]{20}$/', $lin->id) && $portalKey === base64_decode($enrolled['portal_key']) && hash('sha256', $portalKey) === $endpoints->pin());
check('enrol: single-use token used up', 'bad_token' === $agentError(static fn () => $endpoints->enroll((new AgentSim())->enrollRequest($plainToken, $linInventory), '192.0.2.51', 'portal.example.test')));
$linRecord = $endpoints->endpoint($lin->id);
$client = $radius->client($linRecord['radius_client_id']);
check('enrol: Linux endpoint became a RADIUS client', null !== $client && '192.0.2.50/32' === $client['address'] && $client['group_id'] === $linuxRadius['id']);

$checkin = static function (AgentSim $agent, array $applied, ?array $headers = null, string $ip = '192.0.2.50') use ($endpoints): array {
    $body = json_encode(['inventory' => ['hostname' => 'host', 'os' => 'linux'], 'applied' => $applied]);
    $uri = '/portal/agent.php?a=checkin';
    $id = $endpoints->authenticate($headers ?? $agent->headers('POST', $uri, $body), 'POST', $uri, $body);
    return $endpoints->checkin($id, json_decode($body, true), $ip);
};
$none = ['version' => 0, 'status' => 'none', 'error' => '', 'at' => null];
$reply = $checkin($lin, $none);
$config = $lin->openConfig($reply['config'], $portalKey, 0, 'linux');
check('check-in: signed config verifies and opens', 1 === $config['version'] && 'linux' === $config['os'] && $config['secrets']['radius_secret'] === $radius->clientSecret($client['id']));
check('check-in: Linux policy', ['sshd', 'sudo'] === $config['policy']['services'] && ['root', 'deploy'] === $config['policy']['excluded_users']
    && [['host' => 'portal.example.test', 'port' => 1812]] === $config['policy']['radius_servers'] && true === $config['policy']['ssh_keys_need_code']);
check('check-in: config not resent once applied', null === $checkin($lin, ['version' => 1, 'status' => 'applied', 'error' => '', 'at' => time()])['config']);
check('check-in: tampered config refused by the agent', throws(static function () use ($lin, $reply, $portalKey): void {
    $tampered = $reply['config'];
    $tampered['payload'] = base64_encode(str_replace('"sshd"', '"login"', (string) base64_decode($tampered['payload'])));
    $lin->openConfig($tampered, $portalKey);
}, RuntimeException::class));
check('check-in: config replay refused by the agent', throws(static fn () => $lin->openConfig($reply['config'], $portalKey, 1), RuntimeException::class));

$body = '{"applied":{"version":1,"status":"applied"}}';
$uri = '/portal/agent.php?a=checkin';
$headers = $lin->headers('POST', $uri, $body);
check('auth: valid signature accepted', $lin->id === $endpoints->authenticate($headers, 'POST', $uri, $body));
check('auth: replayed request refused', 'replay' === $agentError(static fn () => $endpoints->authenticate($headers, 'POST', $uri, $body)));
check('auth: changed body refused', 'bad_signature' === $agentError(static fn () => $endpoints->authenticate($lin->headers('POST', $uri, $body), 'POST', $uri, $body . ' ')));
check('auth: other URI refused', 'bad_signature' === $agentError(static fn () => $endpoints->authenticate($lin->headers('POST', $uri, $body), 'POST', '/portal/agent.php?a=enroll', $body)));
check('auth: old timestamp refused', 'clock_skew' === $agentError(static fn () => $endpoints->authenticate($lin->headers('POST', $uri, $body, time() - 400), 'POST', $uri, $body)));
$stranger = new AgentSim();
$stranger->id = $lin->id;
check('auth: other key refused', 'bad_signature' === $agentError(static fn () => $endpoints->authenticate($stranger->headers('POST', $uri, $body), 'POST', $uri, $body)));
$stranger->id = str_repeat('a', 20);
check('auth: unknown endpoint refused', 'unknown_endpoint' === $agentError(static fn () => $endpoints->authenticate($stranger->headers('POST', $uri, $body), 'POST', $uri, $body)));

$endpoints->saveGroup($servers['id'], ['name' => 'Servers'] + $form(['linux_timeout' => '9']));
$reply = $checkin($lin, ['version' => 1, 'status' => 'applied', 'error' => '', 'at' => time()]);
$config = $lin->openConfig($reply['config'], $portalKey, 1);
check('policy change: new version pushed', 2 === $config['version'] && 9 === $config['policy']['timeout']);
check('failed apply: same version not resent', null === $checkin($lin, ['version' => 2, 'status' => 'failed', 'error' => 'sshd -t failed', 'at' => time()])['config']);
check('failed apply: error visible to the admin', 'sshd -t failed' === $endpoints->endpoint($lin->id)['applied']['error']);
$reply = $checkin($lin, ['version' => 9, 'status' => 'applied', 'error' => '', 'at' => time()]);
check('portal behind the agent (restored backup): version jumps ahead', 10 === $lin->openConfig($reply['config'], $portalKey, 9)['version']);

$secretBefore = $radius->clientSecret($client['id']);
$radius->rotateSecret($client['id']);
$reply = $checkin($lin, ['version' => 10, 'status' => 'applied', 'error' => '', 'at' => time()]);
check('RADIUS secret rotation reaches the endpoint', null !== $reply['config'] && $lin->openConfig($reply['config'], $portalKey, 10)['secrets']['radius_secret'] !== $secretBefore);

[, $multiToken] = $endpoints->createToken($laptops['id'], 'laptops', 1, 5, 'unit');
$win = new AgentSim();
$win->id = $endpoints->enroll($win->enrollRequest($multiToken, ['hostname' => 'PC01', 'os' => 'windows', 'domain' => 'EXAMPLE']), '192.0.2.60', 'portal.example.test')['endpoint_id'];
$reply = $checkin($win, $none, null, '192.0.2.60');
$winConfig = $win->openConfig($reply['config'], $portalKey, 0, 'windows');
check('Windows: per-endpoint CP gateway URL', 'https://portal.example.test/portal/cp.php?e=' . $win->id === $winConfig['policy']['server_url']);
check('Windows: own CP secret, offline cache policy', 1 === preg_match('/^[0-9a-f]{48}$/', $winConfig['secrets']['cp_shared_secret']) && true === $winConfig['policy']['cache_enabled'] && 'PC01\\breakglass' === $winConfig['policy']['excluded_account']);
check('Windows: no RADIUS client', '' === $endpoints->endpoint($win->id)['radius_client_id']);
check('Windows: CP secret sealed at rest', !str_contains((string) file_get_contents(Endpoints::dir() . '/' . $win->id . '.json'), $winConfig['secrets']['cp_shared_secret']));
$endpoints->setStatus($win->id, false);
check('disabled endpoint refused', 'disabled' === $agentError(static fn () => $checkin($win, $none, null, '192.0.2.60')));
$endpoints->setStatus($win->id, true);
$reply = $checkin($win, ['version' => 1, 'status' => 'applied', 'error' => '', 'at' => time()], null, '192.0.2.60');
check('re-enabled endpoint gets a new CP secret', null !== $reply['config'] && $win->openConfig($reply['config'], $portalKey, 1)['secrets']['cp_shared_secret'] !== $winConfig['secrets']['cp_shared_secret']);

$endpoints->moveEndpoint($lin->id, $laptops['id']);
check('moved to a group without Linux 2FA: RADIUS client removed', '' === $endpoints->endpoint($lin->id)['radius_client_id'] && null === $radius->client($client['id']));
$reply = $checkin($lin, ['version' => 11, 'status' => 'applied', 'error' => '', 'at' => time()]);
$config = $lin->openConfig($reply['config'], $portalKey, 11);
check('Linux 2FA off: policy disabled, no secrets', ['enabled' => false] === $config['policy'] && [] === $config['secrets']);
check('group with endpoints cannot be deleted', throws(static fn () => $endpoints->deleteGroup($laptops['id']), ValidationException::class));
$endpoints->moveEndpoint($lin->id, $servers['id']);
$linRecord = $endpoints->endpoint($lin->id);
check('moved back: RADIUS client recreated', '' !== $linRecord['radius_client_id'] && null !== $radius->client($linRecord['radius_client_id']));
$endpoints->deleteEndpoint($lin->id);
check('deleted endpoint: file and RADIUS client gone', null === $endpoints->endpoint($lin->id) && null === $radius->client($linRecord['radius_client_id']));

echo "\n" . ($count - $failures) . "/$count checks passed\n";
exit($failures > 0 ? 1 : 0);
