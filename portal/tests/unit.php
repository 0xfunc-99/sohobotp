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

echo "\n" . ($count - $failures) . "/$count checks passed\n";
exit($failures > 0 ? 1 : 0);
