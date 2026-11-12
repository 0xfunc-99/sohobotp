<?php
/**
 * End-to-end checks against a running portal (plain HTTP test server).
 *   php portal/tests/e2e.php http://127.0.0.1:8080 SUPERADMIN_TEMP_PASSWORD
 * Expects a fresh data folder with one super administrator "root" (created by the CLI).
 */
declare(strict_types=1);

if ('cli' !== PHP_SAPI) {
    exit;
}
define('PORTAL_ROOT', dirname(__DIR__));
require PORTAL_ROOT . '/src/bootstrap.php';

use Portal\Totp;

[$_, $base, $rootTemp] = $argv + [null, null, null];
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

/** Minimal browser: cookie jar per instance, no automatic redirects. */
final class Browser
{
    public array $cookies = [];
    public ?string $bind = null; // source address (e.g. 127.0.0.5) for agent requests
    public int $status = 0;
    public array $headers = [];
    public string $body = '';

    public function __construct(private string $base)
    {
    }

    public function get(string $path, array $extraHeaders = []): self
    {
        return $this->request('GET', $path, null, $extraHeaders);
    }

    public function post(string $path, array $fields, array $extraHeaders = [], bool $withCsrf = true): self
    {
        if ($withCsrf && !isset($fields['_csrf'])) {
            $fields['_csrf'] = $this->csrf();
        }
        return $this->request('POST', $path, http_build_query($fields), $extraHeaders + ['Content-Type' => 'application/x-www-form-urlencoded']);
    }

    public function raw(string $method, string $path, ?string $body, array $headers): self
    {
        return $this->request($method, $path, $body, $headers);
    }

    public function csrf(): string
    {
        return preg_match('/name="_csrf" value="([0-9a-f]+)"/', $this->body, $m) ? $m[1] : '';
    }

    public function location(): string
    {
        return $this->headers['location'][0] ?? '';
    }

    private function request(string $method, string $path, ?string $body, array $headers): self
    {
        $ch = curl_init($this->base . $path);
        $lines = [];
        foreach ($headers as $name => $value) {
            $lines[] = "$name: $value";
        }
        if ([] !== $this->cookies) {
            $lines[] = 'Cookie: ' . implode('; ', array_map(static fn ($k, $v) => "$k=$v", array_keys($this->cookies), $this->cookies));
        }
        $this->headers = [];
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST  => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => $lines,
            CURLOPT_HEADERFUNCTION => function ($ch, string $line): int {
                if (str_contains($line, ':')) {
                    [$name, $value] = explode(':', $line, 2);
                    $this->headers[strtolower(trim($name))][] = trim($value);
                }
                return strlen($line);
            },
        ]);
        if (null !== $body) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        if (null !== $this->bind) {
            curl_setopt($ch, CURLOPT_INTERFACE, $this->bind);
        }
        $this->body = (string) curl_exec($ch);
        $this->status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        foreach ($this->headers['set-cookie'] ?? [] as $cookie) {
            [$pair] = explode(';', $cookie, 2);
            [$name, $value] = explode('=', $pair, 2);
            if ('' === $value || 'deleted' === $value) {
                unset($this->cookies[$name]);
            } else {
                $this->cookies[$name] = $value;
            }
        }
        return $this;
    }
}

function base32_decode(string $text): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (str_split(strtoupper(preg_replace('/[^A-Za-z2-7]/', '', $text))) as $char) {
        $bits .= str_pad(decbin(strpos($alphabet, $char)), 5, '0', STR_PAD_LEFT);
    }
    $out = '';
    foreach (str_split($bits, 8) as $byte) {
        if (8 === strlen($byte)) {
            $out .= chr(bindec($byte));
        }
    }
    return $out;
}

/** Wait until the next TOTP step so a fresh (never used) code is available. */
function next_code(string $secret, ?int &$lastStep): string
{
    while (null !== $lastStep && intdiv(time(), 30) <= $lastStep) {
        usleep(250_000);
    }
    $lastStep = intdiv(time(), 30);
    return Totp::code($secret, $lastStep);
}

/** Password -> enrol -> forced password change. Returns the TOTP secret. */
function first_sign_in(Browser $b, string $user, string $temp, string $newPassword, ?int &$step): string
{
    $b->get('/portal/index.php');
    $b->post('/portal/index.php?r=login', ['username' => $user, 'password' => $temp]);
    check("$user: password step redirects to enrolment", 303 === $b->status && str_contains($b->location(), 'r=enroll'), (string) $b->status);
    $b->get('/portal/index.php?r=enroll');
    check("$user: enrolment shows QR code", str_contains($b->body, 'data:image/svg+xml;base64,'));
    preg_match('/<p class="secret"><code>([A-Z2-7 ]+)<\/code>/', $b->body, $m);
    $secret = base32_decode($m[1] ?? '');
    check("$user: enrolment shows manual key", 20 === strlen($secret));
    $b->post('/portal/index.php?r=enroll', ['code' => '000000' === Totp::code($secret, intdiv(time(), 30)) ? '111111' : '000000']);
    check("$user: wrong enrolment code refused", 401 === $b->status);
    $b->post('/portal/index.php?r=enroll', ['code' => next_code($secret, $step)]);
    check("$user: enrolment completes, password change forced", 303 === $b->status && str_contains($b->location(), 'r=password'), $b->location());
    $b->get('/portal/index.php?r=dashboard');
    check("$user: other pages blocked until password changed", 303 === $b->status && str_contains($b->location(), 'r=password'));
    $b->get('/portal/index.php?r=password');
    $b->post('/portal/index.php?r=password', ['current_password' => $temp, 'new_password' => 'short', 'confirm_password' => 'short']);
    check("$user: weak password refused", 200 === $b->status && str_contains($b->body, 'at least'));
    $b->post('/portal/index.php?r=password', ['current_password' => $temp, 'new_password' => $newPassword, 'confirm_password' => $newPassword]);
    check("$user: password changed", 303 === $b->status && str_contains($b->location(), 'r=dashboard'), $b->location());
    return $secret;
}

$rootStep = null;
$helperStep = null;

// ---------------------------------------------------------------- basics
$root = new Browser($base);
$root->get('/portal/index.php');
check('login page served', 200 === $root->status && str_contains($root->body, 'name="password"'));
$csp = $root->headers['content-security-policy'][0] ?? '';
check('CSP forbids inline script and framing', str_contains($csp, "script-src 'self'") && str_contains($csp, "frame-ancestors 'none'"));
check('nosniff, DENY, no-store headers', ($root->headers['x-content-type-options'][0] ?? '') === 'nosniff'
    && ($root->headers['x-frame-options'][0] ?? '') === 'DENY' && ($root->headers['cache-control'][0] ?? '') === 'no-store');
$cookie = implode(' ', $root->headers['set-cookie'] ?? []);
check('session cookie HttpOnly + SameSite=Strict', str_contains($cookie, 'HttpOnly') && str_contains($cookie, 'SameSite=Strict'), $cookie);

$attacker = new Browser($base);
$attacker->cookies['motp_portal'] = 'attackerchosensessionid0123456789abcdef';
$attacker->get('/portal/index.php');
check('unknown session id refused (strict mode)', ($attacker->cookies['motp_portal'] ?? '') !== 'attackerchosensessionid0123456789abcdef');

$root->post('/portal/index.php?r=login', ['username' => 'root', 'password' => $rootTemp], [], false);
check('POST without CSRF token refused', 400 === $root->status);
$root->get('/portal/index.php');
$root->post('/portal/index.php?r=login', ['username' => 'root', 'password' => $rootTemp], ['Origin' => 'https://evil.example']);
check('POST from foreign origin refused', 400 === $root->status);
$root->get('/portal/index.php');
$root->post('/portal/index.php?r=login', ['username' => 'root', 'password' => 'wrong password here']);
check('wrong password refused with generic message', 401 === $root->status && str_contains($root->body, 'Sign-in failed'));
$root->post('/portal/index.php?r=login', ['username' => 'nobody', 'password' => 'whatever']);
check('unknown user gets the same message', 401 === $root->status && str_contains($root->body, 'Sign-in failed'));

// ---------------------------------------------------------------- root first sign-in
$before = $root->cookies['motp_portal'] ?? '';
$rootSecret = first_sign_in($root, 'root', $rootTemp, 'Superuser portal passphrase 2026', $rootStep);
check('session id changed after sign-in', ($root->cookies['motp_portal'] ?? '') !== $before);
$root->get('/portal/index.php?r=dashboard');
check('dashboard shows multiOTP counts', 200 === $root->status && str_contains($root->body, 'Active users') && !str_contains($root->body, 'could not be read'));
check('super admin sees Administrators menu', str_contains($root->body, 'r=admins'));

// ---------------------------------------------------------------- create helpdesk admin
$root->get('/portal/index.php?r=admin-new');
$root->post('/portal/index.php?r=admin-new', ['username' => 'helper', 'display_name' => 'Help <b>Desk</b>', 'email' => '', 'role' => 'helpdesk', 'mfa' => 'enroll']);
preg_match('/<p class="secret"><code>([A-Za-z2-9-]+)<\/code>/', $root->body, $m);
$helperTemp = $m[1] ?? '';
check('admin created, temporary password shown once', 200 === $root->status && '' !== $helperTemp);
$root->get('/portal/index.php?r=admins');
check('display name is HTML-escaped', str_contains($root->body, 'Help &lt;b&gt;Desk&lt;/b&gt;'));
check('admin list shows helper', str_contains($root->body, '>helper</a>'));
$root->post('/portal/index.php?r=admin-new', ['username' => 'helper', 'role' => 'helpdesk', 'mfa' => 'enroll']);
check('duplicate admin refused', str_contains($root->body, 'already exists'));

// self-protection
$root->get('/portal/index.php?r=admins');
$rootAdmins = $root->body;
preg_match_all('/<a href="index.php\?r=admin-edit&amp;id=([0-9a-f]{16})">([a-z]+)<\/a>/', $rootAdmins, $rows, PREG_SET_ORDER);
$ids = [];
foreach ($rows as $row) {
    $ids[$row[2]] = $row[1];
}
$root->post('/portal/index.php?r=admin-action', ['id' => $ids['root'] ?? '', 'op' => 'disable']);
$root->get('/portal/index.php?r=admins');
check('cannot disable own account', str_contains($root->body, 'cannot disable your own account'));
$root->post('/portal/index.php?r=admin-edit&id=' . ($ids['root'] ?? ''), ['display_name' => '', 'email' => '', 'role' => 'auditor', 'mfa_user' => '']);
check('last super admin keeps its role', str_contains($root->body, 'last active super administrator'));

// ---------------------------------------------------------------- helpdesk permissions
$helper = new Browser($base);
$helperSecret = first_sign_in($helper, 'helper', $helperTemp, 'Helpdesk passphrase 2026!', $helperStep);
$helper->get('/portal/index.php?r=admins');
check('helpdesk cannot open Administrators', 403 === $helper->status);
$helper->get('/portal/index.php?r=audit');
check('helpdesk cannot open audit trail', 403 === $helper->status);
$helper->get('/portal/index.php?r=dashboard');
check('helpdesk menu hides Administrators', 200 === $helper->status && !str_contains($helper->body, 'r=admins'));
$helper->post('/portal/index.php?r=admin-action', ['id' => $ids['root'] ?? '', 'op' => 'reset-password']);
check('helpdesk cannot run admin actions', 403 === $helper->status);

// ---------------------------------------------------------------- lockout and unlock
$bad = new Browser($base);
for ($i = 0; $i < 5; $i++) {
    $bad->get('/portal/index.php');
    $bad->post('/portal/index.php?r=login', ['username' => 'helper', 'password' => 'not the password ' . $i]);
}
$bad->get('/portal/index.php');
$bad->post('/portal/index.php?r=login', ['username' => 'helper', 'password' => 'Helpdesk passphrase 2026!']);
check('account locked after 5 failures, even with right password', 401 === $bad->status);
$root->get('/portal/index.php?r=admins');
check('admin list shows lock', str_contains($root->body, '>locked</span>'));
$root->post('/portal/index.php?r=admin-action', ['id' => $ids['helper'] ?? '', 'op' => 'unlock']);
check('unlock accepted', 303 === $root->status);
$bad->get('/portal/index.php');
$bad->post('/portal/index.php?r=login', ['username' => 'helper', 'password' => 'Helpdesk passphrase 2026!']);
check('unlocked account reaches MFA step', 303 === $bad->status && str_contains($bad->location(), 'r=mfa'));
$bad->get('/portal/index.php?r=mfa');
$bad->post('/portal/index.php?r=mfa', ['code' => '12345']);
check('bad MFA code refused', 401 === $bad->status);

// ---------------------------------------------------------------- session revocation
$root->get('/portal/index.php?r=admins');
$root->post('/portal/index.php?r=admin-action', ['id' => $ids['helper'] ?? '', 'op' => 'revoke-sessions']);
check('revoke accepted', 303 === $root->status);
$helper->get('/portal/index.php?r=dashboard');
check('revoked session is signed out', str_contains($helper->body, 'name="password"') && str_contains($helper->body, 'signed out because'));

// ---------------------------------------------------------------- MFA replay on second sign-in
$again = new Browser($base);
$again->get('/portal/index.php');
$again->post('/portal/index.php?r=login', ['username' => 'root', 'password' => 'Superuser portal passphrase 2026']);
check('root second sign-in reaches MFA', 303 === $again->status && str_contains($again->location(), 'r=mfa'));
$again->get('/portal/index.php?r=mfa');
$again->post('/portal/index.php?r=mfa', ['code' => Totp::code($rootSecret, (int) $rootStep)]);
check('already used TOTP code refused', 401 === $again->status);
$again->post('/portal/index.php?r=mfa', ['code' => next_code($rootSecret, $rootStep)]);
check('fresh TOTP code accepted', 303 === $again->status && str_contains($again->location(), 'r=dashboard'), $again->location());

// ---------------------------------------------------------------- audit trail
$root->get('/portal/index.php?r=audit');
check('audit trail lists actions', 200 === $root->status && str_contains($root->body, 'admin.create') && str_contains($root->body, 'auth.mfa_enrolled'));
check('audit chain verified', str_contains($root->body, 'hash chain unbroken'));
check('audit records CSRF rejection', str_contains($root->body, 'security.csrf_rejected'));
check('no password in audit page', !str_contains($root->body, $helperTemp) && !str_contains($root->body, 'Helpdesk passphrase'));
$root->get('/portal/index.php?r=audit&result=denied');
check('audit filter by result', str_contains($root->body, 'access.denied') && !str_contains($root->body, '>success<'));

// ---------------------------------------------------------------- logout
$root->get('/portal/index.php?r=dashboard');
$root->post('/portal/index.php?r=logout', []);
$root->get('/portal/index.php?r=dashboard');
check('signed out after logout', 200 === $root->status && str_contains($root->body, 'name="password"'));

// ---------------------------------------------------------------- source files not served
foreach (['/portal/src/App.php', '/portal/templates/login.php', '/portal/bin/portal-admin.php'] as $path) {
    $probe = (new Browser($base))->get($path);
    check("$path does not execute or leak", !str_contains($probe->body, 'namespace Portal') && !str_contains($probe->body, 'Sign-in') && strlen(trim($probe->body)) < 200, (string) $probe->status);
}

// ---------------------------------------------------------------- legacy multiotp.server.php fixes
$legacy = (new Browser($base))->raw('POST', '/multiotp.server.php', '{"c":"getSalt","sid":"fixedbyattacker123"}', ['Prefer' => 'api=vuejs', 'Content-Type' => 'application/json', 'Origin' => 'https://evil.example']);
check('legacy API: foreign origin gets no CORS grant', !isset($legacy->headers['access-control-allow-origin']), json_encode($legacy->headers['access-control-allow-origin'] ?? []));
check('legacy API: client-supplied sid not adopted', ($legacy->cookies['cookid'] ?? '') !== '' && ($legacy->cookies['cookid'] ?? '') !== 'fixedbyattacker123', json_encode($legacy->cookies));

// =================================================================== STAGE 2
echo "\n-- stage 2: users, tokens, directory\n";

/** The multiOTP engine's own verdict for a login (0 = accepted), as RADIUS would get it. */
function engine_check(string $user, string $code): int
{
    Portal\MultiotpService::reset();
    $engine = Portal\MultiotpService::get();
    $engine->SetUser($user);
    return (int) $engine->CheckToken($code);
}

/** Wait for a background job (run by the worker) to finish; returns its final status. */
function wait_job(Browser $b, string $id, int $timeout = 90): string
{
    $until = time() + $timeout;
    do {
        $b->get('/portal/index.php?r=job-status&id=' . $id);
        $status = json_decode($b->body, true)['status'] ?? 'unknown';
        if (!in_array($status, ['queued', 'running'], true)) {
            return $status;
        }
        usleep(500_000);
    } while (time() < $until);
    return 'timeout';
}

function job_id(Browser $b): string
{
    return preg_match('/[?&]id=([0-9]{14}-[0-9a-f]{8})/', $b->location(), $m) ? $m[1] : '';
}

$admin = $again; // root, signed in

// ---------------------------------------------------------------- local user + software token
$admin->get('/portal/index.php?r=users');
check('users page served', 200 === $admin->status && str_contains($admin->body, 'New user'));
$admin->get('/portal/index.php?r=user-new');
$admin->post('/portal/index.php?r=user-new', ['user' => 'contractor.eve', 'display_name' => 'Eve <Contractor>', 'email' => 'eve@example.test', 'token_serial' => '']);
preg_match('/<p class="secret"><code>([A-Z2-7 ]+)<\/code>/', $admin->body, $m);
$eveSecret = base32_decode($m[1] ?? '');
check('user created, enrolment QR shown once', 200 === $admin->status && str_contains($admin->body, 'data:image/svg+xml;base64,') && 20 === strlen($eveSecret));
$eveStep = intdiv(time(), 30);
check('enrolled seed works in the multiOTP engine', 0 === engine_check('contractor.eve', Totp::code($eveSecret, $eveStep)));
check('same code refused a second time (engine replay protection)', 0 !== engine_check('contractor.eve', Totp::code($eveSecret, $eveStep)));
$admin->get('/portal/index.php?r=user&u=contractor.eve');
check('user detail page escapes data', 200 === $admin->status && str_contains($admin->body, 'Eve &lt;Contractor&gt;'));
check('user detail never shows the seed', !str_contains($admin->body, trim(Totp::base32($eveSecret))));
$admin->post('/portal/index.php?r=user-new', ['user' => 'contractor.eve', 'token_serial' => '']);
check('duplicate user refused', str_contains($admin->body, 'already exists'));
$admin->post('/portal/index.php?r=user-new', ['user' => '../etc/passwd', 'token_serial' => '']);
check('invalid username refused', str_contains($admin->body, 'Usernames are'));

// recovery codes
$admin->get('/portal/index.php?r=user&u=contractor.eve');
$admin->post('/portal/index.php?r=user-action', ['u' => 'contractor.eve', 'op' => 'recovery-codes']);
preg_match_all('/<li><code>(\d{4}) (\d{4})<\/code><\/li>/', $admin->body, $codes, PREG_SET_ORDER);
check('10 recovery codes shown', 10 === count($codes));
$recovery = ($codes[0][1] ?? '') . ($codes[0][2] ?? '');
check('recovery code accepted by the engine', 0 === engine_check('contractor.eve', $recovery));
check('recovery code is single use', 0 !== engine_check('contractor.eve', $recovery));

// disable / enable / unlock
$admin->get('/portal/index.php?r=user&u=contractor.eve');
$admin->post('/portal/index.php?r=user-action', ['u' => 'contractor.eve', 'op' => 'disable']);
$fresh = next_code($eveSecret, $eveStep);
check('disabled user refused by the engine', 0 !== engine_check('contractor.eve', $fresh));
$admin->get('/portal/index.php?r=user&u=contractor.eve');
$admin->post('/portal/index.php?r=user-action', ['u' => 'contractor.eve', 'op' => 'enable']);
Portal\MultiotpService::reset();
Portal\MultiotpService::get()->LockUser('contractor.eve');
$admin->get('/portal/index.php?r=users&status=locked');
check('locked filter lists the locked user', str_contains($admin->body, '>contractor.eve</a>'));
$admin->get('/portal/index.php?r=user&u=contractor.eve');
$admin->post('/portal/index.php?r=user-action', ['u' => 'contractor.eve', 'op' => 'unlock']);
check('unlocked user accepted again', 0 === engine_check('contractor.eve', next_code($eveSecret, $eveStep)));

// edit
$admin->get('/portal/index.php?r=user&u=contractor.eve');
$admin->post('/portal/index.php?r=user-action', ['u' => 'contractor.eve', 'op' => 'save', 'display_name' => 'Eve Example', 'email' => 'eve@example.test', 'sms' => '', 'description' => 'Contractor', 'group' => '']);
$admin->get('/portal/index.php?r=user&u=contractor.eve');
check('user edited', str_contains($admin->body, 'value="Eve Example"'));

// ---------------------------------------------------------------- hardware tokens
$admin->get('/portal/index.php?r=tokens');
check('tokens page served', 200 === $admin->status && str_contains($admin->body, 'Import tokens'));
$csv = sys_get_temp_dir() . '/tokens-' . getmypid() . '.csv';
copy(PORTAL_ROOT . '/../oath/test-tokens.csv', $csv);
$ch = curl_init($base . '/portal/index.php?r=token-import');
curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true,
    CURLOPT_HTTPHEADER => ['Cookie: ' . implode('; ', array_map(static fn ($k, $v) => "$k=$v", array_keys($admin->cookies), $admin->cookies))],
    CURLOPT_POSTFIELDS => ['_csrf' => $admin->csrf(), 'password' => '', 'token_file' => new CURLFile($csv, 'text/csv', 'test-tokens.csv')]]);
curl_exec($ch);
$admin->get('/portal/index.php?r=tokens');
preg_match_all('/<td><code>([^<]+)<\/code><\/td>/', $admin->body, $serials);
check('token file imported', count($serials[1]) >= 1, (string) count($serials[1]));
$serial = $serials[1][0] ?? '';
$admin->get('/portal/index.php?r=user&u=contractor.eve');
$admin->post('/portal/index.php?r=user-action', ['u' => 'contractor.eve', 'op' => 'assign-token', 'serial' => $serial]);
$admin->get('/portal/index.php?r=user&u=contractor.eve');
check('hardware token assigned', str_contains($admin->body, 'Hardware token <code>' . e($serial)));
$admin->get('/portal/index.php?r=tokens');
$admin->post('/portal/index.php?r=token-action', ['op' => 'delete', 'serial' => $serial]);
$admin->get('/portal/index.php?r=tokens');
check('assigned token cannot be deleted', str_contains($admin->body, 'Remove it from the user first'));
$admin->get('/portal/index.php?r=user&u=contractor.eve');
$admin->post('/portal/index.php?r=user-action', ['u' => 'contractor.eve', 'op' => 'remove-token']);
$admin->get('/portal/index.php?r=user&u=contractor.eve');
check('hardware token removed', str_contains($admin->body, 'Software (TOTP)'));

// ---------------------------------------------------------------- bulk
$admin->get('/portal/index.php?r=user-new');
$admin->post('/portal/index.php?r=user-new', ['user' => 'temp.one', 'token_serial' => '']);
$admin->get('/portal/index.php?r=users');
$admin->post('/portal/index.php?r=user-bulk', ['op' => 'disable', 'users' => ['temp.one', 'contractor.eve']]);
$admin->get('/portal/index.php?r=users&status=disabled');
check('bulk disable', str_contains($admin->body, '>temp.one</a>') && str_contains($admin->body, '>contractor.eve</a>'));
$admin->post('/portal/index.php?r=user-bulk', ['op' => 'delete', 'users' => ['temp.one']]);
$admin->get('/portal/index.php?r=users');
check('bulk delete', !str_contains($admin->body, '>temp.one</a>'));

// ---------------------------------------------------------------- directory settings
$directoryForm = [
    'enabled' => '1', 'server_type' => '2', 'domain_controllers' => 'ldap', 'port' => '389', 'network_timeout' => '5',
    'tls_reqcert' => 'never', 'base_dn' => 'dc=example,dc=test', 'users_dn' => 'ou=people,dc=example,dc=test',
    'bind_dn' => 'cn=multiotp-sync,ou=service,dc=example,dc=test',
    'account_suffix' => '', 'in_groups' => '', 'ldap_filter' => '', 'without2fa_groups' => '', 'cn_identifier' => '',
    'group_attribute' => '', 'group_cn_identifier' => '', 'synced_user_attribute' => '', 'language_attribute' => '',
    'default_algorithm' => 'totp', 'delete_retention_days' => '30', 'schedule_minutes' => '60',
];
$admin->get('/portal/index.php?r=directory');
check('directory page served', 200 === $admin->status && str_contains($admin->body, 'Test connection'));
$admin->post('/portal/index.php?r=directory-save', ['bind_password' => 'wrong-password'] + $directoryForm);
check('directory settings saved', 303 === $admin->status);
$admin->get('/portal/index.php?r=directory');
$admin->post('/portal/index.php?r=directory-test', []);
check('wrong service password: test fails', str_contains($admin->body, 'alert-error') && str_contains($admin->body, 'bind failed'));
$admin->get('/portal/index.php?r=directory');
$admin->post('/portal/index.php?r=directory-save', ['bind_password' => 'sync-test-password'] + $directoryForm);
$admin->get('/portal/index.php?r=directory');
check('password field never echoes the password', !str_contains($admin->body, 'sync-test-password') && str_contains($admin->body, 'Stored encrypted'));
$admin->post('/portal/index.php?r=directory-test', []);
check('test connection succeeds', str_contains($admin->body, 'Connected and authenticated'));
$config = implode('', array_map('file_get_contents', glob(getenv('MULTIOTP_ETC_DIR') . '/config/*') ?: []));
check('service password not in multiOTP config', '' !== $config && !str_contains($config, 'sync-test-password'));
check('service password not in portal files in clear', !str_contains((string) file_get_contents(Portal\Config::dataDir() . '/directory.json'), 'sync-test'));

// preview through the worker
$admin->get('/portal/index.php?r=directory');
$admin->post('/portal/index.php?r=directory-run', ['op' => 'preview']);
$previewId = job_id($admin);
check('preview queued', '' !== $previewId, $admin->location());
check('preview finished in the worker', 'succeeded' === wait_job($admin, $previewId));
$admin->get('/portal/index.php?r=job&id=' . $previewId);
check('preview shows 4 users to create, nothing changed', str_contains($admin->body, '4 user(s) found') && str_contains($admin->body, '<td>alice</td>'));
$admin->get('/portal/index.php?r=users&status=synced');
check('preview did not create users', !str_contains($admin->body, '>alice</a>'));

// sync through the worker
$admin->get('/portal/index.php?r=directory');
$admin->post('/portal/index.php?r=directory-run', ['op' => 'sync']);
$syncId = job_id($admin);
check('sync finished in the worker', 'succeeded' === wait_job($admin, $syncId));
$admin->get('/portal/index.php?r=job&id=' . $syncId);
check('sync result lists created users', str_contains($admin->body, '<strong>Created:</strong> alice, bob, carol, dave'), strip_tags(substr($admin->body, strpos($admin->body, 'Created') ?: 0, 200)));
$admin->get('/portal/index.php?r=users&status=synced');
check('synced users listed as from directory', str_contains($admin->body, '>alice</a>') && str_contains($admin->body, '>dave</a>'));
$admin->get('/portal/index.php?r=user&u=alice');
check('synced user shows its DN', str_contains($admin->body, 'uid=alice,ou=people,dc=example,dc=test'));

// group lists crash the engine with generic LDAP: the portal refuses them
$admin->get('/portal/index.php?r=directory');
$admin->post('/portal/index.php?r=directory-save', ['in_groups' => 'mfa-users'] + $directoryForm);
check('group list refused for generic LDAP', 200 === $admin->status && str_contains($admin->body, 'only supported for Active Directory'));

// narrow the scope to the mfa-users group: dave leaves the scope and must be disabled
$admin->get('/portal/index.php?r=directory');
$admin->post('/portal/index.php?r=directory-save', ['ldap_filter' => '(&(objectClass=posixAccount)({cn_identifier}={username})(memberOf=cn=mfa-users,ou=groups,dc=example,dc=test))'] + $directoryForm);
$admin->get('/portal/index.php?r=directory');
$admin->post('/portal/index.php?r=directory-run', ['op' => 'sync']);
$syncId = job_id($admin);
check('second sync finished', 'succeeded' === wait_job($admin, $syncId));
$admin->get('/portal/index.php?r=job&id=' . $syncId);
check('user out of scope disabled', str_contains($admin->body, '<strong>Disabled:</strong> dave'));
Portal\MultiotpService::reset();
check('engine agrees dave is disabled', 0 === (int) Portal\MultiotpService::get()->GetUserActivated('dave'));
$admin->get('/portal/index.php?r=directory');
check('directory page shows last sync', str_contains($admin->body, '1 disabled'));
$admin->get('/portal/index.php?r=dashboard');
check('dashboard shows directory sync', str_contains($admin->body, 'Directory synchronisation') && str_contains($admin->body, 'manual only'));

// ---------------------------------------------------------------- helpdesk limits on stage 2 pages
$help = new Browser($base);
$help->get('/portal/index.php');
$help->post('/portal/index.php?r=login', ['username' => 'helper', 'password' => 'Helpdesk passphrase 2026!']);
$help->get('/portal/index.php?r=mfa');
$help->post('/portal/index.php?r=mfa', ['code' => next_code($helperSecret, $helperStep)]);
check('helpdesk signed in again', 303 === $help->status && str_contains($help->location(), 'r=dashboard'), $help->location());
$help->get('/portal/index.php?r=users');
check('helpdesk sees users, no create, no bulk delete', 200 === $help->status && !str_contains($help->body, 'New user') && !str_contains($help->body, 'value="delete"') && str_contains($help->body, 'value="unlock"'));
$help->get('/portal/index.php?r=user-new');
check('helpdesk cannot create users', 403 === $help->status);
$help->get('/portal/index.php?r=user&u=alice');
check('helpdesk can enrol and resync, not delete', str_contains($help->body, 'Enrol new authenticator') && str_contains($help->body, 'Resync token') && !str_contains($help->body, 'Delete user'));
$help->post('/portal/index.php?r=user-action', ['u' => 'alice', 'op' => 'delete']);
check('helpdesk delete refused', 403 === $help->status);
$help->get('/portal/index.php?r=directory');
check('helpdesk has no directory access', 403 === $help->status);
$help->get('/portal/index.php?r=job-status&id=' . $syncId);
check('helpdesk cannot read job status', 403 === $help->status);

// ---------------------------------------------------------------- audit
$auditText = (string) file_get_contents(Portal\Config::auditFile());
foreach (['user.create', 'user.recovery_codes', 'user.token_assigned', 'token.import', 'directory.settings_update', 'directory.test', 'directory.sync', 'directory.preview'] as $action) {
    check("audit has $action", str_contains($auditText, '"action":"' . $action . '"'));
}
check('audit never contains seeds, codes or the service password', !str_contains($auditText, trim(Totp::base32($eveSecret))) && !str_contains($auditText, $recovery) && !str_contains($auditText, 'sync-test-password'));
check('audit records the scheduler or admin as sync actor', str_contains($auditText, '"actor":"root","role":"","ip":"local","action":"directory.sync"'));


// =================================================================== STAGE 3
echo "\n-- stage 3: RADIUS servers, groups, login formats\n";

$admin->get('/portal/index.php?r=radius');
check('RADIUS page served', 200 === $admin->status && str_contains($admin->body, 'Server groups'));
$admin->get('/portal/index.php?r=radius-client');
check('adding a server without a group redirects to group creation', 303 === $admin->status && str_contains($admin->location(), 'r=radius-group'));
$admin->get('/portal/index.php?r=radius-group');
$admin->post('/portal/index.php?r=radius-group', ['name' => 'VPN gateways', 'description' => '<b>Remote</b> access', 'challenge_response' => '1', 'text_token_challenge' => 'Code?', 'cache_timeout' => '3600']);
check('server group created', 303 === $admin->status);
$admin->get('/portal/index.php?r=radius');
check('group listed and escaped', str_contains($admin->body, 'VPN gateways') && str_contains($admin->body, '&lt;b&gt;Remote&lt;/b&gt; access') && str_contains($admin->body, 'Challenge-response'));
preg_match('/r=radius-client&amp;group=([0-9a-f]{12})/', $admin->body, $m);
$groupId = $m[1] ?? '';
$admin->get('/portal/index.php?r=radius-client&group=' . $groupId);
$admin->post('/portal/index.php?r=radius-client', ['name' => 'fw-paris', 'description' => 'Paris firewall', 'address' => '192.0.2.10', 'group_id' => $groupId, 'nas_type' => 'other', 'require_message_authenticator' => '1', 'secret' => '']);
preg_match('/<p class="secret"><code>([A-Za-z0-9]{24})<\/code>/', $admin->body, $m);
$fwSecret = $m[1] ?? '';
check('server added, secret shown once', '' !== $fwSecret);
$admin->get('/portal/index.php?r=radius');
check('server listed, secret not shown again', str_contains($admin->body, '192.0.2.10/32') && !str_contains($admin->body, $fwSecret));
check('pending changes banner', str_contains($admin->body, 'not yet active on FreeRADIUS'));
$admin->post('/portal/index.php?r=radius-client', ['name' => 'fw-bad', 'address' => '0.0.0.0/0', 'group_id' => $groupId, 'nas_type' => 'other', 'secret' => '']);
check('catch-all address refused', str_contains($admin->body, 'larger than /8'));
$admin->get('/portal/index.php?r=radius-client');
$admin->post('/portal/index.php?r=radius-client', ['name' => 'fw-quote', 'address' => '192.0.2.11', 'group_id' => $groupId, 'nas_type' => 'other', 'secret' => 'abcdefghijklmnop"; exec'] );
check('unsafe custom secret refused', str_contains($admin->body, 'Custom secrets need'));
$admin->get('/portal/index.php?r=radius');
$admin->post('/portal/index.php?r=radius-apply', []);
$applyId = job_id($admin);
check('apply runs in the worker', in_array(wait_job($admin, $applyId), ['succeeded', 'failed'], true));
$admin->get('/portal/index.php?r=job&id=' . $applyId);
check('apply without FreeRADIUS reports the missing helper', str_contains($admin->body, 'helper is not available') || str_contains($admin->body, 'Finished'));
$admin->get('/portal/index.php?r=radius-diagnostics');
check('diagnostics page served', 200 === $admin->status && str_contains($admin->body, 'Test login'));
$help->get('/portal/index.php?r=radius');
check('helpdesk has no RADIUS access', 403 === $help->status);
$auditText = (string) file_get_contents(Portal\Config::auditFile());
check('audit has RADIUS changes, never the secret', str_contains($auditText, '"action":"radius.client_create"') && str_contains($auditText, '"action":"radius.group_create"') && !str_contains($auditText, $fwSecret));

// Symantec VIP migration: settings, server group switch, users moved (FreeRADIUS itself: appliance-vip.php)
$admin->get('/portal/index.php?r=radius-vip');
check('Symantec VIP page served', 200 === $admin->status && str_contains($admin->body, 'Symantec VIP Enterprise Gateway') && str_contains($admin->body, 'Not configured'));
$admin->post('/portal/index.php?r=radius-vip', ['op' => 'save', 'address_1' => '192.0.2.70', 'port_1' => '1812', 'secret_1' => 'Vip"broken', 'response_window' => '15', 'message_authenticator' => 'auto']);
check('Symantec VIP: invalid secret refused, address kept in the form, secret not echoed', 200 === $admin->status && str_contains($admin->body, 'shared secret needs') && str_contains($admin->body, 'value="192.0.2.70"') && !str_contains($admin->body, 'Vip"broken') && !str_contains($admin->body, 'Vip&quot;broken'));
$admin->post('/portal/index.php?r=radius-vip', ['op' => 'save', 'address_1' => '192.0.2.70', 'port_1' => '1812', 'secret_1' => 'E2e-Vip-Secret-778899', 'response_window' => '5', 'message_authenticator' => 'auto']);
check('Symantec VIP servers saved', 303 === $admin->status);
$admin->get('/portal/index.php?r=radius');
check('RADIUS page shows Symantec VIP not applied yet', str_contains($admin->body, '192.0.2.70:1812') && str_contains($admin->body, 'not applied yet'));
$admin->get('/portal/index.php?r=radius-group&id=' . $groupId);
check('server group page offers forwarding and the user group restriction', str_contains($admin->body, 'name="vip_forward"') && str_contains($admin->body, 'name="allowed_groups"'));
$admin->post('/portal/index.php?r=radius-group&id=' . $groupId, ['name' => 'VPN gateways', 'description' => '<b>Remote</b> access', 'challenge_response' => '1', 'text_token_challenge' => 'Code?', 'cache_timeout' => '3600', 'vip_forward' => '1']);
check('forwarding switched on for a server group', 303 === $admin->status);
$seedJob = Portal\Jobs::latest('radius.vip_seed');
check('first forwarding: users already on SohobOTP are found in the worker', null !== $seedJob && 'succeeded' === wait_job($admin, $seedJob['id']));
$admin->get('/portal/index.php?r=users');
$admin->post('/portal/index.php?r=user-bulk', ['op' => 'to-vip', 'users' => ['bob', 'carol']]);
check('bulk: sent back to Symantec VIP', 303 === $admin->status && 'vip' === ((new Portal\VipMigration())->stateOf('bob')['state'] ?? '') && 'vip' === ((new Portal\VipMigration())->stateOf('carol')['state'] ?? ''));
$admin->get('/portal/index.php?r=users');
check('bulk menu offers the migration actions', str_contains($admin->body, 'Move to SohobOTP (Symantec VIP migration)'));
$admin->get('/portal/index.php?r=user&u=bob');
check('user page: still on Symantec VIP, with a move button', str_contains($admin->body, 'Still on Symantec VIP') && str_contains($admin->body, 'VPN gateways') && str_contains($admin->body, 'Move to SohobOTP'));
$admin->post('/portal/index.php?r=user-action', ['u' => 'bob', 'op' => 'vip-route', 'route' => 'sohobotp']);
$admin->get('/portal/index.php?r=user&u=bob');
check('user moved to SohobOTP', str_contains($admin->body, 'On SohobOTP') && str_contains($admin->body, 'Send back to Symantec VIP'));
$help->get('/portal/index.php?r=radius-vip');
check('helpdesk cannot open the Symantec VIP settings', 403 === $help->status);
$help->get('/portal/index.php?r=user&u=bob');
$help->post('/portal/index.php?r=user-action', ['u' => 'bob', 'op' => 'vip-route', 'route' => 'vip']);
check('helpdesk cannot move users between Symantec VIP and SohobOTP', 403 === $help->status && 'sohobotp' === ((new Portal\VipMigration())->stateOf('bob')['state'] ?? ''));
$admin->get('/portal/index.php?r=radius-vip');
$admin->post('/portal/index.php?r=radius-vip', ['op' => 'test', 'server' => '1', 'user' => 'nobody', 'password' => 'x']);
check('Symantec VIP test login reports an unreachable gateway', 200 === $admin->status && (str_contains($admin->body, 'timeout') || str_contains($admin->body, 'error')));
$auditText = (string) file_get_contents(Portal\Config::auditFile());
check('audit: Symantec VIP settings and moves recorded, never the secret', str_contains($auditText, '"action":"radius.vip_save"') && str_contains($auditText, '"action":"user.vip_route"') && !str_contains($auditText, 'E2e-Vip-Secret-778899'));
$admin->get('/portal/index.php?r=radius-group&id=' . $groupId);
$admin->post('/portal/index.php?r=radius-group&id=' . $groupId, ['name' => 'VPN gateways', 'description' => '<b>Remote</b> access', 'challenge_response' => '1', 'text_token_challenge' => 'Code?', 'cache_timeout' => '3600']);

// per-user login format: PIN + code for a local user
$admin->get('/portal/index.php?r=user&u=contractor.eve');
$admin->post('/portal/index.php?r=user-action', ['u' => 'contractor.eve', 'op' => 'enable']);
// removing the hardware token earlier gave eve a new seed: enrol again to know it
$admin->get('/portal/index.php?r=user&u=contractor.eve');
$admin->post('/portal/index.php?r=user-action', ['u' => 'contractor.eve', 'op' => 'enroll']);
preg_match('/<p class="secret"><code>([A-Z2-7 ]+)<\/code>/', $admin->body, $m);
$eveSecret = base32_decode($m[1] ?? '');
$eveStep = null;
$admin->get('/portal/index.php?r=user&u=contractor.eve');
$admin->post('/portal/index.php?r=user-action', ['u' => 'contractor.eve', 'op' => 'login-format', 'format' => 'pin']);
preg_match('/<p class="secret"><code>(\d{6})<\/code>/', $admin->body, $m);
$evePin = $m[1] ?? '';
check('PIN shown once', '' !== $evePin);
$code = next_code($eveSecret, $eveStep);
check('code alone refused when a PIN is required', 0 !== engine_check('contractor.eve', $code));
check('PIN + code accepted', 0 === engine_check('contractor.eve', $evePin . next_code($eveSecret, $eveStep)));
$admin->get('/portal/index.php?r=user&u=contractor.eve');
$admin->post('/portal/index.php?r=user-action', ['u' => 'contractor.eve', 'op' => 'login-format', 'format' => 'directory']);
$admin->get('/portal/index.php?r=user&u=contractor.eve');
check('directory format refused for a local user', str_contains($admin->body, 'Only users synchronised from the directory'));

// directory password + code for a synced user
$admin->post('/portal/index.php?r=user-action', ['u' => 'alice', 'op' => 'enroll']);
preg_match('/<p class="secret"><code>([A-Z2-7 ]+)<\/code>/', $admin->body, $m);
$aliceSecret = base32_decode($m[1] ?? '');
$aliceStep = null;
$admin->get('/portal/index.php?r=user&u=alice');
$admin->post('/portal/index.php?r=user-action', ['u' => 'alice', 'op' => 'login-format', 'format' => 'directory']);
$admin->get('/portal/index.php?r=user&u=alice');
check('directory format set for synced user', str_contains($admin->body, '<option value="directory" selected'));
$directoryResult = engine_check('alice', 'alice-test-password' . next_code($aliceSecret, $aliceStep));
check('directory password + code accepted (generic LDAP)', 0 === $directoryResult, 'engine result ' . $directoryResult);
check('wrong directory password refused', 0 !== engine_check('alice', 'wrong-password' . next_code($aliceSecret, $aliceStep)));

// ---------------------------------------------------------------- stage 4: endpoints, enrolment, agent API
require __DIR__ . '/AgentSim.php';
$admin->get('/portal/index.php?r=endpoints');
check('endpoints page served, empty', 200 === $admin->status && str_contains($admin->body, 'No endpoints yet'));
$admin->get('/portal/index.php?r=endpoint-enrol');
check('enrolment without a group redirects to group creation', 303 === $admin->status && str_contains($admin->location(), 'r=endpoint-group'));
$radiusGroupId = '';
foreach ((new Portal\Radius())->groups() as $g) {
    $radiusGroupId = 'VPN gateways' === $g['name'] ? $g['id'] : $radiusGroupId;
}
$admin->get('/portal/index.php?r=endpoint-group');
$groupForm = [
    'name' => 'Linux servers', 'description' => '<i>ops</i> machines', 'checkin_interval' => '60',
    'linux_enabled' => '1', 'linux_radius_group_id' => $radiusGroupId, 'linux_radius_servers' => 'radius.example.test',
    'linux_timeout' => '5', 'linux_services' => ['sshd', 'sudo'], 'linux_excluded_users' => '', 'linux_excluded_groups' => 'mfa-breakglass',
    'linux_ssh_keys_need_code' => '1', 'win_cpus_logon' => '0e', 'win_cpus_unlock' => '0e', 'win_cpus_credui' => '0e',
    'win_excluded_account' => '', 'win_cache_days' => '7', 'win_timeout_unlock' => '0', 'win_server_timeout' => '5',
];
$admin->post('/portal/index.php?r=endpoint-group', ['linux_radius_group_id' => ''] + $groupForm);
check('group without RADIUS group refused with a message', 200 === $admin->status && str_contains($admin->body, 'Choose the RADIUS server group'));
$admin->post('/portal/index.php?r=endpoint-group', $groupForm);
check('endpoint group created', 303 === $admin->status && str_contains($admin->location(), 'r=endpoint-groups'));
$admin->get('/portal/index.php?r=endpoint-groups');
check('group list escapes the description', str_contains($admin->body, '&lt;i&gt;ops&lt;/i&gt;') && !str_contains($admin->body, '<i>ops</i>'));
preg_match('/r=endpoint-group&amp;id=([0-9a-f]{12})/', $admin->body, $m);
$endpointGroupId = $m[1] ?? '';
$admin->get('/portal/index.php?r=endpoint-enrol');
$pinShown = preg_match('/Portal key pin[^<]*<code>([0-9a-f ]+)<\/code>/', $admin->body, $m) ? str_replace(' ', '', $m[1]) : '';
$admin->post('/portal/index.php?r=endpoint-enrol', ['op' => 'create', 'group_id' => $endpointGroupId, 'label' => 'e2e rollout', 'hours' => '1', 'max_uses' => '2']);
preg_match('/<p class="secret"><code>([0-9a-f]{12}\.[A-Za-z0-9_-]{32})<\/code>/', $admin->body, $m);
$enrolToken = $m[1] ?? '';
check('enrolment token shown once with install commands', '' !== $enrolToken && str_contains($admin->body, 'sohobotp-agent install --portal') && str_contains($admin->body, '--pin ' . $pinShown));

$agentHttp = new Browser($base);
$agentHttp->bind = '127.0.0.5';
$agentCall = static function (string $action, array $request, ?AgentSim $signer = null) use ($agentHttp): array {
    $body = json_encode($request);
    $uri = '/portal/agent.php?a=' . $action;
    $headers = ['Content-Type' => 'application/json'];
    if (null !== $signer) {
        foreach ($signer->headers('POST', $uri, $body) as $name => $value) {
            $headers[$name] = $value;
        }
    }
    $agentHttp->raw('POST', $uri, $body, $headers);
    return json_decode($agentHttp->body, true) ?? [];
};
$agentHttp->get('/portal/agent.php?a=enroll');
check('agent API refuses GET', 405 === $agentHttp->status);
$linux = new AgentSim();
$inventory = ['hostname' => 'web-01', 'os' => 'linux', 'os_name' => 'Debian GNU/Linux', 'os_version' => '12', 'ips' => ['127.0.0.5'], 'agent_version' => '0.1.0', 'component' => ['name' => 'pam_radius', 'version' => '2.0.0']];
$reply = $agentCall('enroll', $linux->enrollRequest(substr($enrolToken, 0, 13) . str_repeat('x', 32), $inventory));
check('agent API: wrong token refused', 401 === $agentHttp->status && 'bad_token' === ($reply['error'] ?? ''));
$reply = $agentCall('enroll', $linux->enrollRequest($enrolToken, $inventory));
$linux->id = $reply['endpoint_id'] ?? null;
$portalKeyHttp = (string) base64_decode((string) ($reply['portal_key'] ?? ''), true);
check('agent API: enrolment accepted', 200 === $agentHttp->status && null !== $linux->id, $agentHttp->body);
check('agent API: portal key matches the pin shown to the admin', hash('sha256', $portalKeyHttp) === $pinShown);
$reply = $agentCall('checkin', ['inventory' => $inventory, 'applied' => ['version' => 0, 'status' => 'none', 'error' => '', 'at' => null]], $linux);
$pushed = null;
try {
    $pushed = $linux->openConfig($reply['config'] ?? [], $portalKeyHttp, 0, 'linux');
} catch (Throwable $error) {
    check('agent API: config opens', false, $error->getMessage() . ' ' . $agentHttp->body);
}
$endpointRecord = (new Portal\Endpoints())->endpoint((string) $linux->id);
$linuxClient = (new Portal\Radius())->client((string) ($endpointRecord['radius_client_id'] ?? ''));
check('agent API: signed check-in returns the config', null !== $pushed && [['host' => 'radius.example.test', 'port' => 1812]] === $pushed['policy']['radius_servers']);
check('agent API: endpoint became RADIUS client at its address', null !== $linuxClient && '127.0.0.5/32' === $linuxClient['address']);
check('agent API: RADIUS secret delivered sealed', null !== $pushed && $pushed['secrets']['radius_secret'] === (new Portal\Radius())->clientSecret($linuxClient['id'] ?? ''));
$body = json_encode(['applied' => ['version' => 1, 'status' => 'applied', 'error' => '', 'at' => time()]]);
$replayHeaders = ['Content-Type' => 'application/json'] + $linux->headers('POST', '/portal/agent.php?a=checkin', $body);
$agentHttp->raw('POST', '/portal/agent.php?a=checkin', $body, $replayHeaders);
$checkinReply = json_decode($agentHttp->body, true) ?? [];
check('agent API: applied config not resent', 200 === $agentHttp->status && array_key_exists('config', $checkinReply) && null === $checkinReply['config'], $agentHttp->body);
$agentHttp->raw('POST', '/portal/agent.php?a=checkin', $body, $replayHeaders);
check('agent API: replayed request refused', 401 === $agentHttp->status && str_contains($agentHttp->body, 'replay'));
$agentHttp->raw('POST', '/portal/agent.php?a=checkin', $body . ' ', $linux->headers('POST', '/portal/agent.php?a=checkin', $body) + ['Content-Type' => 'application/json']);
check('agent API: tampered body refused', 401 === $agentHttp->status && str_contains($agentHttp->body, 'bad_signature'));

$windows = new AgentSim();
$windowsInventory = ['hostname' => '<b>PC-07</b>', 'os' => 'windows', 'os_name' => 'Windows 11 Pro', 'domain' => 'EXAMPLE', 'component' => ['name' => 'multiotp-cp', 'version' => '5.10.4.1']];
$windows->id = $agentCall('enroll', $windows->enrollRequest($enrolToken, $windowsInventory))['endpoint_id'] ?? null;
check('agent API: second machine enrolled with the same token (2 uses)', null !== $windows->id);
$reply = $agentCall('enroll', (new AgentSim())->enrollRequest($enrolToken, $windowsInventory));
check('agent API: token used up after 2 machines', 'bad_token' === ($reply['error'] ?? ''));

$admin->get('/portal/index.php?r=endpoints');
check('endpoint list shows machines, host names escaped', str_contains($admin->body, 'web-01') && str_contains($admin->body, '&lt;b&gt;PC-07&lt;/b&gt;') && !str_contains($admin->body, '<b>PC-07</b>'));
$admin->get('/portal/index.php?r=endpoint&id=' . $linux->id);
check('endpoint page shows inventory and RADIUS client', 200 === $admin->status && str_contains($admin->body, 'Debian GNU/Linux') && str_contains($admin->body, '127.0.0.5/32'));
$admin->post('/portal/index.php?r=endpoint&id=' . $linux->id, ['op' => 'disable']);
$reply = $agentCall('checkin', ['applied' => ['version' => 1, 'status' => 'applied', 'error' => '', 'at' => time()]], $linux);
check('disabled endpoint refused by the API', 403 === $agentHttp->status && 'disabled' === ($reply['error'] ?? ''));
check('disabled endpoint lost its RADIUS client', null === (new Portal\Radius())->client($linuxClient['id'] ?? ''));
$help->get('/portal/index.php?r=endpoints');
check('helpdesk has no endpoint access', 403 === $help->status);
$auditText = (string) file_get_contents(Portal\Config::auditFile());
check('audit has enrolment and token events, never the token or secrets', str_contains($auditText, '"action":"endpoint.enroll"') && str_contains($auditText, '"action":"endpoint.token_create"')
    && str_contains($auditText, '"action":"endpoint.disable"') && !str_contains($auditText, substr($enrolToken, 13)) && !str_contains($auditText, (string) ($pushed['secrets']['radius_secret'] ?? 'no-secret')));

// ---------------------------------------------------------------- stage 4: approval of new machines, AD rules page
$admin->get('/portal/index.php?r=endpoint-enrol');
check('enrol page offers approval modes', str_contains($admin->body, 'name="approval"') && str_contains($admin->body, 'value="directory" selected'));
$admin->post('/portal/index.php?r=endpoint-enrol', ['op' => 'create', 'group_id' => $endpointGroupId, 'label' => 'needs approval', 'hours' => '1', 'max_uses' => '1', 'approval' => 'manual']);
preg_match('/<p class="secret"><code>([0-9a-f]{12}\.[A-Za-z0-9_-]{32})<\/code>/', $admin->body, $m);
$approvalToken = $m[1] ?? '';
$waiting = new AgentSim();
$agentHttp->bind = '127.0.0.7';
$waiting->id = $agentCall('enroll', $waiting->enrollRequest($approvalToken, ['hostname' => 'new-laptop', 'os' => 'linux']))['endpoint_id'] ?? null;
$reply = $agentCall('checkin', ['inventory' => ['hostname' => 'new-laptop', 'os' => 'linux'], 'applied' => ['version' => 0, 'status' => 'none', 'error' => '', 'at' => null]], $waiting);
check('machine from an approval token waits: no configuration', 200 === $agentHttp->status && 'pending' === ($reply['state'] ?? '') && array_key_exists('config', $reply) && null === $reply['config'], $agentHttp->body);
$admin->get('/portal/index.php?r=endpoints');
check('endpoint list shows the machine waiting for approval', str_contains($admin->body, 'Waiting for approval') && str_contains($admin->body, 'new-laptop'));
$admin->get('/portal/index.php?r=endpoint&id=' . $waiting->id);
check('endpoint page offers approve and reject', str_contains($admin->body, 'Approve this machine?') && str_contains($admin->body, 'value="approve"'));
$admin->post('/portal/index.php?r=endpoint&id=' . $waiting->id, ['op' => 'approve']);
$reply = $agentCall('checkin', ['applied' => ['version' => 0, 'status' => 'none', 'error' => '', 'at' => null]], $waiting);
check('approved machine gets its configuration', 'active' === ($reply['state'] ?? '') && is_array($reply['config'] ?? null), $agentHttp->body);
$admin->get('/portal/index.php?r=endpoint-groups');
check('AD rules section shown, AD not configured hint', str_contains($admin->body, 'Assignment from Active Directory') && str_contains($admin->body, 'Configure Active Directory'));
$admin->post('/portal/index.php?r=endpoint-rules', ['op' => 'add', 'type' => 'ou', 'value' => 'OU=Laptops,DC=example,DC=test', 'group_id' => $endpointGroupId]);
$admin->get('/portal/index.php?r=endpoint-groups');
check('AD rule added and listed', str_contains($admin->body, 'OU=Laptops,DC=example,DC=test'));
$help->post('/portal/index.php?r=endpoint-rules', ['op' => 'add', 'type' => 'ou', 'value' => 'OU=Evil,DC=example,DC=test', 'group_id' => $endpointGroupId]);
check('helpdesk cannot add AD rules', 403 === $help->status);
$auditText = (string) file_get_contents(Portal\Config::auditFile());
check('audit has approval and rule events', str_contains($auditText, '"action":"endpoint.approve"') && str_contains($auditText, '"action":"endpoint.rule_add"'));

// ---------------------------------------------------------------- stage 4c: Credential Provider gateway (portal/cp.php)
// The CP's own client is the multiOTP engine in client mode: a second engine with its own
// folders plays the Windows machine.
$winReply = $agentCall('checkin', ['inventory' => $windowsInventory, 'applied' => ['version' => 0, 'status' => 'none', 'error' => '', 'at' => null]], $windows);
$winConfig = null;
try {
    $winConfig = $windows->openConfig($winReply['config'] ?? [], $portalKeyHttp, 0, 'windows');
} catch (Throwable $error) {
    check('Windows config opens', false, $error->getMessage() . ' ' . $agentHttp->body);
}
$gatewayUrl = str_replace('https://', 'http://', (string) ($winConfig['policy']['server_url'] ?? ''));
check('Windows config points the CP at its own gateway URL', str_contains($gatewayUrl, '/portal/cp.php?e=' . $windows->id));
$cpUsers = new Portal\Users();
$cpCreated = $cpUsers->create(['user' => 'cp.tester', 'display_name' => 'CP tester', 'token_serial' => '']);
parse_str((string) parse_url((string) $cpCreated['otpauth'], PHP_URL_QUERY), $cpQuery);
$cpSeed = base32_decode((string) ($cpQuery['secret'] ?? ''));
$cpStep = null;
$cpClient = static function (string $url, string $secret, string $folder): Multiotp {
    @mkdir($folder . '/config', 0700, true);
    foreach (['users', 'tokens', 'devices', 'groups', 'log', 'cache'] as $sub) {
        @mkdir("$folder/$sub", 0700, true);
    }
    $client = new Multiotp('LaptopKey', false, '', $folder . '/config');
    $client->ForceNoDisplayLog();
    foreach (['Config' => 'config', 'Users' => 'users', 'Tokens' => 'tokens', 'Devices' => 'devices', 'Groups' => 'groups', 'Cache' => 'cache', 'Log' => 'log'] as $kind => $sub) {
        $client->{"Set{$kind}Folder"}("$folder/$sub/");
    }
    $client->SetServerUrl($url);
    $client->SetServerSecret($secret);
    $client->SetServerTimeout(5);
    $client->SetServerCacheLevel(1); // the CP asks for cache data; the portal decides
    return $client;
};
$laptop = sys_get_temp_dir() . '/cp-laptop-' . bin2hex(random_bytes(4));
$cpSecret = (string) ($winConfig['secrets']['cp_shared_secret'] ?? '');
$result = $cpClient($gatewayUrl, $cpSecret, $laptop)->CheckUserTokenOnServer('cp.tester', next_code($cpSeed, $cpStep));
check('CP gateway: right code accepted with the endpoint secret', 0 === $result, "result $result");
check('CP gateway: offline cache off in this group, nothing cached on the laptop', !is_file("$laptop/users/cp.tester.db"));
$result = $cpClient($gatewayUrl, $cpSecret, $laptop)->CheckUserTokenOnServer('cp.tester', '000000' === Portal\Totp::code($cpSeed, intdiv(time(), 30)) ? '111111' : '000000');
check('CP gateway: wrong code refused', 0 !== $result && _MULTIOTP_SERVER_AUTH_FAILED_ !== $result, "result $result");
$result = $cpClient($gatewayUrl, 'ClientServerSecret', $laptop)->CheckUserTokenOnServer('cp.tester', next_code($cpSeed, $cpStep));
check('CP gateway: default/other secret refused', _MULTIOTP_SERVER_AUTH_FAILED_ === $result, "result $result");
$linuxUrl = preg_replace('/e=[0-9a-f]+/', 'e=' . $linux->id, $gatewayUrl);
check('CP gateway: a Linux endpoint id is refused', 0 !== $cpClient($linuxUrl, $cpSecret, $laptop)->CheckUserTokenOnServer('cp.tester', next_code($cpSeed, $cpStep)));
$legacy = (new Browser($base))->post('/multiotp.server.php', ['data' => '<multiOTP version="4.0"><CheckUserExists><UserId>cp.tester</UserId></CheckUserExists></multiOTP>'], [], false);
check('legacy server: client mode refused with the default secret', 403 === $legacy->status && str_contains($legacy->body, 'default server secret'), $legacy->status . ' ' . substr($legacy->body, 0, 120));

// offline cache allowed by the group
$admin->get('/portal/index.php?r=endpoint-group&id=' . $endpointGroupId);
$admin->post('/portal/index.php?r=endpoint-group&id=' . $endpointGroupId, ['win_cache_enabled' => '1', 'win_cache_days' => '3'] + $groupForm);
check('group saved with offline cache', 303 === $admin->status);
$result = $cpClient($gatewayUrl, $cpSecret, $laptop)->CheckUserTokenOnServer('cp.tester', next_code($cpSeed, $cpStep));
$cached = (string) @file_get_contents("$laptop/users/cp.tester.db");
check('CP gateway: with offline cache, the laptop stores the user after a login', 0 === $result && str_contains($cached, 'token_seed'), "result $result");
preg_match('/^autolock_time=(\d+)/m', $cached, $m);
check('cached copy expires within the group lifetime (3 days)', isset($m[1]) && (int) $m[1] <= time() + 3 * 86400 + 60 && (int) $m[1] > time(), $m[1] ?? 'no autolock_time');

$endpointRecord = (new Portal\Endpoints())->endpoint((string) $windows->id);
check('endpoint page data: last Credential Provider request recorded', null !== ($endpointRecord['cp_last_seen'] ?? null));
$admin->get('/portal/index.php?r=endpoint&id=' . $windows->id);
check('endpoint page shows the last Credential Provider request', str_contains($admin->body, 'last request'));
$admin->post('/portal/index.php?r=endpoint&id=' . $windows->id, ['op' => 'disable']);
check('CP gateway: disabled endpoint refused', 0 !== $cpClient($gatewayUrl, $cpSecret, $laptop)->CheckUserTokenOnServer('cp.tester', next_code($cpSeed, $cpStep)));
$signInRetries = new Browser($base);
$signInRetries->bind = '127.0.0.11';
for ($i = 0; $i < 25; $i++) { // users keep trying to sign in on the disabled machine
    $signInRetries->post('/portal/cp.php?e=' . $windows->id, ['data' => '<multiOTP/>'], [], false);
}
check('CP gateway: a disabled machine refused 25 times does not block its IP (NAT)', 403 === $signInRetries->status, (string) $signInRetries->status);

// ================================================================ P1 cases (tests/CATALOGUE.md)

// ---------------------------------------------------------------- CP gateway: ReadUserData never returns secrets
$reader = $cpClient(str_replace('e=' . $windows->id, 'e=' . $windows->id, $gatewayUrl), $cpSecret, $laptop);
$admin->get('/portal/index.php?r=endpoint&id=' . $windows->id);
$admin->post('/portal/index.php?r=endpoint&id=' . $windows->id, ['op' => 'enable']);
$readSecret = (new Portal\Endpoints())->cpSecret((string) $windows->id);
$reader = $cpClient($gatewayUrl, $readSecret, sys_get_temp_dir() . '/cp-reader-' . bin2hex(random_bytes(3)));
$readBack = (string) $reader->ReadUserDataOnServer('cp.tester');
check('CP ReadUserData: answers for a known user', str_contains($readBack, 'algorithm'), substr($readBack, 0, 80));
check('CP ReadUserData: never returns the token seed, PIN or recovery codes', !preg_match('/^(token_seed|user_pin|scratch_passwords|seed_password)\b/m', $readBack) && !str_contains($readBack, bin2hex($cpSeed)));

// ---------------------------------------------------------------- directory down / wrong password: users untouched
$directory = new Portal\Directory();
$originalSettings = $directory->settings();
$states = static fn (): array => array_map(static fn (array $u): bool => $u['enabled'], Portal\Directory::snapshot());
$usersBefore = $states();
foreach (['unreachable directory server' => [['domain_controllers' => 'ldap-down.invalid'], null], 'wrong service password' => [[], 'wrong-password']] as $case => [$override, $password]) {
    $directory->save($override + $originalSettings, $password);
    $admin->get('/portal/index.php?r=directory');
    $admin->post('/portal/index.php?r=directory-run', ['op' => 'sync']);
    $status = wait_job($admin, job_id($admin));
    check("$case: sync reported as failed", 'failed' === $status, $status);
    check("$case: no user disabled, created or deleted", $states() === $usersBefore, json_encode(array_diff_assoc($states(), $usersBefore)));
}
$directory->save($originalSettings, 'sync-test-password');

// ---------------------------------------------------------------- per-IP blocking
$attacker = new Browser($base);
$attacker->bind = '127.0.0.9';
for ($i = 0; $i < 20; $i++) {
    $attacker->get('/portal/index.php');
    $attacker->post('/portal/index.php?r=login', ['username' => 'nobody-' . $i, 'password' => 'guess ' . $i]);
}
$attacker->get('/portal/index.php');
$attacker->post('/portal/index.php?r=login', ['username' => 'root', 'password' => 'Superuser portal passphrase 2026']);
check('admin sign-in: an IP with 20 failures is blocked, even with the right password', !str_contains($attacker->location(), 'r=mfa') && 303 !== $attacker->status);
$elsewhere = new Browser($base);
$elsewhere->get('/portal/index.php');
$elsewhere->post('/portal/index.php?r=login', ['username' => 'root', 'password' => 'Superuser portal passphrase 2026']);
check('admin sign-in: other addresses are not affected', 303 === $elsewhere->status && str_contains($elsewhere->location(), 'r=mfa'));

$prober = new Browser($base);
$prober->bind = '127.0.0.8';
for ($i = 0; $i < 21; $i++) { // 20 failures, then the 21st request is blocked
    $prober->raw('POST', '/portal/agent.php?a=enroll', json_encode((new AgentSim())->enrollRequest(str_repeat('0', 12) . '.' . str_repeat('x', 32), ['hostname' => 'probe', 'os' => 'linux'])), ['Content-Type' => 'application/json']);
}
check('agent API: after 20 bad tokens from one IP, 429', 429 === $prober->status && str_contains($prober->body, 'rate_limited'), $prober->status . ' ' . $prober->body);
$prober->raw('POST', '/portal/agent.php?a=checkin', '{}', ['Content-Type' => 'application/json'] + $waiting->headers('POST', '/portal/agent.php?a=checkin', '{}'));
check('agent API: a blocked IP is refused even with a valid signature', 429 === $prober->status);
$gatewayProber = new Browser($base);
$gatewayProber->bind = '127.0.0.10';
for ($i = 0; $i < 21; $i++) {
    $gatewayProber->post('/portal/cp.php?e=' . bin2hex(random_bytes(10)), ['data' => '<multiOTP/>'], [], false);
}
check('CP gateway: probing unknown endpoint ids is blocked (429)', 429 === $gatewayProber->status, (string) $gatewayProber->status);
// a deleted machine whose agent and SohobOTP Sign-in are still installed
$admin->get('/portal/index.php?r=endpoint-enrol');
$admin->post('/portal/index.php?r=endpoint-enrol', ['op' => 'create', 'group_id' => $endpointGroupId, 'label' => 'to delete', 'hours' => '1', 'max_uses' => '1']);
preg_match('/<p class="secret"><code>([0-9a-f]{12}\.[A-Za-z0-9_-]{32})<\/code>/', $admin->body, $m);
$gone = new AgentSim();
$previousBind = $agentHttp->bind;
$agentHttp->bind = '127.0.0.12';
$goneSignIn = new Browser($base);
$goneSignIn->bind = '127.0.0.12';
$gone->id = $agentCall('enroll', $gone->enrollRequest($m[1] ?? '', ['hostname' => 'retired-pc', 'os' => 'windows']))['endpoint_id'] ?? null;
check('machine to delete enrolled', is_string($gone->id) && '' !== $gone->id, $agentHttp->status . ' ' . $agentHttp->body);
if (is_string($gone->id) && '' !== $gone->id) {
    (new Portal\Endpoints())->deleteEndpoint($gone->id);
}
for ($i = 0; $i < 25; $i++) {
    $agentCall('checkin', ['applied' => ['version' => 0, 'status' => 'none', 'error' => '', 'at' => null]], $gone);
    $goneSignIn->post('/portal/cp.php?e=' . $gone->id, ['data' => '<multiOTP/>'], [], false);
}
$agentCall('checkin', ['applied' => ['version' => 0, 'status' => 'none', 'error' => '', 'at' => null]], $gone);
check('agent API: a deleted machine still checking in is refused but does not block its IP', 401 === $agentHttp->status && str_contains($agentHttp->body, 'unknown_endpoint'), $agentHttp->status . ' ' . $agentHttp->body);
check('CP gateway: SohobOTP Sign-in of a deleted machine refused, IP not blocked', 403 === $goneSignIn->status, (string) $goneSignIn->status);
$agentHttp->bind = $previousBind;
check('agent API: malformed request from a clean IP gets 400, not 429', 400 === $agentHttp->raw('POST', '/portal/agent.php?a=enroll', 'not json', ['Content-Type' => 'application/json'])->status);
check('agent API: unknown action 404, body over 256 KiB 413', 404 === $agentHttp->raw('POST', '/portal/agent.php?a=nope', '{}', [])->status
    && 413 === $agentHttp->raw('POST', '/portal/agent.php?a=enroll', str_repeat('x', 262145), ['Content-Type' => 'application/json'])->status);

// ---------------------------------------------------------------- every POST route: CSRF, origin, roles
$auditor = new Browser($base);
$admin->get('/portal/index.php?r=admin-new');
$admin->post('/portal/index.php?r=admin-new', ['username' => 'reader', 'display_name' => 'Read Only', 'email' => '', 'role' => 'auditor', 'mfa' => 'enroll']);
preg_match('/<p class="secret"><code>([^<]+)<\/code>/', $admin->body, $m);
$readerStep = null;
first_sign_in($auditor, 'reader', html_entity_decode($m[1] ?? ''), 'Auditor portal passphrase 2026', $readerStep);
$radiusClients = (new Portal\Radius())->clients();
$postRoutes = [
    'user-new' => [], 'user-action' => ['u' => 'cp.tester', 'op' => 'delete'], 'user-bulk' => ['op' => 'delete', 'users' => ['cp.tester']],
    'token-import' => [], 'token-action' => ['op' => 'delete', 'serial' => 'none'],
    'directory-save' => [], 'directory-test' => [], 'directory-run' => ['op' => 'sync'], 'job-cancel' => ['id' => 'none'],
    'radius-group' => ['name' => 'Evil'], 'radius-group-delete' => ['id' => 'none'], 'radius-client' => ['name' => 'evil'],
    'radius-client-action' => ['id' => $radiusClients[0]['id'] ?? 'none', 'op' => 'delete'], 'radius-apply' => [],
    'radius-diagnostics' => ['op' => 'disable-default-client'], 'radius-vip' => ['op' => 'save', 'address_1' => '192.0.2.99', 'secret_1' => 'Evil-Secret-12345'],
    'endpoint&id=' . $linux->id => ['op' => 'delete'], 'endpoint-group' => ['name' => 'Evil'], 'endpoint-group-delete' => ['id' => $endpointGroupId],
    'endpoint-rules' => ['op' => 'check'], 'endpoint-enrol' => ['op' => 'create', 'group_id' => $endpointGroupId],
    'api-keys' => ['op' => 'create', 'name' => 'evil', 'scopes' => ['users.write']], 'ha' => ['op' => 'promote'], 'database' => ['op' => 'local'], 'admin-new' => ['username' => 'evil', 'role' => 'superadmin'], 'admin-edit' => [], 'admin-action' => ['op' => 'delete'],
];
$deniedBefore = substr_count((string) file_get_contents(Portal\Config::auditFile()), '"action":"access.denied"');
foreach ($postRoutes as $route => $fields) {
    $admin->get('/portal/index.php?r=dashboard');
    $admin->post('/portal/index.php?r=' . $route, $fields, [], false);
    $noToken = $admin->status;
    $admin->get('/portal/index.php?r=dashboard');
    $admin->post('/portal/index.php?r=' . $route, $fields, ['Origin' => 'https://evil.example']);
    check("CSRF: $route refused without token ($noToken) and from a foreign origin ($admin->status)", 400 === $noToken && 400 === $admin->status);
    foreach (['helpdesk' => $help, 'auditor' => $auditor] as $role => $session) {
        $session->get('/portal/index.php?r=dashboard');
        $session->post('/portal/index.php?r=' . $route, $fields);
        check("roles: $role cannot POST $route", 403 === $session->status, (string) $session->status);
    }
}
$deniedAfter = substr_count((string) file_get_contents(Portal\Config::auditFile()), '"action":"access.denied"');
check('every refused POST is in the audit trail', $deniedAfter - $deniedBefore >= 2 * count($postRoutes), ($deniedAfter - $deniedBefore) . ' entries');
check('refused POSTs changed nothing (user, endpoint, group still there)', (new Portal\Users())->exists('cp.tester') && null !== (new Portal\Endpoints())->endpoint((string) $linux->id) && null !== (new Portal\Endpoints())->group($endpointGroupId));
foreach (['users', 'tokens', 'radius', 'endpoints', 'endpoint-groups', 'audit', 'directory', 'jobs'] as $page) {
    $auditor->get('/portal/index.php?r=' . $page);
    check("roles: auditor can read $page", 200 === $auditor->status, (string) $auditor->status);
}

// ---------------------------------------------------------------- XSS: a payload in every stored text field, every page crawled
$xss = '"><svg onload=alert(7)>';
$xssUsers = new Portal\Users();
$xssUsers->create(['user' => 'xss.user', 'display_name' => $xss, 'token_serial' => '']);
$xssRadius = (new Portal\Radius())->saveGroup(null, ['name' => 'XSS radius', 'description' => $xss, 'cache_timeout' => '3600']);
(new Portal\Radius())->createClient(['name' => 'xss-client', 'description' => $xss, 'address' => '192.0.2.200', 'group_id' => $xssRadius['id'], 'nas_type' => 'other', 'require_message_authenticator' => '1']);
$xssEndpoints = new Portal\Endpoints();
$xssGroup = $xssEndpoints->saveGroup(null, ['name' => 'XSS endpoints', 'description' => $xss, 'win_login_text' => $xss, 'win_otp_text' => $xss, 'win_default_prefix' => $xss] + array_diff_key($groupForm, ['name' => 1, 'description' => 1]));
[, $xssToken] = $xssEndpoints->createToken($xssGroup['id'], $xss, 1, 1, 'e2e');
$xssAgent = new AgentSim();
$xssInventory = ['os' => 'windows'];
foreach (['hostname', 'os_name', 'os_version', 'kernel', 'arch', 'domain', 'agent_version'] as $field) {
    $xssInventory[$field] = $xss;
}
$xssInventory['component'] = ['name' => $xss, 'version' => $xss];
$xssAgent->id = $xssEndpoints->enroll($xssAgent->enrollRequest($xssToken, $xssInventory), '192.0.2.201', 'portal.example.test')['endpoint_id'];
$xssEndpoints->checkin($xssAgent->id, ['inventory' => $xssInventory, 'applied' => ['version' => 0, 'status' => 'failed', 'error' => $xss, 'at' => time()]], '192.0.2.201');
$pages = ['dashboard', 'users', 'user&u=xss.user', 'tokens', 'radius', 'radius-group&id=' . $xssRadius['id'], 'radius-diagnostics',
    'endpoints', 'endpoint&id=' . $xssAgent->id, 'endpoint-groups', 'endpoint-group&id=' . $xssGroup['id'], 'endpoint-enrol',
    'directory', 'jobs', 'audit', 'admins', 'account'];
foreach ($pages as $page) {
    $admin->get('/portal/index.php?r=' . $page);
    check("XSS: $page escapes stored text", 200 === $admin->status && !str_contains($admin->body, '<svg onload=alert(7)>'), (string) $admin->status);
}

// ---------------------------------------------------------------- path tricks in ids
foreach (['endpoint&id=..%2F..%2Fportal.key', 'endpoint&id=../endpoints', 'user&u=..%2F..%2Fconfig%2Fmultiotp', 'job&id=..%2Fjobs',
    'radius-group&id=..%2Fradius', 'endpoint-group&id=..%2F..%2Fadmins', 'admin-edit&id=..%2Fadmins', 'radius-client&id=..%2F..'] as $probe) {
    $admin->get('/portal/index.php?r=' . $probe);
    check("path trick refused: $probe", in_array($admin->status, [404, 303], true) && !str_contains($admin->body, 'sb1:') && !str_contains($admin->body, 'password_hash'), (string) $admin->status);
}
$agentHttp->bind = '127.0.0.7';
$agentHttp->raw('POST', '/portal/agent.php?a=checkin', '{}', ['Content-Type' => 'application/json', 'X-Agent-Id' => '../../portal', 'X-Agent-Time' => (string) time(), 'X-Agent-Nonce' => base64_encode(random_bytes(16)), 'X-Agent-Signature' => base64_encode(random_bytes(64))]);
check('agent API: path in endpoint id refused (400)', 400 === $agentHttp->status);
check('CP gateway: path in endpoint id refused (403)', 403 === (new Browser($base))->post('/portal/cp.php?e=..%2F..%2Fportal', ['data' => '<multiOTP/>'], [], false)->status);

// ---------------------------------------------------------------- backup and restore
$etc = Portal\Config::etcDir();
$data = Portal\Config::dataDir();
$backup = sys_get_temp_dir() . '/backup-' . bin2hex(random_bytes(3));
mkdir($backup);
exec('cp -a ' . escapeshellarg($etc) . ' ' . escapeshellarg("$backup/etc") . ' && cp -a ' . escapeshellarg($data) . ' ' . escapeshellarg("$backup/portal"), $out, $rc);
check('backup copied', 0 === $rc);
exec('rm -rf ' . escapeshellarg($etc) . '/* ' . escapeshellarg($data) . '/*');
$lost = (new Browser($base))->get('/portal/index.php');
check('after data loss the portal no longer knows its admins', !str_contains((string) @file_get_contents("$data/admins.json"), 'root'));
exec('cp -a ' . escapeshellarg("$backup/etc") . '/. ' . escapeshellarg($etc) . ' && cp -a ' . escapeshellarg("$backup/portal") . '/. ' . escapeshellarg($data), $out, $rc);
Portal\MultiotpService::reset();
check('restore copied', 0 === $rc);
$restored = new Browser($base);
$restored->get('/portal/index.php');
$restored->post('/portal/index.php?r=login', ['username' => 'root', 'password' => 'Superuser portal passphrase 2026']);
check('restored: administrators can sign in', 303 === $restored->status && str_contains($restored->location(), 'r=mfa'));
$reply = $agentCall('checkin', ['applied' => ['version' => 0, 'status' => 'none', 'error' => '', 'at' => null]], $waiting);
$restoredConfig = null;
try {
    $restoredConfig = $waiting->openConfig($reply['config'] ?? [], $portalKeyHttp, 0, 'linux');
} catch (Throwable $error) {
}
check('restored: agents keep working, signing key and sealed secrets readable', null !== $restoredConfig && '' !== ($restoredConfig['secrets']['radius_secret'] ?? ''), $agentHttp->body);
check('restored: users and their codes still work', 0 === engine_check('cp.tester', next_code($cpSeed, $cpStep)));
@unlink("$data/portal.key");
$reply = $agentCall('checkin', ['applied' => ['version' => 0, 'status' => 'none', 'error' => '', 'at' => null]], $waiting);
check('restore without portal.key: sealed secrets cannot be used (server error, nothing leaked)', 500 === $agentHttp->status && !str_contains($agentHttp->body, 'secret'), $agentHttp->status . ' ' . $agentHttp->body);
copy("$backup/portal/portal.key", "$data/portal.key");

// ---------------------------------------------------------------- licences page (public), no third-party footer
$public = (new Browser($base))->get('/portal/index.php?r=licences');
check('licences page is public and lists the open-source parts', 200 === $public->status && str_contains($public->body, 'LGPL-3.0') && str_contains($public->body, 'phpseclib') && str_contains($public->body, 'Apache-2.0'));
// ---------------------------------------------------------------- REST API (stage 5)
$admin->get('/portal/index.php?r=api-keys');
check('API keys page served to the super administrator', 200 === $admin->status && str_contains($admin->body, 'New key'));
$newKey = static function (array $fields) use ($admin): string {
    $admin->get('/portal/index.php?r=api-keys');
    $admin->post('/portal/index.php?r=api-keys', $fields + ['op' => 'create', 'networks' => '', 'expires_days' => '30', 'rate' => '200']);
    return preg_match('/<p class="secret"><code>(sohob_[0-9a-f]{12}_[A-Za-z0-9_-]{32})<\/code>/', $admin->body, $m) ? $m[1] : '';
};
$apiKey = $newKey(['name' => 'HR onboarding', 'scopes' => ['users.read', 'users.write', 'tokens.write', 'auth.check']]);
check('API key created and shown once', '' !== $apiKey);
$admin->get('/portal/index.php?r=api-keys');
check('key listed without its secret', str_contains($admin->body, 'HR onboarding') && !str_contains($admin->body, substr($apiKey, 19)));
$api = new Browser($base);
$api->bind = '127.0.0.13';
$call = static function (string $method, string $path, ?array $body = null, ?string $key = null) use ($api, $apiKey): array {
    $headers = ['Content-Type' => 'application/json'];
    $key ??= $apiKey;
    if ('' !== $key) {
        $headers['Authorization'] = 'Bearer ' . $key;
    }
    $api->raw($method, '/portal/api.php' . $path, null === $body ? null : json_encode($body), $headers);
    return json_decode($api->body, true) ?? [];
};
$reply = $call('GET', '/v1/health', null, '');
check('API: health without a key', 200 === $api->status && 'ok' === ($reply['status'] ?? ''));
$call('GET', '/v1/users', null, '');
check('API: no key, 401', 401 === $api->status);
$call('GET', '/v1/users', null, 'sohob_000000000000_' . str_repeat('x', 32));
check('API: unknown key, 401', 401 === $api->status);
$reply = $call('GET', '/v1/me');
check('API: /v1/me shows the key and its permissions', 200 === $api->status && 'HR onboarding' === ($reply['name'] ?? '') && in_array('auth.check', $reply['scopes'] ?? [], true));
$reply = $call('POST', '/v1/users', ['user' => 'api.created', 'display_name' => 'Created by API', 'email' => 'api.created@example.test', 'group' => 'VPN-Users']);
check('API: user created, provisioning link returned', 201 === $api->status && str_starts_with((string) ($reply['provisioning_uri'] ?? ''), 'otpauth://') && 'VPN-Users' === ($reply['user']['group'] ?? ''), $api->status . ' ' . $api->body);
parse_str((string) parse_url((string) ($reply['provisioning_uri'] ?? ''), PHP_URL_QUERY), $apiQuery);
$apiSeed = base32_decode((string) ($apiQuery['secret'] ?? ''));
$call('POST', '/v1/users', ['user' => 'api.created']);
check('API: duplicate user, 409', 409 === $api->status);
$call('POST', '/v1/users', ['user' => 'bad user"name']);
check('API: invalid user name, 422', 422 === $api->status, $api->status . ' ' . $api->body);
$reply = $call('GET', '/v1/users/api.created');
check('API: read one user', 200 === $api->status && 'api.created@example.test' === ($reply['email'] ?? ''));
$reply = $call('GET', '/v1/users?q=api.created');
check('API: search users', 200 === $api->status && 1 === ($reply['total'] ?? 0) && 'api.created' === ($reply['users'][0]['user'] ?? ''));
$reply = $call('PATCH', '/v1/users/api.created', ['display_name' => 'Renamed', 'enabled' => false]);
check('API: user changed and disabled', 200 === $api->status && 'Renamed' === ($reply['display_name'] ?? '') && false === ($reply['enabled'] ?? null));
$reply = $call('POST', '/v1/auth/check', ['user' => 'api.created', 'code' => Portal\Totp::code($apiSeed, intdiv(time(), 30))]);
check('API: code check of a disabled user is not accepted', 200 === $api->status && 'accepted' !== ($reply['result'] ?? ''), $api->body);
$call('PATCH', '/v1/users/api.created', ['enabled' => true]);
$apiStep = null;
$reply = $call('POST', '/v1/auth/check', ['user' => 'api.created', 'code' => next_code($apiSeed, $apiStep)]);
check('API: right code accepted', 'accepted' === ($reply['result'] ?? ''), $api->body);
$reply = $call('POST', '/v1/auth/check', ['user' => 'api.created', 'code' => '000000' === Portal\Totp::code($apiSeed, intdiv(time(), 30)) ? '111111' : '000000']);
check('API: wrong code rejected', 'rejected' === ($reply['result'] ?? ''), $api->body);
$reply = $call('POST', '/v1/auth/check', ['user' => 'nobody.here', 'code' => '123456']);
check('API: unknown user reported as unknown', 'unknown' === ($reply['result'] ?? ''));
$reply = $call('POST', '/v1/users/api.created/route', ['route' => 'vip']);
check('API: user sent back to Symantec VIP', 200 === $api->status && 'vip' === ((new Portal\VipMigration())->stateOf('api.created')['state'] ?? ''));
$reply = $call('POST', '/v1/users/api.created/enroll');
check('API: new authenticator enrolled, user moved to SohobOTP', 200 === $api->status && str_starts_with((string) ($reply['provisioning_uri'] ?? ''), 'otpauth://') && (new Portal\VipMigration())->isOnSohobotp('api.created'));
$api->raw('POST', '/portal/api.php/v1/users', '{not json', ['Authorization' => 'Bearer ' . $apiKey]);
check('API: malformed JSON, 400', 400 === $api->status);
$call('GET', '/v1/nothing');
check('API: unknown call, 404', 404 === $api->status);
$api->raw('GET', '/portal/api.php?path=/v1/users/api.created', null, ['Authorization' => 'Bearer ' . $apiKey]);
check('API: ?path= works without PATH_INFO', 200 === $api->status && str_contains($api->body, '"user":"api.created"'));
$call('GET', '/v1/audit');
check('API: a call outside the key permissions, 403', 403 === $api->status && str_contains($api->body, 'audit.read'));
$readOnly = $newKey(['name' => 'Reporting', 'scopes' => ['users.read', 'audit.read']]);
$call('DELETE', '/v1/users/api.created', null, $readOnly);
check('API: read-only key cannot delete users', 403 === $api->status);
$reply = $call('GET', '/v1/audit?action=user.create&limit=20', null, $readOnly);
$apiAudit = json_encode($reply);
check('API: audit shows the API changes under the key name, never the key or seed', 200 === $api->status && str_contains($apiAudit, 'api:HR onboarding') && !str_contains($apiAudit, substr($apiKey, 19)) && !str_contains($apiAudit, (string) ($apiQuery['secret'] ?? 'no-seed')));
$fenced = $newKey(['name' => 'Fenced', 'scopes' => ['users.read'], 'networks' => '192.0.2.0/24']);
$call('GET', '/v1/users', null, $fenced);
check('API: key used outside its allowed networks, 403', 403 === $api->status);
$slow = $newKey(['name' => 'Throttled', 'scopes' => ['users.read'], 'rate' => '3']);
for ($i = 0; $i < 4; $i++) {
    $call('GET', '/v1/me', null, $slow);
}
check('API: rate limit per key, 429', 429 === $api->status);
$reply = $call('DELETE', '/v1/users/api.created');
check('API: user deleted', 200 === $api->status && null === (new Portal\Users())->get('api.created'));
$prober = new Browser($base);
$prober->bind = '127.0.0.14';
for ($i = 0; $i < 21; $i++) {
    $prober->raw('GET', '/portal/api.php/v1/users', null, ['Authorization' => 'Bearer sohob_' . bin2hex(random_bytes(6)) . '_' . str_repeat('y', 32)]);
}
check('API: guessing keys from one address is blocked (429)', 429 === $prober->status);
$admin->get('/portal/index.php?r=api-keys');
$keyIds = [];
preg_match_all('/name="id" value="([0-9a-f]{12})"/', $admin->body, $keyIds);
foreach ($keyIds[1] as $id) {
    $admin->get('/portal/index.php?r=api-keys');
    $admin->post('/portal/index.php?r=api-keys', ['op' => 'revoke', 'id' => $id]);
}
$call('GET', '/v1/me');
check('API: revoked key refused at once', 401 === $api->status);
$help->get('/portal/index.php?r=api-keys');
check('helpdesk cannot open API keys', 403 === $help->status);
$auditText = (string) file_get_contents(Portal\Config::auditFile());
check('audit: API keys created and revoked, never the key', str_contains($auditText, '"action":"api_key.create"') && str_contains($auditText, '"action":"api_key.revoke"') && !str_contains($auditText, substr($apiKey, 19)));

// ---------------------------------------------------------------- Database page (MariaDB itself: appliance-db.php)
$admin->get('/portal/index.php?r=database');
check('Database page: files now, MariaDB offered', 200 === $admin->status && str_contains($admin->body, 'Files on this appliance') && str_contains($admin->body, 'Use MariaDB on this appliance'));
$admin->post('/portal/index.php?r=database', ['op' => 'test', 'host' => '127.0.0.1', 'port' => '1', 'database' => 'sohobotp', 'user' => 'sohobotp', 'password' => 'Wrong-Password-123']);
check('Database: connection test reports an unreachable server, no move', 200 === $admin->status && str_contains($admin->body, 'Cannot connect') && 'files' === Portal\Database::current()['backend'], strip_tags(substr($admin->body, 0, 0)));
$admin->get('/portal/index.php?r=database');
$admin->post('/portal/index.php?r=database', ['op' => 'test', 'host' => 'bad host;', 'database' => 'x', 'user' => 'x', 'password' => 'x']);
check('Database: invalid server name refused', str_contains($admin->body, 'IP address or a host name'));
$help->get('/portal/index.php?r=database');
check('helpdesk cannot open the Database page', 403 === $help->status);
$auditText = (string) file_get_contents(Portal\Config::auditFile());
check('audit: database test recorded, never the password', str_contains($auditText, '"action":"database.test"') && !str_contains($auditText, 'Wrong-Password-123'));

// ---------------------------------------------------------------- High availability page (two appliances: run-ha-test.sh)
$admin->get('/portal/index.php?r=ha');
check('High availability page: not paired, MariaDB needed first', 200 === $admin->status && str_contains($admin->body, 'Not paired') && str_contains($admin->body, 'First move the data to MariaDB'));
$admin->post('/portal/index.php?r=ha', ['op' => 'join', 'code' => 'SOHOBOTP-HA-bm90IGEgY29kZQ']);
check('High availability: an invalid pairing code is refused', str_contains($admin->body, 'not a valid pairing code') && 'none' === (new Portal\Ha())->state()['role']);
$admin->get('/portal/index.php?r=ha');
$admin->post('/portal/index.php?r=ha', ['op' => 'pair', 'primary_ip' => '192.0.2.10', 'secondary_ip' => '192.0.2.11', 'portal_url' => 'https://192.0.2.10']);
check('High availability: pairing refused while the data is on files', str_contains($admin->body, 'First move the data to MariaDB'));
$haProbe = (new Browser($base))->raw('GET', '/portal/ha.php', null, ['X-HA-Time' => (string) time(), 'X-HA-Signature' => str_repeat('0', 64)]);
check('ha.php refuses requests without the pairing key', 403 === $haProbe->status);
$help->get('/portal/index.php?r=ha');
check('helpdesk cannot open High availability', 403 === $help->status);

$admin->get('/portal/index.php?r=dashboard');
check('footer shows the company only, no licences link, no third-party credit', str_contains($admin->body, '© Sohobcom') && !str_contains($admin->body, 'r=licences') && !str_contains($admin->body, 'Powered by'));
$admin->get('/portal/index.php?r=account');
check('open-source notices linked from My account', str_contains($admin->body, 'r=licences'));

// ---------------------------------------------------------------- engine key (security review)
Portal\MultiotpService::reset();
check('worker gave the engine a private key at start', !Portal\EngineKey::isPublic() && is_file(Portal\EngineKey::path()) && 64 === strlen(trim((string) file_get_contents(Portal\EngineKey::path()))));
$seedLine = '';
foreach (glob(Portal\Config::etcDir() . '/users/*.db') ?: [] as $userFile) {
    foreach (file($userFile) ?: [] as $line) {
        if (str_starts_with($line, 'token_seed:=')) {
            $seedLine = trim(substr($line, strlen('token_seed:=')));
            break 2;
        }
    }
}
$raw = (string) base64_decode($seedLine);
$guess = '';
for ($i = 0; $i < strlen($raw); $i++) {
    $guess .= chr(ord('DefaultCliEncryptionKey'[$i % 23]) ^ ord('token_seed'[$i % 10]) ^ ord($raw[$i]));
}
check('stored seeds cannot be decrypted with the public default key', '' !== $seedLine && !ctype_xdigit($guess));
check('engine-key is idempotent', false === Portal\EngineKey::protect()['changed']);
check('legacy admin password is not the default', !Portal\MultiotpService::get()->CheckAdminPassword(_MULTIOTP_DEFAULT_PASSWORD_));

// ---------------------------------------------------------------- Download agent: enrolment settings built into the program
$helper->get('/portal/index.php?r=agent-download');
check('download agent: not for the help desk role (no page, no permission)', !str_contains($helper->body, 'name="platform"') && !Portal\Roles::can('helpdesk', 'endpoints.manage'), (string) $helper->status);
$anonymous = (new Browser($base))->get('/portal/index.php?r=agent-download');
check('download agent: not without signing in', !str_contains($anonymous->body, 'name="platform"') && !str_contains($anonymous->body, Portal\AgentBundle::MAGIC));
$admin->get('/portal/index.php?r=agent-download');
check('download agent: page served, Linux available, Windows not (no program)', 200 === $admin->status
    && 1 === preg_match('/value="linux\/amd64" class="button-primary">/', $admin->body) && 1 === preg_match('/value="windows\/amd64" class="button-primary" disabled>/', $admin->body), (string) $admin->status);
check('download agent: in the sidebar', str_contains($admin->body, 'r=agent-download'));
$downloadForm = ['group_id' => $endpointGroupId, 'label' => 'e2e <b>download</b>', 'hours' => '2', 'max_uses' => '1', 'approval' => 'none', 'portal' => 'https://otp.example.test', 'ca_pem' => ''];
$admin->post('/portal/index.php?r=agent-download', $downloadForm + ['platform' => 'windows/amd64']);
check('download agent: platform without a program refused', 400 === $admin->status && str_contains($admin->body, 'no agent program'));
$admin->get('/portal/index.php?r=agent-download');
$admin->post('/portal/index.php?r=agent-download', ['portal' => 'http://otp.example.test'] + $downloadForm + ['platform' => 'linux/amd64']);
check('download agent: plain http portal address refused', 400 === $admin->status && str_contains($admin->body, 'must look like https://'));
$admin->get('/portal/index.php?r=agent-download');
$admin->post('/portal/index.php?r=agent-download', ['ca_pem' => 'not a certificate'] + $downloadForm + ['platform' => 'linux/amd64']);
check('download agent: bad CA certificate refused', 400 === $admin->status && str_contains($admin->body, 'PEM format'));
$tokensBefore = count((new Portal\Endpoints())->tokens());
$admin->get('/portal/index.php?r=agent-download');
$admin->post('/portal/index.php?r=agent-download', $downloadForm + ['platform' => 'linux/amd64'], [], false);
check('download agent: refused without the CSRF token', 400 === $admin->status && $tokensBefore === count((new Portal\Endpoints())->tokens()));
$admin->get('/portal/index.php?r=agent-download');
$admin->post('/portal/index.php?r=agent-download', $downloadForm + ['platform' => 'linux/amd64']);
$download = $admin->body;
$plainProgram = (string) file_get_contents(Portal\AgentBundle::programsDir() . '/sohobotp-agent-linux-amd64');
check('download agent: a file download, not cached', 200 === $admin->status && str_contains($admin->headers['content-disposition'][0] ?? '', 'attachment; filename="sohobotp-agent-')
    && 'no-store' === ($admin->headers['cache-control'][0] ?? '') && (int) ($admin->headers['content-length'][0] ?? 0) === strlen($download), $admin->status . ' ' . json_encode($admin->headers));
check('download agent: the agent program, unchanged, then the settings', str_starts_with($download, $plainProgram) && str_ends_with($download, Portal\AgentBundle::MAGIC));
$settingsLength = unpack('N', substr($download, -20, 4))[1];
$settingsRaw = substr($download, strlen($plainProgram), $settingsLength);
$built = json_decode($settingsRaw, true);
check('download agent: settings checksum, portal address and pin', hash('sha256', $settingsRaw, true) === substr($download, -52, 32)
    && 'https://otp.example.test' === ($built['portal'] ?? '') && $pinShown === ($built['pin'] ?? '') && !isset($built['ca_pem']) && 1 === ($built['v'] ?? 0), $settingsRaw);
$builtToken = (string) ($built['token'] ?? '');
$agentHttp->bind = '127.0.0.9';
$downloaded = new AgentSim();
$downloaded->id = $agentCall('enroll', $downloaded->enrollRequest($builtToken, ['hostname' => 'from-download', 'os' => 'linux']))['endpoint_id'] ?? null;
check('download agent: the built-in token enrols a machine', null !== $downloaded->id, $agentHttp->body);
$reply = $agentCall('enroll', (new AgentSim())->enrollRequest($builtToken, ['hostname' => 'second', 'os' => 'linux']));
check('download agent: and only as many machines as chosen (1)', 'bad_token' === ($reply['error'] ?? ''));
$admin->get('/portal/index.php?r=endpoint-enrol');
check('download agent: its token is in the token list (label escaped), where it can be revoked', str_contains($admin->body, 'e2e &lt;b&gt;download&lt;/b&gt;') && !str_contains($admin->body, $builtToken));
$auditText = (string) file_get_contents(Portal\Config::auditFile());
check('download agent: audit trail has the download, never the token', str_contains($auditText, 'endpoint.agent_download') && '' !== $builtToken && !str_contains($auditText, $builtToken));
$ownCa = '';
$caKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
openssl_x509_export(openssl_csr_sign(openssl_csr_new(['commonName' => 'e2e CA'], $caKey), null, $caKey, 1), $ownCa);
$admin->get('/portal/index.php?r=agent-download');
$admin->post('/portal/index.php?r=agent-download', ['ca_pem' => $ownCa] + $downloadForm + ['platform' => 'linux/amd64']);
$withCa = json_decode(substr($admin->body, strlen($plainProgram), unpack('N', substr($admin->body, -20, 4))[1]), true);
check('download agent: CA certificate built in, and a different token each time', trim($ownCa) . "\n" === ($withCa['ca_pem'] ?? '') && '' !== ($withCa['token'] ?? '') && $builtToken !== $withCa['token']);

echo "\n" . ($count - $failures) . "/$count checks passed\n";
exit($failures > 0 ? 1 : 0);
