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

echo "\n" . ($count - $failures) . "/$count checks passed\n";
exit($failures > 0 ? 1 : 0);
