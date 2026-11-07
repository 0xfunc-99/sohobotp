<?php
/**
 * multiOTP portal - administrator account tool (command line only).
 *
 * Creates the first super administrator and recovers locked-out accounts.
 * Every operation is written to the portal audit trail as "cli:<system user>".
 *
 *   php portal/bin/portal-admin.php create --username=alice --role=superadmin [--display-name="Alice"] [--email=..] [--mfa-user=multiotp_user]
 *   php portal/bin/portal-admin.php list
 *   php portal/bin/portal-admin.php reset-password --username=alice
 *   php portal/bin/portal-admin.php reset-mfa --username=alice
 *   php portal/bin/portal-admin.php unlock --username=alice
 *   php portal/bin/portal-admin.php enable|disable --username=alice
 *   php portal/bin/portal-admin.php verify-audit
 *
 * In Docker:  docker exec -it multiotp php /usr/local/bin/multiotp/portal/bin/portal-admin.php list
 */
declare(strict_types=1);

if ('cli' !== PHP_SAPI) {
    http_response_code(404);
    exit;
}

define('PORTAL_ROOT', dirname(__DIR__));
require PORTAL_ROOT . '/src/bootstrap.php';

use Portal\AdminRepository;
use Portal\Audit;
use Portal\Config;
use Portal\Mfa;
use Portal\Passwords;
use Portal\Roles;
use Portal\ValidationException;

function out(string $text): void
{
    fwrite(STDOUT, $text . "\n");
}

function fail(string $text, int $code = 1): never
{
    fwrite(STDERR, 'Error: ' . $text . "\n");
    exit($code);
}

/** Files created as root must stay readable by the web server. */
function fix_ownership(): void
{
    if (!function_exists('posix_geteuid') || 0 !== posix_geteuid()) {
        return;
    }
    $owner = getenv('MULTIOTP_PORTAL_OWNER') ?: 'www-data';
    if (false === posix_getpwnam($owner)) {
        return;
    }
    $dir = Config::dataDir();
    @chown($dir, $owner);
    foreach (glob($dir . '/*') ?: [] as $file) {
        @chown($file, $owner);
    }
}

$command = $argv[1] ?? 'help';
// --name=value options after the command (getopt() would stop at the command word)
$options = [];
foreach (array_slice($argv, 2) as $arg) {
    if (preg_match('/^--(username|role|display-name|email|mfa-user)=(.*)$/s', $arg, $m)) {
        $options[$m[1]] = $m[2];
    } else {
        fail('Unknown option: ' . $arg);
    }
}
$systemUser = function_exists('posix_geteuid') ? (posix_getpwuid(posix_geteuid())['name'] ?? 'unknown') : get_current_user();
Audit::setActor('cli:' . $systemUser);
Audit::setIp('local');

$admins = new AdminRepository();
$audit = Audit::default();

$findOrFail = static function () use ($options, $admins): array {
    $username = (string) ($options['username'] ?? '');
    $admin = '' === $username ? null : $admins->findByUsername($username);
    return $admin ?? fail('No administrator named "' . $username . '". Use --username=NAME.');
};

try {
    switch ($command) {
        case 'create':
            $input = [
                'username'     => (string) ($options['username'] ?? ''),
                'role'         => (string) ($options['role'] ?? 'superadmin'),
                'display_name' => (string) ($options['display-name'] ?? ''),
                'email'        => (string) ($options['email'] ?? ''),
                'mfa_user'     => (string) ($options['mfa-user'] ?? ''),
            ];
            if ('' !== $input['mfa_user'] && null !== ($error = Mfa::checkLinkableUser($input['mfa_user']))) {
                fail($error);
            }
            $temporary = Passwords::temporary();
            $created = $admins->create($input, $temporary, true, 'cli:' . $systemUser);
            $audit->record('admin.create', 'success', $created['username'], ['role' => $created['role'], 'mfa_user' => $created['mfa_user']]);
            out('Created ' . Roles::label($created['role']) . ' "' . $created['username'] . '".');
            out('Temporary password (shown once, valid ' . intdiv(Config::tempPasswordLifetime(), 3600) . ' h): ' . $temporary);
            out(null === $created['mfa_mode']
                ? 'At first sign-in the administrator sets up an authenticator app, then chooses a new password.'
                : 'Second factor: multiOTP user "' . $created['mfa_user'] . '". A new password is required at first sign-in.');
            break;

        case 'list':
            foreach ($admins->all() as $a) {
                out(sprintf('%-24s %-12s %-9s %-10s %s',
                    $a['username'], $a['role'], $a['status'],
                    AdminRepository::isLocked($a) ? 'LOCKED' : '-',
                    null === $a['mfa_mode'] ? 'mfa:not-set-up' : 'mfa:' . $a['mfa_mode']));
            }
            break;

        case 'reset-password':
            $admin = $findOrFail();
            $temporary = Passwords::temporary();
            $admins->update($admin['id'], static function (array &$a) use ($temporary): void {
                $a['password_hash'] = Passwords::hash($temporary);
                $a['must_change_password'] = true;
                $a['password_expires_at'] = time() + Config::tempPasswordLifetime();
                $a['failed_attempts'] = 0;
                $a['locked_until'] = null;
                $a['session_version']++;
            });
            $audit->record('admin.reset-password', 'success', $admin['username']);
            out('Temporary password for ' . $admin['username'] . ' (shown once): ' . $temporary);
            break;

        case 'reset-mfa':
            $admin = $findOrFail();
            $admins->update($admin['id'], static function (array &$a): void {
                $a['mfa_mode'] = null;
                $a['mfa_secret'] = null;
                $a['mfa_last_step'] = -1;
                $a['mfa_user'] = null;
                $a['session_version']++;
            });
            $audit->record('admin.reset-mfa', 'success', $admin['username']);
            out('Second factor removed for ' . $admin['username'] . '. A new authenticator is set up at next sign-in.');
            break;

        case 'unlock':
            $admin = $findOrFail();
            $admins->update($admin['id'], static function (array &$a): void {
                $a['failed_attempts'] = 0;
                $a['locked_until'] = null;
            });
            $audit->record('admin.unlock', 'success', $admin['username']);
            out('Unlocked ' . $admin['username'] . '.');
            break;

        case 'enable':
        case 'disable':
            $admin = $findOrFail();
            $admins->update($admin['id'], static function (array &$a, array &$all) use ($command): void {
                if ('disable' === $command && 'superadmin' === $a['role'] && 0 === AdminRepository::activeSuperadmins($all, $a['id'])) {
                    throw new ValidationException('The last active super administrator cannot be disabled.');
                }
                $a['status'] = 'enable' === $command ? 'active' : 'disabled';
                $a['session_version']++;
            });
            $audit->record('admin.' . $command, 'success', $admin['username']);
            out(ucfirst($command) . 'd ' . $admin['username'] . '.');
            break;

        case 'verify-audit':
            $result = $audit->verify();
            if ($result['ok']) {
                out('Audit trail OK: ' . $result['entries'] . ' entries, hash chain unbroken.');
            } else {
                fail('Audit trail integrity check FAILED at line ' . $result['broken_at'] . '.', 2);
            }
            break;

        default:
            out(trim((string) preg_replace('/^ \* ?/m', '', explode('*/', explode('/**', (string) file_get_contents(__FILE__), 2)[1], 2)[0])));
            exit('help' === $command ? 0 : 1);
    }
} catch (ValidationException $invalid) {
    fail($invalid->getMessage());
} finally {
    fix_ownership();
}
