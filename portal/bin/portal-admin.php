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
 *   php portal/bin/portal-admin.php engine-key   (encrypt token secrets with a private key; status: --state=status)
 *   php portal/bin/portal-admin.php agent-release-add --file=sohobotp-agent-linux-amd64 --manifest=manifest.json
 *   php portal/bin/portal-admin.php agent-release-list
 *       signed agent releases for self-update (sign them OFFLINE: sohobotp-agent release sign)
 *   php portal/bin/portal-admin.php anonymous-stats [--state=on|off|status] [--once]
 *       multiOTP's weekly anonymous statistics (sent during a login, off by default in SohobOTP);
 *       --once does nothing if an administrator already chose (used at appliance start)
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
    if (preg_match('/^--(username|role|display-name|email|mfa-user|state|file|manifest)=(.*)$/s', $arg, $m)) {
        $options[$m[1]] = $m[2];
    } elseif ('--once' === $arg) {
        $options['once'] = true;
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
                : 'Second factor: SohobOTP user "' . $created['mfa_user'] . '". A new password is required at first sign-in.');
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

        case 'engine-key':
            if ('status' === ($options['state'] ?? '')) {
                out(Portal\EngineKey::isPublic() ? 'Token secrets use the PUBLIC default key: run engine-key.' : 'Token secrets use a private key (' . Portal\EngineKey::path() . ').');
                $legacy = Portal\MultiotpService::get();
                out('Legacy multiOTP admin password: ' . ('' === (string) $legacy->GetConfigAttribute('admin_password_hash') || $legacy->CheckAdminPassword(_MULTIOTP_DEFAULT_PASSWORD_) ? 'DEFAULT (1234): run engine-key.' : 'random.'));
                break;
            }
            if ('secondary' === ((new Portal\Ha())->state()['role'] ?? 'none')) {
                fail('This appliance is an HA secondary: it takes the key from its primary.');
            }
            if (Portal\MultiotpService::lockLegacyAdmin()) {
                $audit->record('engine.legacy_admin_locked', 'success');
                out('Legacy multiOTP admin password replaced by a random one.');
            }
            $summary = Portal\EngineKey::protect();
            if (!$summary['changed']) {
                out('Token secrets already use a private key.');
                break;
            }
            $audit->record('engine.key_protected', [] === $summary['failed'] ? 'success' : 'failure', '', $summary);
            out(sprintf('Re-encrypted %d user(s), %d token(s), %d RADIUS device(s), %d group(s) with a private key (%s).', $summary['users'], $summary['tokens'], $summary['devices'], $summary['groups'], Portal\EngineKey::path()));
            if ([] !== $summary['failed']) {
                fail('Not re-encrypted: ' . implode(', ', $summary['failed']), 2);
            }
            out('Back up this key file with your data: without it, the data cannot be read.');
            break;

        case 'agent-release-add':
            $manifest = json_decode((string) @file_get_contents((string) ($options['manifest'] ?? '')), true);
            if (!is_array($manifest)) {
                fail('--manifest must be the JSON file written by "sohobotp-agent release sign".');
            }
            $m = Portal\AgentReleases::add((string) ($options['file'] ?? ''), $manifest);
            $audit->record('agent.release_add', 'success', "{$m['os']}/{$m['arch']} {$m['version']}", ['sha256' => $m['sha256'], 'size' => $m['size']]);
            out("Added agent {$m['version']} for {$m['os']}/{$m['arch']}. Choose it as the target version of an endpoint group to roll it out.");
            break;

        case 'agent-release-list':
            foreach (Portal\AgentReleases::all() as $m) {
                out(sprintf('%-8s %-14s %10d bytes  %s', $m['version'], $m['os'] . '/' . $m['arch'], $m['size'], substr($m['sha256'], 0, 16)));
            }
            break;

        case 'anonymous-stats':
            $engine = Portal\MultiotpService::get();
            $state = $options['state'] ?? 'status';
            $marker = Config::ensureDataDir() . '/anonymous-stats.chosen';
            if ('status' === $state) {
                out('Anonymous statistics: ' . ($engine->IsAnonymousStat() ? 'on' : 'off') . (is_file($marker) ? ' (chosen by an administrator)' : ''));
                break;
            }
            if (!in_array($state, ['on', 'off'], true)) {
                fail('--state must be on, off or status.');
            }
            if (!empty($options['once']) && is_file($marker)) {
                out('Anonymous statistics already chosen by an administrator: left ' . ($engine->IsAnonymousStat() ? 'on' : 'off') . '.');
                break;
            }
            'on' === $state ? $engine->EnableAnonymousStat() : $engine->DisableAnonymousStat();
            if (!$engine->WriteConfigData()) {
                fail('The multiOTP configuration could not be written.');
            }
            file_put_contents($marker, $state . "\n");
            $audit->record('settings.anonymous_stats', 'success', $state);
            out('Anonymous statistics turned ' . $state . '.');
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
