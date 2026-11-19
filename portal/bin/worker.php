<?php
/**
 * multiOTP portal - background worker (command line only).
 *
 * Runs queued jobs (directory sync, sync preview) and the scheduled directory
 * sync, outside browser requests. Only one worker runs at a time (lock file).
 *
 *   php portal/bin/worker.php --loop     keep running, check every 10 s (systemd, Docker, dev server)
 *   php portal/bin/worker.php --once     run what is due, then exit (cron: * * * * *)
 *
 * Run it as the web server user (www-data) so the files it writes stay readable by the portal.
 */
declare(strict_types=1);

if ('cli' !== PHP_SAPI) {
    http_response_code(404);
    exit;
}

define('PORTAL_ROOT', dirname(__DIR__));
require PORTAL_ROOT . '/src/bootstrap.php';

use Portal\Audit;
use Portal\Config;
use Portal\Directory;
use Portal\Jobs;
use Portal\MultiotpService;

// Engine deprecation notices (PHP 8.4) are not useful in job output
error_reporting(E_ALL & ~E_DEPRECATED);
set_time_limit(0);

$mode = $argv[1] ?? '--once';
if (!in_array($mode, ['--once', '--loop'], true)) {
    fwrite(STDERR, "Usage: worker.php --once|--loop\n");
    exit(1);
}

$lock = fopen(Config::ensureDataDir() . '/worker.lock', 'c');
if (false === $lock || !flock($lock, LOCK_EX | LOCK_NB)) {
    fwrite(STDOUT, "Another worker is already running.\n");
    exit(0);
}

Audit::setIp('local');

// Token seeds must not stay encrypted with the engine's public default key (see EngineKey).
// Runs once on each appliance's first start (never at image build, so keys differ per appliance).
// An HA secondary never makes its own key: it adopts the primary's during the sync.
if (Config::hasEtcDir() && Portal\EngineKey::isPublic() && 'secondary' !== ((new Portal\Ha())->state()['role'] ?? 'none')) {
    try {
        $summary = Portal\EngineKey::protect();
        if ($summary['changed']) {
            Audit::setActor('system');
            Audit::default()->record('engine.key_protected', [] === $summary['failed'] ? 'success' : 'failure', '', $summary);
            fwrite(STDOUT, gmdate('Y-m-d H:i:s') . ' token secrets now encrypted with a private key: ' . json_encode($summary) . "\n");
        }
    } catch (Throwable $error) {
        fwrite(STDOUT, gmdate('Y-m-d H:i:s') . ' could not protect the engine key: ' . $error->getMessage() . "\n");
    }
}
// The legacy multiOTP admin API must not accept its default password (1234)
if (Config::hasEtcDir() && 'secondary' !== ((new Portal\Ha())->state()['role'] ?? 'none')) {
    try {
        if (MultiotpService::lockLegacyAdmin()) {
            Audit::setActor('system');
            Audit::default()->record('engine.legacy_admin_locked', 'success');
            fwrite(STDOUT, gmdate('Y-m-d H:i:s') . " legacy multiOTP admin password replaced by a random one\n");
        }
    } catch (Throwable $error) {
        fwrite(STDOUT, gmdate('Y-m-d H:i:s') . ' could not lock the legacy admin: ' . $error->getMessage() . "\n");
    }
}

function log_line(string $text): void
{
    fwrite(STDOUT, gmdate('Y-m-d H:i:s') . " $text\n");
}

/** Log a step of the loop that took more than 5 seconds (it delays every queued job). */
function timed(string $step, callable $fn): mixed
{
    $started = microtime(true);
    $result = $fn();
    $took = microtime(true) - $started;
    if ($took > 5) {
        log_line(sprintf('slow: %s took %.0f s', $step, $took));
    }
    return $result;
}

/** Run every queued job, plus the scheduled sync when it is due. */
function tick(): void
{
    $directory = new Directory();
    $stale = timed('recovering interrupted jobs', static fn (): int => Jobs::recoverStale());
    if ($stale > 0) {
        log_line("marked $stale interrupted job(s) as failed");
    }
    if (timed('directory schedule check', static fn (): bool => $directory->isScheduleDue(time()))) {
        $job = Jobs::enqueue('directory.sync', [], 'scheduler');
        $directory->updateState(static function (array &$state): void {
            $state['last_scheduled_at'] = time();
        });
        log_line('scheduled directory sync ' . (empty($job['already_active']) ? 'queued' : 'skipped (one is already active)'));
    }
    $endpoints = new Portal\Endpoints();
    if (timed('endpoint AD check due', static fn (): bool => $endpoints->isDirectoryCheckDue(time()))) {
        $job = Jobs::enqueue('endpoints.directory', [], 'scheduler');
        log_line('scheduled endpoint AD check ' . (empty($job['already_active']) ? 'queued' : 'skipped (one is already active)'));
    }
    // user groups change with directory syncs and edits: keep the RADIUS restriction data fresh
    if (timed('RADIUS routing refresh', static fn (): bool => (new Portal\VipMigration())->refreshIfStale(300))) {
        log_line('RADIUS routing file refreshed (user group restrictions)');
    }
    // install links: expired ones carry a usable enrolment token until their file is deleted
    timed('install links cleanup', static fn () => Portal\AgentLinks::cleanup(time()));
    timed('high availability', static function (): void {
        (new Portal\Ha())->tick(static fn (string $line) => log_line($line));
    });
    while (null !== ($job = timed('claiming the next job', static fn (): ?array => Jobs::claimNext()))) {
        log_line("running {$job['type']} {$job['id']} for {$job['requested_by']}");
        run_job($job, $directory);
        MultiotpService::reset();
    }
}

function run_job(array $job, Directory $directory): void
{
    Audit::setActor((string) $job['requested_by']);
    $audit = Audit::default();
    try {
        switch ($job['type']) {
            case 'directory.sync':
                Jobs::progress($job['id'], 'Synchronising with the directory');
                $result = $directory->sync();
                $cancelled = (bool) (Jobs::find($job['id'])['cancel_requested'] ?? false);
                $status = $cancelled ? 'cancelled' : ($result['ok'] ? 'succeeded' : 'failed');
                $error = $result['ok'] ? null : ($result['already_running']
                    ? 'Another synchronisation was already running (started from the command line?).'
                    : 'The synchronisation reported an error. See the engine messages.');
                Jobs::finish($job['id'], $status, $result, $cancelled ? null : $error);
                $summary = [
                    'created'  => count($result['created']),
                    'disabled' => count($result['disabled']),
                    'enabled'  => count($result['enabled']),
                    'deleted'  => count($result['deleted']),
                    'job'      => $job['id'],
                ];
                $directory->updateState(static function (array &$state) use ($job, $status, $summary): void {
                    $state['last_sync'] = ['job' => $job['id'], 'status' => $status, 'at' => time(), 'summary' => $summary];
                });
                $audit->record('directory.sync', 'succeeded' === $status ? 'success' : ('cancelled' === $status ? 'denied' : 'failure'), '', $summary);
                (new Portal\VipMigration())->export(); // new or changed users and groups
                log_line("sync {$job['id']} $status " . json_encode($summary));
                break;

            case 'directory.preview':
                Jobs::progress($job['id'], 'Reading the directory');
                $result = $directory->preview();
                Jobs::finish($job['id'], $result['ok'] ? 'succeeded' : 'failed', $result, $result['ok'] ? null : $result['error']);
                $audit->record('directory.preview', $result['ok'] ? 'success' : 'failure', '', ['found' => $result['found'] ?? 0, 'job' => $job['id']]);
                log_line("preview {$job['id']} " . ($result['ok'] ? 'done' : 'failed'));
                break;

            case 'radius.apply':
                Jobs::progress($job['id'], 'Checking and applying the FreeRADIUS configuration');
                $result = (new Portal\Radius())->apply();
                $error = $result['ok'] ? null : ($result['available']
                    ? 'FreeRADIUS refused the configuration; the previous one is still active.'
                    : 'The FreeRADIUS helper is not available on this system.');
                Jobs::finish($job['id'], $result['ok'] ? 'succeeded' : 'failed', ['log' => explode("\n", $result['output'])], $error);
                $audit->record('radius.apply', $result['ok'] ? 'success' : 'failure', '', ['job' => $job['id']]);
                log_line("radius apply {$job['id']} " . ($result['ok'] ? 'applied' : 'failed'));
                break;

            case 'database.migrate':
                $connection = json_decode(Portal\Crypto::decrypt((string) ($job['params']['connection'] ?? '')), true);
                if (!is_array($connection)) {
                    Jobs::finish($job['id'], 'failed', null, 'The connection details of this job cannot be read.');
                    break;
                }
                $result = Portal\Database::migrate($connection, static fn (string $step) => Jobs::progress($job['id'], $step));
                Jobs::finish($job['id'], $result['ok'] ? 'succeeded' : 'failed', ['before' => $result['before'], 'after' => $result['after']], $result['error']);
                $audit->record('database.migrate', $result['ok'] ? 'success' : 'failure', $connection['host'] ?? '', ['before' => $result['before'], 'after' => $result['after'], 'job' => $job['id']]);
                log_line("database migrate {$job['id']} " . ($result['ok'] ? 'done ' . json_encode($result['after']) : 'failed: ' . $result['error']));
                break;

            case 'radius.vip_seed':
                Jobs::progress($job['id'], 'Finding the users who already sign in with SohobOTP');
                $migration = new Portal\VipMigration();
                $marked = $migration->seed((string) $job['requested_by']);
                $counts = $migration->counts();
                $result = ['marked' => $marked, 'on_sohobotp' => $counts['sohobotp'], 'sent_back' => $counts['vip']];
                Jobs::finish($job['id'], 'succeeded', $result);
                $audit->record('radius.vip_seed', 'success', '', $result + ['job' => $job['id']]);
                log_line("vip seed {$job['id']}: " . json_encode($result));
                break;

            case 'endpoints.directory':
                Jobs::progress($job['id'], 'Reading computer accounts in Active Directory');
                $only = $job['params']['endpoint'] ?? null;
                $result = (new Portal\Endpoints())->checkDirectory(is_string($only) ? $only : null);
                Jobs::finish($job['id'], 'succeeded', $result);
                Audit::setActor('directory-rules');
                foreach ($result['approved'] as $id) {
                    $audit->record('endpoint.approve', 'success', $id, ['endpoint' => $id, 'by' => 'active-directory', 'job' => $job['id']]);
                }
                foreach ($result['moved'] as $move) {
                    $audit->record('endpoint.move', 'success', $move['endpoint'], $move + ['by' => 'active-directory', 'job' => $job['id']]);
                }
                log_line("endpoint AD check {$job['id']}: " . json_encode(['checked' => $result['checked'], 'found' => $result['found'], 'approved' => count($result['approved']), 'moved' => count($result['moved'])]));
                break;

            default:
                Jobs::finish($job['id'], 'failed', null, 'Unknown job type.');
        }
    } catch (\Throwable $error) {
        $message = $error instanceof Portal\ValidationException ? $error->getMessage() : 'Unexpected error: ' . $error->getMessage();
        Jobs::finish($job['id'], 'failed', null, $message);
        $audit->record($job['type'], 'failure', '', ['job' => $job['id'], 'reason' => $message]);
        log_line("{$job['type']} {$job['id']} failed: $message");
    }
}

if ('--once' === $mode) {
    tick();
    exit(0);
}

log_line('worker started');
while (true) {
    try {
        tick();
    } catch (\Throwable $error) {
        log_line('error: ' . $error->getMessage());
    }
    sleep(10);
}
