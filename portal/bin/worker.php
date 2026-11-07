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

function log_line(string $text): void
{
    fwrite(STDOUT, gmdate('Y-m-d H:i:s') . " $text\n");
}

/** Run every queued job, plus the scheduled sync when it is due. */
function tick(): void
{
    $directory = new Directory();
    $stale = Jobs::recoverStale();
    if ($stale > 0) {
        log_line("marked $stale interrupted job(s) as failed");
    }
    if ($directory->isScheduleDue(time())) {
        $job = Jobs::enqueue('directory.sync', [], 'scheduler');
        $directory->updateState(static function (array &$state): void {
            $state['last_scheduled_at'] = time();
        });
        log_line('scheduled directory sync ' . (empty($job['already_active']) ? 'queued' : 'skipped (one is already active)'));
    }
    while (null !== ($job = Jobs::claimNext())) {
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
                log_line("sync {$job['id']} $status " . json_encode($summary));
                break;

            case 'directory.preview':
                Jobs::progress($job['id'], 'Reading the directory');
                $result = $directory->preview();
                Jobs::finish($job['id'], $result['ok'] ? 'succeeded' : 'failed', $result, $result['ok'] ? null : $result['error']);
                $audit->record('directory.preview', $result['ok'] ? 'success' : 'failure', '', ['found' => $result['found'] ?? 0, 'job' => $job['id']]);
                log_line("preview {$job['id']} " . ($result['ok'] ? 'done' : 'failed'));
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
