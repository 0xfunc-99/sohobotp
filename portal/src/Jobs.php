<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Background job queue: one JSON file per job in <data>/jobs/.
 * Browser requests only enqueue jobs; portal/bin/worker.php runs them, so long
 * operations (directory sync, previews) never depend on a browser staying open.
 *
 * Job fields: id, type, params, status (queued|running|succeeded|failed|cancelled),
 * requested_by, created_at, started_at, finished_at, worker_pid, progress,
 * cancel_requested, result, error
 */
final class Jobs
{
    public const ACTIVE = ['queued', 'running'];
    private const KEEP = 200;

    public static function dir(): string
    {
        $dir = Config::ensureDataDir() . '/jobs';
        if (!is_dir($dir) && !@mkdir($dir, 0700) && !is_dir($dir)) {
            throw new \RuntimeException('Cannot create the jobs folder.');
        }
        return $dir;
    }

    /** Queue a job, unless one of the same type is already queued or running (then that one is returned). */
    public static function enqueue(string $type, array $params, string $requestedBy): array
    {
        return self::locked(static function () use ($type, $params, $requestedBy): array {
            foreach (self::all() as $job) {
                if ($job['type'] === $type && in_array($job['status'], self::ACTIVE, true)) {
                    return $job + ['already_active' => true];
                }
            }
            $job = [
                'id'               => gmdate('YmdHis') . '-' . bin2hex(random_bytes(4)),
                'type'             => $type,
                'params'           => $params,
                'status'           => 'queued',
                'requested_by'     => $requestedBy,
                'created_at'       => time(),
                'started_at'       => null,
                'finished_at'      => null,
                'worker_pid'       => null,
                'progress'         => 'Waiting for the background worker',
                'cancel_requested' => false,
                'result'           => null,
                'error'            => null,
            ];
            self::write($job);
            self::prune();
            return $job;
        });
    }

    public static function find(string $id): ?array
    {
        if (!preg_match('/^\d{14}-[0-9a-f]{8}$/', $id)) {
            return null;
        }
        $file = self::dir() . "/$id.json";
        if (!is_file($file)) {
            return null;
        }
        $job = json_decode((string) file_get_contents($file), true);
        return is_array($job) ? $job : null;
    }

    /** @return list<array> newest first */
    public static function all(?string $type = null): array
    {
        $jobs = [];
        foreach (glob(self::dir() . '/*.json') ?: [] as $file) {
            $job = json_decode((string) file_get_contents($file), true);
            if (is_array($job) && (null === $type || $job['type'] === $type)) {
                $jobs[] = $job;
            }
        }
        usort($jobs, static fn (array $a, array $b): int => strcmp($b['id'], $a['id']));
        return $jobs;
    }

    public static function latest(string $type): ?array
    {
        return self::all($type)[0] ?? null;
    }

    /** Oldest queued job, marked running for this worker. */
    public static function claimNext(): ?array
    {
        return self::locked(static function (): ?array {
            $queued = array_values(array_filter(self::all(), static fn (array $j): bool => 'queued' === $j['status']));
            if ([] === $queued) {
                return null;
            }
            $job = end($queued);
            $job['status'] = 'running';
            $job['started_at'] = time();
            $job['worker_pid'] = getmypid();
            $job['progress'] = 'Starting';
            self::write($job);
            return $job;
        });
    }

    public static function update(string $id, callable $mutate): ?array
    {
        return self::locked(static function () use ($id, $mutate): ?array {
            $job = self::find($id);
            if (null === $job) {
                return null;
            }
            $mutate($job);
            self::write($job);
            return $job;
        });
    }

    public static function progress(string $id, string $message): void
    {
        self::update($id, static function (array &$job) use ($message): void {
            $job['progress'] = $message;
        });
    }

    public static function finish(string $id, string $status, ?array $result, ?string $error = null): ?array
    {
        return self::update($id, static function (array &$job) use ($status, $result, $error): void {
            $job['status'] = $status;
            $job['finished_at'] = time();
            $job['result'] = $result;
            $job['error'] = $error;
            $job['progress'] = match ($status) {
                'succeeded' => 'Finished',
                'cancelled' => 'Cancelled',
                default     => 'Failed',
            };
        });
    }

    /** Cancel a queued job, or ask a running one to stop. */
    public static function cancel(string $id): ?array
    {
        return self::update($id, static function (array &$job): void {
            if ('queued' === $job['status']) {
                $job['status'] = 'cancelled';
                $job['finished_at'] = time();
                $job['progress'] = 'Cancelled before it started';
            } elseif ('running' === $job['status']) {
                $job['cancel_requested'] = true;
                $job['progress'] = 'Stopping…';
            }
        });
    }

    /** Running jobs whose worker process is gone (crash, container restart) are marked failed. */
    public static function recoverStale(): int
    {
        return self::locked(static function (): int {
            $count = 0;
            foreach (self::all() as $job) {
                if ('running' !== $job['status']) {
                    continue;
                }
                $pid = (int) $job['worker_pid'];
                $alive = $pid > 0 && $pid !== getmypid() && function_exists('posix_kill') && posix_kill($pid, 0);
                if (!$alive && $pid !== getmypid()) {
                    $job['status'] = 'failed';
                    $job['finished_at'] = time();
                    $job['error'] = 'The background worker stopped while this job was running.';
                    $job['progress'] = 'Failed';
                    self::write($job);
                    $count++;
                }
            }
            return $count;
        });
    }

    private static function write(array $job): void
    {
        $file = self::dir() . '/' . $job['id'] . '.json';
        $tmp = $file . '.tmp-' . bin2hex(random_bytes(4));
        file_put_contents($tmp, json_encode($job, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
        @chmod($tmp, 0600);
        rename($tmp, $file);
    }

    private static function prune(): void
    {
        $finished = array_values(array_filter(self::all(), static fn (array $j): bool => !in_array($j['status'], self::ACTIVE, true)));
        foreach (array_slice($finished, self::KEEP) as $old) {
            @unlink(self::dir() . '/' . $old['id'] . '.json');
        }
    }

    private static function locked(callable $fn): mixed
    {
        $handle = fopen(self::dir() . '/.lock', 'c');
        if (false === $handle || !flock($handle, LOCK_EX)) {
            throw new \RuntimeException('Cannot lock the job queue.');
        }
        try {
            return $fn();
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}
