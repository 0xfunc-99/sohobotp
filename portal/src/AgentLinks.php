<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Install links: "Add a computer" can give a one-time address instead of a download, so a Linux
 * machine fetches the agent itself (wget on the machine, nothing to copy from a browser).
 *
 * The file behind a link is built when the link is made (the same agent and settings, with a
 * new enrolment token, as the download buttons), kept in <data>/agent-links/ (0600) and given
 * out ONCE, before the link expires; then it is deleted. The command the portal shows checks
 * the file's SHA-256 before installing it, so a self-signed portal certificate (wget
 * --no-check-certificate) cannot be used to hand the machine another file.
 *
 * Only the SHA-256 of the link's key is stored. Wrong keys count against the address (Throttle).
 * Public entry point: portal/get.php?k=<key>.
 */
final class AgentLinks
{
    private const KEY = '/^[A-Za-z0-9_-]{43}$/';

    public static function dir(): string
    {
        $dir = Config::ensureDataDir() . '/agent-links';
        if (!is_dir($dir) && !@mkdir($dir, 0700) && !is_dir($dir)) {
            throw new \RuntimeException('Cannot create the install links folder.');
        }
        return $dir;
    }

    private static function store(): JsonStore
    {
        return new JsonStore(Config::ensureDataDir() . '/agent-links.json');
    }

    /**
     * Keep a file behind a new one-time link.
     * @param array{label: string, token_id: string, platform: string, format: string, created_by: string} $meta
     * @return array{key: string, sha256: string, size: int, expires_at: int, file_name: string}
     */
    public static function create(string $content, string $fileName, string $contentType, int $expiresAt, array $meta, int $now): array
    {
        self::cleanup($now);
        $key = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $id = hash('sha256', $key);
        $file = self::dir() . '/' . $id . '.bin';
        if (false === file_put_contents($file, $content, LOCK_EX)) {
            throw new \RuntimeException('Cannot store the install link file.');
        }
        @chmod($file, 0600);
        $record = [
            'file_name' => $fileName, 'type' => $contentType, 'sha256' => hash('sha256', $content), 'size' => strlen($content),
            'created_at' => $now, 'expires_at' => $expiresAt, 'used_at' => null,
        ] + $meta;
        self::store()->update(static function (array &$data) use ($id, $record): void {
            $data[$id] = $record;
        });
        return ['key' => $key, 'sha256' => $record['sha256'], 'size' => $record['size'], 'expires_at' => $expiresAt, 'file_name' => $fileName];
    }

    /**
     * Use a link: the file's content and its record, or null when the key is unknown, used or
     * expired. A link can be used once: it is marked used before the file is read.
     * @return ?array{content: string, record: array}
     */
    public static function take(string $key, int $now): ?array
    {
        if (!preg_match(self::KEY, $key)) {
            return null;
        }
        $id = hash('sha256', $key);
        $record = self::store()->update(static function (array &$data) use ($id, $now): ?array {
            $record = $data[$id] ?? null;
            if (null === $record || null !== $record['used_at'] || $record['expires_at'] <= $now) {
                return null;
            }
            $data[$id]['used_at'] = $now;
            return $record;
        });
        if (null === $record) {
            return null;
        }
        $file = self::dir() . '/' . $id . '.bin';
        $content = @file_get_contents($file);
        @unlink($file);
        return false === $content ? null : ['content' => $content, 'record' => $record];
    }

    /** Forget used and expired links and delete their files (kept a day for the record). */
    public static function cleanup(int $now): void
    {
        $dir = self::dir();
        self::store()->update(static function (array &$data) use ($dir, $now): void {
            foreach ($data as $id => $record) {
                if (null !== $record['used_at'] || $record['expires_at'] <= $now) {
                    @unlink($dir . '/' . $id . '.bin');
                    if (max((int) $record['used_at'], (int) $record['expires_at']) < $now - 86400) {
                        unset($data[$id]);
                    }
                }
            }
        });
    }

    /** Links not used yet, newest first (for the page). @return list<array> */
    public static function open(int $now): array
    {
        $open = array_values(array_filter(self::store()->read(), static fn (array $r): bool => null === $r['used_at'] && $r['expires_at'] > $now));
        usort($open, static fn (array $a, array $b): int => $b['created_at'] <=> $a['created_at']);
        return $open;
    }

    /**
     * The commands an administrator pastes on the Linux machine.
     * @return list<string>
     */
    public static function commands(string $url, string $sha256, string $format, bool $selfSigned): array
    {
        $file = 'deb' === $format ? 'sohobotp-agent.deb' : 'sohobotp-agent';
        $get = 'wget -q' . ($selfSigned ? ' --no-check-certificate' : '') . ' -O ' . $file . " '" . $url . "'";
        $check = "echo '" . $sha256 . '  ' . $file . "' | sha256sum -c -";
        return 'deb' === $format
            ? [$get, $check . ' && sudo apt install ./' . $file]
            : [$get, $check . ' && chmod +x ' . $file . ' && sudo ./' . $file . ' install'];
    }

    /** portal/get.php: hand out the file of a link, once. */
    public static function serve(): never
    {
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        Audit::setIp($ip);
        $throttle = new Throttle(new JsonStore(Config::dataDir() . '/agent-throttle.json'));
        $https = (!empty($_SERVER['HTTPS']) && 'off' !== strtolower((string) $_SERVER['HTTPS'])) || '443' === (string) ($_SERVER['SERVER_PORT'] ?? '');
        if (!$https && !Config::allowHttp()) {
            self::refuse(403, 'HTTPS is required.');
        }
        if (!in_array($_SERVER['REQUEST_METHOD'] ?? '', ['GET', 'HEAD'], true)) {
            self::refuse(405, 'Use GET.');
        }
        if ($throttle->isBlocked($ip)) {
            self::refuse(429, 'Too many wrong install links from this address. Try again later.');
        }
        $taken = self::take((string) ($_GET['k'] ?? ''), time());
        Audit::setActor('install link');
        if (null === $taken) {
            $throttle->fail($ip);
            self::refuse(404, 'This install link is not valid: it was already used, it expired, or it is incomplete. Make a new one in the portal (Add a computer).');
        }
        $r = $taken['record'];
        Audit::default()->record('endpoint.agent_link_used', 'success', $r['label'], [
            'token' => $r['token_id'], 'platform' => $r['platform'], 'format' => $r['format'], 'sha256' => $r['sha256'],
        ]);
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
        header('Content-Type: ' . $r['type']);
        header('Content-Disposition: attachment; filename="' . $r['file_name'] . '"');
        header('Content-Length: ' . strlen($taken['content']));
        echo $taken['content'];
        exit;
    }

    private static function refuse(int $status, string $message): never
    {
        http_response_code($status);
        header('Content-Type: text/plain; charset=utf-8');
        echo $message, "\n";
        exit;
    }
}
