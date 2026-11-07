<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Append-only, hash-chained audit trail (one JSON object per line).
 *
 * Every entry stores the hash of the previous one, so editing or deleting a
 * line breaks the chain and verify() reports where. Values whose key looks
 * like a secret are always replaced by "[redacted]" before they are written.
 */
final class Audit
{
    private const REDACT_KEYS = '/(pass|secret|seed|otp|credential|hash|private|^pin$|_pin$|^key$|_key$|^code$)/i';
    private const GENESIS = '0000000000000000000000000000000000000000000000000000000000000000';

    private static string $actor = 'anonymous';
    private static string $role = '';
    private static string $ip = '';

    public function __construct(private string $file)
    {
    }

    public static function default(): self
    {
        return new self(Config::auditFile());
    }

    public static function setActor(string $actor, string $role = ''): void
    {
        self::$actor = $actor;
        self::$role = $role;
    }

    public static function setIp(string $ip): void
    {
        self::$ip = $ip;
    }

    /**
     * @param string $action  dotted name, e.g. "admin.create"
     * @param string $result  "success", "failure" or "denied"
     */
    public function record(string $action, string $result, string $target = '', array $details = []): void
    {
        Config::ensureDataDir();
        $lock = fopen($this->file . '.lock', 'c');
        if (false === $lock || !flock($lock, LOCK_EX)) {
            throw new \RuntimeException('Cannot lock the audit trail.');
        }
        try {
            [$seq, $prev] = $this->lastLink();
            $entry = [
                'seq'     => $seq + 1,
                'time'    => gmdate('Y-m-d\TH:i:s\Z'),
                'actor'   => self::$actor,
                'role'    => self::$role,
                'ip'      => self::$ip,
                'action'  => $action,
                'result'  => $result,
                'target'  => $target,
                'details' => self::redact($details),
                'prev'    => $prev,
            ];
            $entry['hash'] = self::hashEntry($entry);
            $line = json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . "\n";
            if (false === file_put_contents($this->file, $line, FILE_APPEND)) {
                throw new \RuntimeException('Cannot write the audit trail.');
            }
            @chmod($this->file, 0600);
            file_put_contents($this->file . '.state', json_encode(['seq' => $entry['seq'], 'hash' => $entry['hash']]));
            @chmod($this->file . '.state', 0600);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /**
     * Newest first. Filters: actor, action (prefix), result, target, from, to (YYYY-MM-DD), q (free text).
     * @return array{entries: list<array>, total: int}
     */
    public function search(array $filters, int $page = 1, int $perPage = 50): array
    {
        $matches = [];
        foreach ($this->entries() as $entry) {
            if (self::matches($entry, $filters)) {
                $matches[] = $entry;
            }
        }
        $matches = array_reverse($matches);
        $page = max(1, $page);
        return [
            'entries' => array_slice($matches, ($page - 1) * $perPage, $perPage),
            'total'   => count($matches),
        ];
    }

    /** @return array{ok: bool, entries: int, broken_at: ?int} */
    public function verify(): array
    {
        $prev = self::GENESIS;
        $count = 0;
        foreach ($this->entries(false) as $lineNo => $entry) {
            $count++;
            if (!is_array($entry) || ($entry['prev'] ?? null) !== $prev || ($entry['hash'] ?? null) !== self::hashEntry($entry)) {
                return ['ok' => false, 'entries' => $count, 'broken_at' => $lineNo + 1];
            }
            $prev = $entry['hash'];
        }
        return ['ok' => true, 'entries' => $count, 'broken_at' => null];
    }

    public static function redact(array $details): array
    {
        $clean = [];
        foreach ($details as $key => $value) {
            if (is_string($key) && preg_match(self::REDACT_KEYS, $key)) {
                $clean[$key] = '[redacted]';
            } elseif (is_array($value)) {
                $clean[$key] = self::redact($value);
            } elseif (is_scalar($value) || null === $value) {
                $clean[$key] = $value;
            } else {
                $clean[$key] = get_debug_type($value);
            }
        }
        return $clean;
    }

    private static function hashEntry(array $entry): string
    {
        unset($entry['hash']);
        return hash('sha256', json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
    }

    /** @return array{0: int, 1: string} */
    private function lastLink(): array
    {
        $state = is_file($this->file . '.state') ? json_decode((string) file_get_contents($this->file . '.state'), true) : null;
        if (is_array($state) && isset($state['seq'], $state['hash'])) {
            return [(int) $state['seq'], (string) $state['hash']];
        }
        // State file missing: rebuild it from the trail itself
        $seq = 0;
        $hash = self::GENESIS;
        foreach ($this->entries() as $entry) {
            $seq = (int) $entry['seq'];
            $hash = (string) $entry['hash'];
        }
        return [$seq, $hash];
    }

    /** @return \Generator<int, mixed> */
    private function entries(bool $skipInvalid = true): \Generator
    {
        if (!is_file($this->file)) {
            return;
        }
        $handle = fopen($this->file, 'r');
        if (false === $handle) {
            throw new \RuntimeException('Cannot read the audit trail.');
        }
        try {
            $lineNo = 0;
            while (false !== ($line = fgets($handle))) {
                $entry = json_decode($line, true);
                if (is_array($entry) || !$skipInvalid) {
                    yield $lineNo => $entry;
                }
                $lineNo++;
            }
        } finally {
            fclose($handle);
        }
    }

    private static function matches(array $entry, array $f): bool
    {
        if (($f['actor'] ?? '') !== '' && 0 !== strcasecmp($entry['actor'] ?? '', $f['actor'])) {
            return false;
        }
        if (($f['action'] ?? '') !== '' && !str_starts_with($entry['action'] ?? '', $f['action'])) {
            return false;
        }
        if (($f['result'] ?? '') !== '' && ($entry['result'] ?? '') !== $f['result']) {
            return false;
        }
        if (($f['target'] ?? '') !== '' && 0 !== strcasecmp($entry['target'] ?? '', $f['target'])) {
            return false;
        }
        $day = substr($entry['time'] ?? '', 0, 10);
        if (($f['from'] ?? '') !== '' && $day < $f['from']) {
            return false;
        }
        if (($f['to'] ?? '') !== '' && $day > $f['to']) {
            return false;
        }
        if (($f['q'] ?? '') !== '') {
            $haystack = json_encode([$entry['actor'] ?? '', $entry['action'] ?? '', $entry['target'] ?? '', $entry['ip'] ?? '', $entry['details'] ?? []]);
            if (false === stripos((string) $haystack, $f['q'])) {
                return false;
            }
        }
        return true;
    }
}
