<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Captures the multiOTP engine log lines written during one operation
 * (connection test, preview, sync) so they can be shown with the result.
 * Only works with the file log; with a SQL backend the list stays empty.
 */
final class EngineLog
{
    private string $file;
    private int $offset;

    public function __construct(\Multiotp $engine)
    {
        $engine->EnableLog();
        $this->file = $engine->GetLogFolder() . $engine->GetLogFileName();
        clearstatcache(true, $this->file);
        $this->offset = is_file($this->file) ? (int) filesize($this->file) : 0;
    }

    /** @return list<string> "level: message", LDAP and system categories only */
    public function lines(int $max = 200): array
    {
        clearstatcache(true, $this->file);
        if (!is_file($this->file) || filesize($this->file) <= $this->offset) {
            return [];
        }
        $handle = fopen($this->file, 'r');
        if (false === $handle) {
            return [];
        }
        fseek($handle, $this->offset);
        $raw = (string) stream_get_contents($handle, 2_000_000);
        fclose($handle);
        $lines = [];
        foreach (preg_split('/\r?\n/', $raw) ?: [] as $line) {
            $columns = explode("\t", $line);
            if (count($columns) < 5 || !in_array($columns[3], ['LDAP', 'System'], true)) {
                continue;
            }
            $message = trim($columns[4]);
            if ('' === $message || str_starts_with($message, 'Debug:') || str_starts_with($message, 'Developer:')) {
                continue;
            }
            $lines[] = $message;
        }
        return array_slice($lines, -$max);
    }
}
