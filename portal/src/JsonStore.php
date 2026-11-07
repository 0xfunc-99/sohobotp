<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * A JSON document on disk, protected by an advisory lock file.
 * Writes go to a temporary file that is renamed over the original, so a
 * crash never leaves a half-written document behind.
 */
final class JsonStore
{
    public function __construct(private string $path)
    {
    }

    public function read(): array
    {
        $lock = $this->lock(LOCK_SH);
        try {
            return $this->load();
        } finally {
            $this->unlock($lock);
        }
    }

    /**
     * Read, modify and write under an exclusive lock.
     * $mutate receives the document by reference; its return value is passed through.
     */
    public function update(callable $mutate): mixed
    {
        $lock = $this->lock(LOCK_EX);
        try {
            $data = $this->load();
            $result = $mutate($data);
            $this->save($data);
            return $result;
        } finally {
            $this->unlock($lock);
        }
    }

    private function load(): array
    {
        if (!is_file($this->path)) {
            return [];
        }
        $raw = file_get_contents($this->path);
        if (false === $raw) {
            throw new \RuntimeException('Cannot read ' . basename($this->path));
        }
        if ('' === trim($raw)) {
            return [];
        }
        $data = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($data)) {
            throw new \RuntimeException('Corrupted ' . basename($this->path));
        }
        return $data;
    }

    private function save(array $data): void
    {
        $tmp = $this->path . '.tmp-' . bin2hex(random_bytes(6));
        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        if (false === file_put_contents($tmp, $json . "\n")) {
            throw new \RuntimeException('Cannot write ' . basename($this->path));
        }
        @chmod($tmp, 0600);
        if (!rename($tmp, $this->path)) {
            @unlink($tmp);
            throw new \RuntimeException('Cannot replace ' . basename($this->path));
        }
    }

    /** @return resource */
    private function lock(int $mode)
    {
        Config::ensureDataDir();
        $handle = fopen($this->path . '.lock', 'c');
        if (false === $handle || !flock($handle, $mode)) {
            throw new \RuntimeException('Cannot lock ' . basename($this->path));
        }
        @chmod($this->path . '.lock', 0600);
        return $handle;
    }

    /** @param resource $handle */
    private function unlock($handle): void
    {
        flock($handle, LOCK_UN);
        fclose($handle);
    }
}
