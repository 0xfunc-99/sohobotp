<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * A small zip writer (the appliance's PHP has zlib but not the zip extension). Files are
 * deflated when that makes them smaller, else stored. Names are UTF-8, no zip64: enough for
 * the Group Policy kit (a few files, some megabytes).
 */
final class ZipWriter
{
    private string $body = '';
    private string $directory = '';
    private int $count = 0;
    private int $dosTime;
    private int $dosDate;

    public function __construct(int $now)
    {
        $t = getdate($now);
        $this->dosTime = ($t['hours'] << 11) | ($t['minutes'] << 5) | intdiv($t['seconds'], 2);
        $this->dosDate = (max(0, $t['year'] - 1980) << 9) | ($t['mon'] << 5) | $t['mday'];
    }

    public function add(string $name, string $data): void
    {
        if ('' === $name || strlen($name) > 255 || str_contains($name, '..') || str_starts_with($name, '/') || strlen($data) > 0x7fffffff) {
            throw new \InvalidArgumentException('Invalid zip entry: ' . $name);
        }
        $method = 0;
        $packed = $data;
        if (function_exists('gzdeflate') && '' !== $data) {
            $deflated = gzdeflate($data, 6);
            if (false !== $deflated && strlen($deflated) < strlen($data)) {
                $method = 8;
                $packed = $deflated;
            }
        }
        // version 2.0, flag bit 11 (UTF-8 names)
        $common = pack('vvvvvVVVvv', 20, 0x0800, $method, $this->dosTime, $this->dosDate, crc32($data), strlen($packed), strlen($data), strlen($name), 0);
        $offset = strlen($this->body);
        $this->body .= "PK\x03\x04" . $common . $name . $packed;
        $this->directory .= "PK\x01\x02" . pack('v', 20) . $common . pack('vvvVV', 0, 0, 0, 0, $offset) . $name;
        $this->count++;
    }

    public function finish(): string
    {
        return $this->body . $this->directory
            . "PK\x05\x06" . pack('vvvvVVv', 0, 0, $this->count, $this->count, strlen($this->directory), strlen($this->body), 0);
    }
}
