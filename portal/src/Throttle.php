<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/** Per-IP brute-force protection for the login and MFA forms. */
final class Throttle
{
    private JsonStore $store;

    public function __construct(?JsonStore $store = null)
    {
        $this->store = $store ?? new JsonStore(Config::dataDir() . '/throttle.json');
    }

    public function isBlocked(string $ip): bool
    {
        $entry = $this->store->read()[$ip] ?? null;
        return null !== $entry
            && $entry['first'] > time() - Config::ipWindow()
            && $entry['count'] >= Config::ipMaxFailures();
    }

    public function fail(string $ip): void
    {
        $this->store->update(static function (array &$data) use ($ip): void {
            $now = time();
            $window = Config::ipWindow();
            foreach ($data as $key => $entry) {
                if ($entry['first'] <= $now - $window) {
                    unset($data[$key]);
                }
            }
            $data[$ip] ??= ['count' => 0, 'first' => $now];
            $data[$ip]['count']++;
        });
    }

    public function clear(string $ip): void
    {
        $this->store->update(static function (array &$data) use ($ip): void {
            unset($data[$ip]);
        });
    }
}
