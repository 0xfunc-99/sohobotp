<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Migration from Symantec VIP: which users sign in with SohobOTP, and the routing file
 * FreeRADIUS reads for every request (bin/sohobotp-vip-route, installed by the helper).
 *
 * On a server group with "Forward users who are not on SohobOTP yet" switched on, a login
 * is checked by SohobOTP when the user is ON SOHOBOTP here, and forwarded unchanged to the
 * Symantec VIP Enterprise Gateway (Radius::vipSettings) otherwise, including users SohobOTP
 * does not know. A user is on SohobOTP when an administrator moved them, when an
 * authenticator was enrolled or a hardware token assigned in the portal, or (once, when
 * forwarding is first switched on: seed()) when they already have a hardware token or have
 * signed in with SohobOTP before. "Send back to Symantec VIP" is remembered too.
 *
 * vip-migration.json: { users: { "<lower-case name>": {state, at, by, how} }, seeded_at }
 */
final class VipMigration
{
    public const STATES = ['sohobotp' => 'SohobOTP', 'vip' => 'Symantec VIP'];

    private JsonStore $store;

    public function __construct(?JsonStore $store = null)
    {
        $this->store = $store ?? new JsonStore(Config::dataDir() . '/vip-migration.json');
    }

    public static function routeFile(): string
    {
        return Config::vipRouteFile();
    }

    private static function key(string $user): string
    {
        return mb_strtolower(trim($user), 'UTF-8');
    }

    /** @return ?array{state: string, at: int, by: string, how: string} null: never set */
    public function stateOf(string $user): ?array
    {
        return $this->store->read()['users'][self::key($user)] ?? null;
    }

    public function isOnSohobotp(string $user): bool
    {
        return 'sohobotp' === ($this->stateOf($user)['state'] ?? null);
    }

    /** @param list<string> $users */
    public function set(array $users, string $state, string $by, string $how): int
    {
        if (!isset(self::STATES[$state])) {
            throw new ValidationException('Unknown sign-in route.');
        }
        $changed = $this->store->update(static function (array &$data) use ($users, $state, $by, $how): int {
            $changed = 0;
            foreach ($users as $user) {
                $key = self::key($user);
                if ('' === $key) {
                    continue;
                }
                if (($data['users'][$key]['state'] ?? null) !== $state) {
                    $changed++;
                }
                $data['users'][$key] = ['state' => $state, 'at' => time(), 'by' => mb_substr($by, 0, 64), 'how' => $how];
            }
            return $changed;
        });
        $this->export();
        return $changed;
    }

    /** A deleted user: a new account with the same name starts again from Symantec VIP. */
    public function forget(string $user): void
    {
        $this->store->update(static function (array &$data) use ($user): void {
            unset($data['users'][self::key($user)]);
        });
        $this->export();
    }

    /** @return array{sohobotp: int, vip: int, seeded_at: ?int} */
    public function counts(): array
    {
        $data = $this->store->read();
        $counts = ['sohobotp' => 0, 'vip' => 0, 'seeded_at' => $data['seeded_at'] ?? null];
        foreach ($data['users'] ?? [] as $entry) {
            $counts[$entry['state']] = ($counts[$entry['state']] ?? 0) + 1;
        }
        return $counts;
    }

    public function isSeeded(): bool
    {
        return null !== ($this->store->read()['seeded_at'] ?? null);
    }

    /**
     * Mark as on SohobOTP the users who already use it: a hardware token, or a successful
     * SohobOTP login before. Users with a route set by hand keep it. Runs in the worker.
     * @return int users marked
     */
    public function seed(string $by): int
    {
        $users = new Users();
        $known = $this->store->read()['users'] ?? [];
        $marked = [];
        $all = MultiotpService::get()->ApiGetUsersArray(['page' => 1, 'itemsPerPage' => 1000000])['users'] ?? [];
        foreach ($all as $row) {
            $name = (string) ($row['user'] ?? '');
            if ('' === $name || isset($known[self::key($name)])) {
                continue;
            }
            if ('' !== (string) ($row['token'] ?? '')) {
                $marked[] = $name;
                continue;
            }
            $user = $users->get($name);
            if (null !== $user && null !== $user['last_login']) {
                $marked[] = $name;
            }
        }
        if ([] !== $marked) {
            $this->set($marked, 'sohobotp', $by, 'already using SohobOTP');
        }
        $this->store->update(static function (array &$data): void {
            $data['seeded_at'] = time();
        });
        $this->export();
        return count($marked);
    }

    /**
     * Write the routing file read by FreeRADIUS for every request:
     * - forwarding to Symantec VIP: on only when the servers are configured AND applied
     *   (otherwise FreeRADIUS has no realm to forward to), for the RADIUS clients of server
     *   groups with forwarding switched on;
     * - user group restriction: for the RADIUS clients of server groups with "only these user
     *   groups", the allowed groups and every user's groups (multiOTP group attribute, a
     *   comma list with multiple AD groups).
     * @return array{enabled: bool, clients: int, sohobotp: int, restricted: int, file: string, written: bool}
     */
    public function export(): array
    {
        if (Ha::isSecondary()) { // the routing file comes from the primary (Ha::sync)
            return ['enabled' => false, 'clients' => 0, 'sohobotp' => 0, 'restricted' => 0, 'file' => self::routeFile(), 'written' => false];
        }
        $radius = new Radius();
        $clients = $radius->vipActive() ? $radius->forwardingClients() : [];
        $sohobotp = [];
        foreach ($this->store->read()['users'] ?? [] as $key => $entry) {
            if ('sohobotp' === $entry['state']) {
                $sohobotp[(string) $key] = 1;
            }
        }
        $restrict = $radius->restrictedClients();
        $groups = [];
        if ([] !== $restrict) {
            foreach (MultiotpService::get()->ApiGetUsersArray(['page' => 1, 'itemsPerPage' => 1000000])['users'] ?? [] as $row) {
                if (empty($row['enabled'])) {
                    continue; // disabled users are refused by multiOTP anyway
                }
                $list = array_values(array_filter(array_map(static fn (string $g): string => mb_strtolower(trim($g), 'UTF-8'), explode(',', (string) ($row['group'] ?? ''))), 'strlen'));
                if ([] !== $list) {
                    $groups[self::key((string) $row['user'])] = $list;
                }
            }
        }
        // lost or stolen Linux computers: no user group is allowed, every login is rejected
        // (and nothing is forwarded to Symantec VIP for them)
        $lost = (new Endpoints())->lostRadiusClients($radius);
        $restrict = array_merge($restrict, $lost);
        $clients = array_values(array_diff($clients, array_keys($lost)));
        $route = ['enabled' => [] !== $clients, 'clients' => (object) array_fill_keys($clients, 1), 'sohobotp' => (object) $sohobotp,
            'restrict' => (object) $restrict, 'groups' => (object) $groups, 'at' => time()];
        $file = self::routeFile();
        $written = false;
        $dir = dirname($file);
        if (is_dir($dir) || @mkdir($dir, 0750, true)) {
            $tmp = $file . '.' . bin2hex(random_bytes(4)) . '.tmp';
            if (false !== @file_put_contents($tmp, json_encode($route, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE))) {
                @chmod($tmp, 0640);
                $written = @rename($tmp, $file);
            }
            if (!$written) {
                @unlink($tmp);
            }
        }
        return ['enabled' => $route['enabled'], 'clients' => count($clients), 'sohobotp' => count($sohobotp), 'restricted' => count($restrict), 'file' => $file, 'written' => $written];
    }

    /** Re-export when user groups may have changed (worker): restrictions only, at most every $seconds. */
    public function refreshIfStale(int $seconds): bool
    {
        $file = self::routeFile();
        if ([] === (new Radius())->restrictedClients() || (is_file($file) && filemtime($file) > time() - $seconds)) {
            return false;
        }
        $this->export();
        return true;
    }

    /**
     * Forwarded logins and logins refused by a user group restriction (FreeRADIUS
     * linelog, newest first). result: accept | reject (Symantec VIP) | denied (user group).
     * @return list<array{time: string, result: string, user: string, server: string}>
     */
    public static function recentForwarded(string $userFilter = '', int $limit = 100): array
    {
        $file = Config::logDir() . 'sohobotp-vip.log';
        if (!is_file($file) || !is_readable($file)) {
            return [];
        }
        $handle = fopen($file, 'r');
        if (false === $handle) {
            return [];
        }
        fseek($handle, max(0, (int) filesize($file) - 1_000_000));
        $lines = explode("\n", (string) stream_get_contents($handle));
        fclose($handle);
        $out = [];
        foreach (array_reverse($lines) as $line) {
            $parts = explode("\t", $line);
            if (4 !== count($parts) || !in_array($parts[1], ['accept', 'reject', 'denied'], true)) {
                continue;
            }
            if ('' !== $userFilter && !str_contains(mb_strtolower($parts[2]), mb_strtolower($userFilter))) {
                continue;
            }
            $out[] = ['time' => $parts[0], 'result' => $parts[1], 'user' => $parts[2], 'server' => $parts[3]];
            if (count($out) >= $limit) {
                break;
            }
        }
        return $out;
    }
}
