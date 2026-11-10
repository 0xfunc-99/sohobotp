<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * API keys for the REST API (portal/api.php, src/Api.php).
 *
 * A key is "sohob_<id>_<secret>"; only the SHA-256 of the secret is stored, the key is shown
 * once. Every key has scopes (what it may do), an optional list of allowed client networks,
 * an optional expiry and a rate limit (requests per minute).
 *
 * api-keys.json: { keys: { id: {id, name, hash, scopes, networks, expires_at, rate,
 *                  created_at, created_by, last_used_at, last_ip} }, rate: { id: {minute, count} } }
 */
final class ApiKeys
{
    public const SCOPES = [
        'users.read'     => 'Read users',
        'users.write'    => 'Create, change, unlock, delete users; move them between Symantec VIP and SohobOTP',
        'tokens.write'   => 'Enrol authenticators (returns the provisioning link)',
        'auth.check'     => 'Check a user\'s code (for other applications)',
        'endpoints.read' => 'Read endpoints (machines with the agent)',
        'radius.read'    => 'Read RADIUS servers and server groups (no secrets)',
        'audit.read'     => 'Read the audit trail',
    ];
    private const PREFIX = 'sohob_';

    private JsonStore $store;

    public function __construct(?JsonStore $store = null)
    {
        $this->store = $store ?? new JsonStore(Config::dataDir() . '/api-keys.json');
    }

    /** @return list<array> without hashes, newest first */
    public function all(): array
    {
        $keys = array_values(array_map(static fn (array $k): array => array_diff_key($k, ['hash' => true]), $this->store->read()['keys'] ?? []));
        usort($keys, static fn (array $a, array $b): int => $b['created_at'] <=> $a['created_at']);
        return $keys;
    }

    /**
     * @return array{0: array, 1: string} the key record (no hash) and the full key, shown once
     */
    public function create(array $input, string $createdBy): array
    {
        $name = trim((string) ($input['name'] ?? ''));
        if (!preg_match('/^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,63}$/u', $name)) {
            throw new ValidationException('Key names are 1-64 characters: letters, digits, space, dot, dash, underscore.');
        }
        $scopes = array_values(array_intersect(array_keys(self::SCOPES), array_map('strval', (array) ($input['scopes'] ?? []))));
        if ([] === $scopes) {
            throw new ValidationException('Choose at least one permission for the key.');
        }
        $networks = self::networks((string) ($input['networks'] ?? ''));
        $days = trim((string) ($input['expires_days'] ?? ''));
        if ('' !== $days && (!ctype_digit($days) || (int) $days < 1 || (int) $days > 3650)) {
            throw new ValidationException('The validity must be 1-3650 days, or empty for no expiry.');
        }
        $rate = trim((string) ($input['rate'] ?? '120')) ?: '120';
        if (!ctype_digit($rate) || (int) $rate < 1 || (int) $rate > 6000) {
            throw new ValidationException('The rate limit must be 1-6000 requests per minute.');
        }
        $id = bin2hex(random_bytes(6));
        $secret = rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '=');
        $record = [
            'id' => $id, 'name' => $name, 'hash' => hash('sha256', $secret), 'scopes' => $scopes, 'networks' => $networks,
            'expires_at' => '' === $days ? null : time() + 86400 * (int) $days, 'rate' => (int) $rate,
            'created_at' => time(), 'created_by' => $createdBy, 'last_used_at' => null, 'last_ip' => '',
        ];
        $this->store->update(static function (array &$data) use ($record): void {
            foreach ($data['keys'] ?? [] as $existing) {
                if (0 === strcasecmp($existing['name'], $record['name'])) {
                    throw new ValidationException('An API key with this name already exists.');
                }
            }
            $data['keys'][$record['id']] = $record;
        });
        unset($record['hash']);
        return [$record, self::PREFIX . $id . '_' . $secret];
    }

    public function revoke(string $id): array
    {
        return $this->store->update(static function (array &$data) use ($id): array {
            $key = $data['keys'][$id] ?? throw new ValidationException('This API key does not exist.');
            unset($data['keys'][$id], $data['rate'][$id]);
            unset($key['hash']);
            return $key;
        });
    }

    /**
     * Check a presented key for a client address. Returns the key record (no hash).
     * @throws ApiError 401 (unknown, wrong, expired), 403 (address not allowed), 429 (rate)
     */
    public function authenticate(string $presented, string $ip): array
    {
        if (!preg_match('/^' . self::PREFIX . '([0-9a-f]{12})_([A-Za-z0-9_-]{32})$/', $presented, $m)) {
            throw new ApiError('unauthorized', 401, 'Missing or malformed API key (Authorization: Bearer sohob_...).');
        }
        [, $id, $secret] = $m;
        $key = $this->store->read()['keys'][$id] ?? null;
        if (null === $key || !hash_equals($key['hash'], hash('sha256', $secret))) {
            throw new ApiError('unauthorized', 401, 'Unknown or revoked API key.');
        }
        if (null !== $key['expires_at'] && $key['expires_at'] < time()) {
            throw new ApiError('unauthorized', 401, 'This API key has expired.');
        }
        if ([] !== $key['networks'] && !self::inNetworks($ip, $key['networks'])) {
            throw new ApiError('forbidden', 403, 'This API key may not be used from this address.');
        }
        $limited = $this->store->update(static function (array &$data) use ($id, $ip): bool {
            $minute = intdiv(time(), 60);
            $rate = $data['rate'][$id] ?? ['minute' => $minute, 'count' => 0];
            if ($rate['minute'] !== $minute) {
                $rate = ['minute' => $minute, 'count' => 0];
            }
            $rate['count']++;
            $data['rate'][$id] = $rate;
            $data['keys'][$id]['last_used_at'] = time();
            $data['keys'][$id]['last_ip'] = $ip;
            return $rate['count'] > (int) $data['keys'][$id]['rate'];
        });
        if ($limited) {
            throw new ApiError('rate_limited', 429, 'Rate limit of this API key reached; try again in a minute.');
        }
        unset($key['hash']);
        return $key;
    }

    /** "10.0.0.0/8, 192.0.2.7" -> ["10.0.0.0/8", "192.0.2.7/32"] */
    public static function networks(string $input): array
    {
        $out = [];
        foreach (preg_split('/[\s,;]+/', $input, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $net) {
            [$ip, $prefix] = array_pad(explode('/', $net, 2), 2, null);
            $binary = @inet_pton((string) $ip);
            $bits = false === $binary ? 0 : 8 * strlen($binary);
            if (false === $binary || (null !== $prefix && (!ctype_digit($prefix) || (int) $prefix > $bits))) {
                throw new ValidationException("Not an IP address or network: $net");
            }
            $out[] = inet_ntop($binary) . '/' . (null === $prefix ? $bits : (int) $prefix);
        }
        if (count($out) > 50) {
            throw new ValidationException('At most 50 networks per key.');
        }
        return array_values(array_unique($out));
    }

    public static function inNetworks(string $ip, array $networks): bool
    {
        $addr = @inet_pton($ip);
        if (false === $addr) {
            return false;
        }
        foreach ($networks as $net) {
            [$base, $prefix] = explode('/', $net, 2);
            $baseBin = @inet_pton($base);
            if (false === $baseBin || strlen($baseBin) !== strlen($addr)) {
                continue;
            }
            $bits = (int) $prefix;
            $bytes = intdiv($bits, 8);
            if (substr($addr, 0, $bytes) !== substr($baseBin, 0, $bytes)) {
                continue;
            }
            $rest = $bits % 8;
            if (0 === $rest || (ord($addr[$bytes]) >> (8 - $rest)) === (ord($baseBin[$bytes]) >> (8 - $rest))) {
                return true;
            }
        }
        return false;
    }
}
