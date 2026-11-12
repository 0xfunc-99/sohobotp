<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Self-service "Set up my code": users synchronised from Active Directory / LDAP scan their own
 * QR code at portal/enrol.php after signing in with their directory password, then confirm it
 * with a first code. Meant for a rollout: before the agents are pushed, users set up their
 * authenticator themselves instead of one by one at the help desk.
 *
 * A stolen directory password must not be enough to take over someone's codes, so it only
 * works for users who have NO authenticator in use yet (never signed in with a code, nothing
 * set up here or by an administrator, no hardware token), while an administrator keeps it open
 * (until a date), optionally only from listed networks. An administrator can allow one user
 * again (new phone). Every step is in the audit trail; failures are throttled per address.
 *
 * self-enrol.json: { settings: {enabled, until, networks: [cidr]}, users: {name: {at, via, ip}}, resets: {name: time} }
 */
final class SelfEnrol
{
    public const MAX_DAYS = 90;

    private JsonStore $store;

    public function __construct(?JsonStore $store = null)
    {
        $this->store = $store ?? new JsonStore(Config::ensureDataDir() . '/self-enrol.json');
    }

    private static function key(string $user): string
    {
        return mb_strtolower(trim($user), 'UTF-8');
    }

    /** @return array{enabled: bool, until: ?int, networks: list<string>} */
    public function settings(): array
    {
        $s = $this->store->read()['settings'] ?? [];
        return ['enabled' => !empty($s['enabled']), 'until' => isset($s['until']) ? (int) $s['until'] : null, 'networks' => array_values($s['networks'] ?? [])];
    }

    /** @param array{enabled?: string, days?: string, networks?: string} $input */
    public function saveSettings(array $input): array
    {
        $enabled = !empty($input['enabled']);
        $days = trim((string) ($input['days'] ?? '14'));
        if ($enabled && (!ctype_digit($days) || (int) $days < 1 || (int) $days > self::MAX_DAYS)) {
            throw new ValidationException('Keep it open for 1 to ' . self::MAX_DAYS . ' days.');
        }
        $networks = [];
        foreach (preg_split('/[\s,;]+/', (string) ($input['networks'] ?? '')) ?: [] as $line) {
            if ('' !== $line) {
                $networks[] = self::normaliseNetwork($line);
            }
        }
        $settings = ['enabled' => $enabled, 'until' => $enabled ? time() + 86400 * (int) $days : null, 'networks' => array_values(array_unique($networks))];
        $this->store->update(static function (array &$data) use ($settings): void {
            $data['settings'] = $settings;
        });
        return $settings;
    }

    public static function normaliseNetwork(string $input): string
    {
        [$ip, $prefix] = array_pad(explode('/', trim($input), 2), 2, null);
        $binary = @inet_pton((string) $ip);
        if (false === $binary || !filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new ValidationException('Networks: an address or network per line, e.g. 10.0.0.0/8 or 192.168.1.0/24.');
        }
        $bits = 8 * strlen($binary);
        $prefix = null === $prefix ? $bits : (ctype_digit($prefix) && (int) $prefix <= $bits ? (int) $prefix : -1);
        if ($prefix < 0) {
            throw new ValidationException('Invalid network prefix in "' . $input . '".');
        }
        $masked = '';
        for ($i = 0; $i < strlen($binary); $i++) {
            $keep = max(0, min(8, $prefix - 8 * $i));
            $masked .= chr(ord($binary[$i]) & (0xff << (8 - $keep)) & 0xff);
        }
        return inet_ntop($masked) . '/' . $prefix;
    }

    public static function inNetwork(string $ip, string $network): bool
    {
        [$net, $prefix] = explode('/', $network);
        $a = @inet_pton($ip);
        $b = @inet_pton($net);
        if (false === $a || false === $b || strlen($a) !== strlen($b)) {
            return false;
        }
        $prefix = (int) $prefix;
        for ($i = 0; $i < strlen($a); $i++) {
            $keep = max(0, min(8, $prefix - 8 * $i));
            $mask = (0xff << (8 - $keep)) & 0xff;
            if ((ord($a[$i]) & $mask) !== (ord($b[$i]) & $mask)) {
                return false;
            }
        }
        return true;
    }

    /** null when the page is open for this address, else why not (shown to the user). */
    public function closedReason(string $ip): ?string
    {
        $s = $this->settings();
        if (!$s['enabled'] || null === $s['until'] || $s['until'] < time()) {
            return 'Self-service set-up is not open at the moment. Ask your IT team to set up your code.';
        }
        if ([] !== $s['networks'] && [] === array_filter($s['networks'], static fn (string $n): bool => self::inNetwork($ip, $n))) {
            return 'Self-service set-up is only available from the company network. Connect to it (in the office or by VPN) and try again.';
        }
        return null;
    }

    /** @return ?array{at: int, via: string, ip: string} the last set-up recorded here, unless an administrator allowed it again since */
    public function record(string $user): ?array
    {
        $data = $this->store->read();
        $key = self::key($user);
        $record = $data['users'][$key] ?? null;
        $reset = (int) ($data['resets'][$key] ?? 0);
        return null !== $record && (int) $record['at'] >= $reset ? $record : null;
    }

    public function resetAt(string $user): ?int
    {
        $at = $this->store->read()['resets'][self::key($user)] ?? null;
        return null === $at ? null : (int) $at;
    }

    /**
     * Why this user may not set up a code here (null: may). $user from Users::get().
     * Only called after the directory password was checked: the reasons may be specific.
     */
    public function refusal(array $user): ?string
    {
        if (!$user['enabled']) {
            return 'Your account is disabled in SohobOTP. Ask your IT team.';
        }
        if ('' !== $user['token_serial']) {
            return 'You use a key fob (hardware token): there is nothing to set up here.';
        }
        if (null !== $this->record($user['user'])) {
            return 'Your code is already set up. If you changed or lost your phone, ask your IT team to allow a new set-up.';
        }
        $reset = $this->resetAt($user['user']);
        if (null !== $user['last_login'] && (null === $reset || $user['last_login'] > $reset)) {
            return 'You already sign in with a code. If you changed or lost your phone, ask your IT team to allow a new set-up.';
        }
        return null;
    }

    public function markDone(string $user, string $via, string $ip): void
    {
        $this->store->update(static function (array &$data) use ($user, $via, $ip): void {
            $data['users'][self::key($user)] = ['at' => time(), 'via' => $via, 'ip' => mb_substr($ip, 0, 45)];
        });
    }

    /** An administrator lets this user set up a code again (new phone). */
    public function allowAgain(string $user): void
    {
        $this->store->update(static function (array &$data) use ($user): void {
            $data['resets'][self::key($user)] = time() + 1; // later than any set-up recorded this second
        });
    }

    /** @return list<array{user: string, at: int, via: string, ip: string}> newest first */
    public function recent(int $limit = 20): array
    {
        $data = $this->store->read();
        $out = [];
        foreach ($data['users'] ?? [] as $user => $r) {
            if ((int) $r['at'] >= (int) ($data['resets'][$user] ?? 0)) {
                $out[] = ['user' => (string) $user] + $r;
            }
        }
        usort($out, static fn (array $a, array $b): int => $b['at'] <=> $a['at']);
        return array_slice($out, 0, $limit);
    }

    /** @return array{self: int, admin: int} set-ups recorded here, by the user or by an administrator */
    public function counts(): array
    {
        $counts = ['self' => 0, 'admin' => 0];
        foreach ($this->recent(PHP_INT_MAX) as $r) {
            $counts['self' === $r['via'] ? 'self' : 'admin']++;
        }
        return $counts;
    }

    public static function otpauthUri(string $user, string $seed): string
    {
        $issuer = Config::brandName();
        return 'otpauth://totp/' . rawurlencode($issuer) . ':' . rawurlencode($user)
            . '?secret=' . Totp::base32($seed) . '&issuer=' . rawurlencode($issuer) . '&algorithm=SHA1&digits=6&period=30';
    }
}
