<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Named administrator accounts, stored in admins.json in the portal data folder.
 *
 * Record fields:
 *   id, username, display_name, email, role, status (active|disabled),
 *   password_hash, must_change_password, password_expires_at, password_changed_at,
 *   mfa_mode (null = not enrolled yet | "portal" | "multiotp"), mfa_secret (encrypted),
 *   mfa_last_step, mfa_user (linked multiOTP user),
 *   failed_attempts, locked_until, session_version,
 *   created_at, created_by, updated_at, last_login_at, last_login_ip
 */
final class AdminRepository
{
    private JsonStore $store;

    public function __construct(?JsonStore $store = null)
    {
        $this->store = $store ?? new JsonStore(Config::dataDir() . '/admins.json');
    }

    /** @return list<array> sorted by username */
    public function all(): array
    {
        $admins = array_values($this->store->read()['admins'] ?? []);
        usort($admins, static fn (array $a, array $b): int => strcmp($a['username'], $b['username']));
        return $admins;
    }

    public function find(string $id): ?array
    {
        return $this->store->read()['admins'][$id] ?? null;
    }

    public function findByUsername(string $username): ?array
    {
        $username = self::normalise($username);
        foreach ($this->store->read()['admins'] ?? [] as $admin) {
            if ($admin['username'] === $username) {
                return $admin;
            }
        }
        return null;
    }

    /**
     * The administrator whose second factor is checked against this SohobOTP user ("multiotp"
     * mode), or null. Such a user's code is that administrator's portal second factor: whoever
     * can enrol it, print its recovery codes or change its login format can pass that step.
     */
    public function linkedToMfaUser(string $user): ?array
    {
        $user = mb_strtolower(trim($user));
        foreach ($this->store->read()['admins'] ?? [] as $admin) {
            if ('multiotp' === ($admin['mfa_mode'] ?? null) && '' !== $user && mb_strtolower((string) ($admin['mfa_user'] ?? '')) === $user) {
                return $admin;
            }
        }
        return null;
    }

    public function count(): int
    {
        return count($this->store->read()['admins'] ?? []);
    }

    public static function normalise(string $username): string
    {
        return mb_strtolower(trim($username));
    }

    public static function validateUsername(string $username): ?string
    {
        return preg_match('/^[a-z0-9][a-z0-9._-]{1,63}$/', $username)
            ? null
            : 'Usernames are 2-64 characters: lowercase letters, digits, dot, dash and underscore.';
    }

    /**
     * @param array{username: string, role: string, display_name?: string, email?: string, mfa_user?: string} $input
     * @return array the created record
     */
    public function create(array $input, string $password, bool $temporary, string $createdBy): array
    {
        $username = self::normalise($input['username']);
        if (null !== ($error = self::validateUsername($username))) {
            throw new ValidationException($error);
        }
        if (!Roles::exists($input['role'])) {
            throw new ValidationException('Unknown role.');
        }
        $now = time();
        $record = [
            'id'                   => bin2hex(random_bytes(8)),
            'username'             => $username,
            'display_name'         => trim($input['display_name'] ?? ''),
            'email'                => trim($input['email'] ?? ''),
            'role'                 => $input['role'],
            'status'               => 'active',
            'password_hash'        => Passwords::hash($password),
            'must_change_password' => $temporary,
            'password_expires_at'  => $temporary ? $now + Config::tempPasswordLifetime() : null,
            'password_changed_at'  => $now,
            'mfa_mode'             => null,
            'mfa_secret'           => null,
            'mfa_last_step'        => -1,
            'mfa_user'             => null,
            'failed_attempts'      => 0,
            'locked_until'         => null,
            'session_version'      => 1,
            'created_at'           => $now,
            'created_by'           => $createdBy,
            'updated_at'           => $now,
            'last_login_at'        => null,
            'last_login_ip'        => null,
        ];
        $mfaUser = trim($input['mfa_user'] ?? '');
        if ('' !== $mfaUser) {
            $record['mfa_mode'] = 'multiotp';
            $record['mfa_user'] = $mfaUser;
        }
        if ('' !== $record['email'] && false === filter_var($record['email'], FILTER_VALIDATE_EMAIL)) {
            throw new ValidationException('The email address is not valid.');
        }

        $this->store->update(static function (array &$data) use ($record): void {
            foreach ($data['admins'] ?? [] as $existing) {
                if ($existing['username'] === $record['username']) {
                    throw new ValidationException('An administrator with this username already exists.');
                }
            }
            $data['admins'][$record['id']] = $record;
        });
        return $record;
    }

    /**
     * Apply $mutate to one record under the store lock and return the updated record.
     * $mutate receives the record and the whole admin map (read-only use) by reference.
     */
    public function update(string $id, callable $mutate): array
    {
        return $this->store->update(static function (array &$data) use ($id, $mutate): array {
            if (!isset($data['admins'][$id])) {
                throw new ValidationException('This administrator no longer exists.');
            }
            $record = $data['admins'][$id];
            $mutate($record, $data['admins']);
            $record['updated_at'] = time();
            $data['admins'][$id] = $record;
            return $record;
        });
    }

    /** Count active super administrators, optionally ignoring one account. */
    public static function activeSuperadmins(array $admins, ?string $exceptId = null): int
    {
        $count = 0;
        foreach ($admins as $admin) {
            if ($admin['id'] !== $exceptId && 'superadmin' === $admin['role'] && 'active' === $admin['status']) {
                $count++;
            }
        }
        return $count;
    }

    public static function isLocked(array $admin): bool
    {
        return null !== $admin['locked_until'] && $admin['locked_until'] > time();
    }

    /** Record a failed password or MFA attempt; locks the account after too many. */
    public function registerFailure(string $id): array
    {
        return $this->update($id, static function (array &$admin): void {
            $admin['failed_attempts']++;
            if ($admin['failed_attempts'] >= Config::maxFailures()) {
                $admin['locked_until'] = time() + Config::lockoutSeconds();
                $admin['failed_attempts'] = 0;
            }
        });
    }
}
