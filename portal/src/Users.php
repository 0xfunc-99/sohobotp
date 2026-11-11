<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * multiOTP users (the people who authenticate over RADIUS / the Credential
 * Provider), managed through the engine. Secrets the portal creates (token
 * seeds, recovery codes) come from random_bytes()/random_int(), not from the
 * engine's md5/mt_rand helpers.
 */
final class Users
{
    public const STATUSES = ['' => 'All', 'enabled' => 'Enabled', 'disabled' => 'Disabled', 'locked' => 'Locked', 'synced' => 'From directory', 'local' => 'Local only'];
    public const LOGIN_FORMATS = [
        'code'      => 'Code only',
        'pin'       => 'PIN + code',
        'directory' => 'Directory password + code',
    ];
    private const RECOVERY_CODES = 10;
    private const RECOVERY_DIGITS = 8;

    private \Multiotp $engine;

    public function __construct()
    {
        $this->engine = MultiotpService::get();
    }

    public static function validateName(string $user): ?string
    {
        return preg_match('/^[\p{L}\p{N}][\p{L}\p{N}._@-]{0,127}$/u', $user)
            ? null
            : 'Usernames are 1-128 characters: letters, digits, dot, dash, underscore and @.';
    }

    /** @return array{total: int, users: list<array>} */
    public function search(string $query, string $status, int $page, int $perPage): array
    {
        if ('mysql' === $this->engine->GetBackendType() && $this->engine->GetBackendTypeValidated() && class_exists(\mysqli::class)) {
            $found = $this->searchSql($query, $status, $page, $perPage);
            if (null !== $found) {
                return $found;
            }
        }
        $all = $this->engine->ApiGetUsersArray(['page' => 1, 'itemsPerPage' => 1000000])['users'] ?? [];
        $query = mb_strtolower(trim($query));
        $matches = array_values(array_filter($all, static function (array $u) use ($query, $status): bool {
            if ('' !== $query) {
                $haystack = mb_strtolower(implode(' ', [$u['user'], $u['display_name'] ?? '', $u['description'] ?? '', $u['email'] ?? '', $u['group'] ?? '', $u['token'] ?? '']));
                if (!str_contains($haystack, $query)) {
                    return false;
                }
            }
            return match ($status) {
                'enabled'  => (bool) $u['enabled'],
                'disabled' => !$u['enabled'],
                'locked'   => (bool) $u['locked'],
                'synced'   => (bool) (int) $u['synchronized'],
                'local'    => !(int) $u['synchronized'],
                default    => true,
            };
        }));
        return ['total' => count($matches), 'users' => array_slice($matches, ($page - 1) * $perPage, $perPage)];
    }

    /**
     * The same search in SQL (MariaDB / MySQL backend): one page and a count, so 100,000 users
     * are not read into PHP. null: no connection (the caller falls back to the engine).
     */
    private function searchSql(string $query, string $status, int $page, int $perPage): ?array
    {
        $c = $this->engine->_config_data;
        [$host, $port] = array_pad(explode(':', (string) ($c['sql_server'] ?? '')), 2, '3306');
        mysqli_report(MYSQLI_REPORT_OFF);
        $db = mysqli_init();
        $db->options(MYSQLI_OPT_CONNECT_TIMEOUT, 5);
        if (!@$db->real_connect($host, (string) ($c['sql_username'] ?? ''), (string) ($c['sql_password'] ?? ''), (string) ($c['sql_database'] ?? ''), (int) $port)) {
            return null;
        }
        $db->set_charset('utf8mb4');
        $table = '`' . str_replace('`', '', (string) ($c['sql_users_table'] ?? 'multiotp_users')) . '`';
        $where = [];
        $types = '';
        $params = [];
        $query = trim($query);
        if ('' !== $query) {
            $like = '%' . addcslashes($query, '%_\\') . '%';
            $where[] = '(`user` LIKE ? OR `display_name` LIKE ? OR `description` LIKE ? OR `email` LIKE ? OR `group` LIKE ? OR `token_serial` LIKE ?)';
            $types .= 'ssssss';
            array_push($params, $like, $like, $like, $like, $like, $like);
        }
        $where[] = match ($status) {
            'enabled'  => '`desactivated` = 0',
            'disabled' => '`desactivated` = 1',
            'locked'   => '`locked` = 1',
            'synced'   => '`synchronized` = 1',
            'local'    => '`synchronized` = 0',
            default    => '1 = 1',
        };
        $sqlWhere = implode(' AND ', $where);
        $count = $db->prepare("SELECT COUNT(*) FROM $table WHERE $sqlWhere");
        $rows = $db->prepare("SELECT `user`, `display_name`, `description`, `email`, `group`, `token_serial`, `desactivated`, `locked`, `synchronized`
            FROM $table WHERE $sqlWhere ORDER BY `user` LIMIT ? OFFSET ?");
        if (false === $count || false === $rows) {
            $db->close();
            return null;
        }
        if ('' !== $types) {
            $count->bind_param($types, ...$params);
        }
        $count->execute();
        $total = (int) ($count->get_result()->fetch_row()[0] ?? 0);
        $limit = $perPage;
        $offset = max(0, ($page - 1) * $perPage);
        $rows->bind_param($types . 'ii', ...[...$params, $limit, $offset]);
        $rows->execute();
        $users = [];
        foreach ($rows->get_result()->fetch_all(MYSQLI_ASSOC) as $r) {
            $users[] = ['user' => $r['user'], 'display_name' => (string) $r['display_name'], 'description' => (string) $r['description'],
                'email' => (string) $r['email'], 'group' => (string) $r['group'], 'token' => (string) $r['token_serial'],
                'enabled' => 0 === (int) $r['desactivated'], 'locked' => 1 === (int) $r['locked'], 'synchronized' => (int) $r['synchronized']];
        }
        $db->close();
        return ['total' => $total, 'users' => $users];
    }

    public function exists(string $user): bool
    {
        return '' !== $user && (bool) $this->engine->CheckUserExists($user, true, true);
    }

    public function get(string $user): ?array
    {
        if (!$this->exists($user)) {
            return null;
        }
        $e = $this->engine;
        $e->SetUser($user);
        return [
            'user'            => $e->GetUser(),
            'display_name'    => (string) $e->GetUserDisplayName(),
            'description'     => (string) $e->GetUserDescription(),
            'email'           => (string) $e->GetUserEmail(),
            'sms'             => (string) $e->GetUserSms(),
            'group'           => (string) $e->GetUserGroup(),
            'algorithm'       => (string) $e->GetUserAlgorithm(),
            'token_serial'    => (string) $e->GetUserTokenSerialNumber(),
            'enabled'         => 1 === (int) $e->GetUserActivated(),
            'locked'          => (bool) $e->GetUserLocked() || (bool) $e->GetUserDelayed(),
            'error_counter'   => (int) $e->GetUserErrorCounter(),
            'last_login'      => (int) $e->GetUserLastLogin() ?: null,
            'synchronized'    => (bool) (int) $e->GetUserSynchronized(),
            'synced_dn'       => (string) $e->GetUserSynchronizedDn(),
            'synced_server'   => (string) $e->GetUserSynchronizedServer(),
            'synced_time'     => (int) $e->GetUserSynchronizedTime() ?: null,
            'recovery_codes'  => count($e->GetUserScratchPasswordsArray()),
            'ldap_password'   => (bool) $e->IsUserRequestLdapPasswordEnabled(),
            'prefix_pin'      => (bool) $e->IsUserPrefixPin(),
            'login_format'    => $e->IsUserPrefixPin() ? ($e->IsUserRequestLdapPasswordEnabled() ? 'directory' : 'pin') : 'code',
        ];
    }

    /**
     * What the user types at a RADIUS / Windows login. The engine checks a prefix (PIN or
     * directory password) only when request_prefix_pin is on; with request_ldap_pwd the
     * prefix is verified by binding to the directory as the user.
     * @return ?string a new random PIN to show once (format "pin"), otherwise null
     */
    public function setLoginFormat(string $user, string $format): ?string
    {
        if (!isset(self::LOGIN_FORMATS[$format])) {
            throw new ValidationException('Unknown login format.');
        }
        $e = $this->engine;
        $e->SetUser($user);
        $pin = null;
        switch ($format) {
            case 'code':
                $e->SetUserPrefixPin(0);
                $e->SetUserRequestLdapPassword(0);
                break;
            case 'pin':
                $pin = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
                $e->SetUserPin($pin);
                $e->SetUserPrefixPin(1);
                $e->SetUserRequestLdapPassword(0);
                break;
            case 'directory':
                if ('' === (string) $e->GetUserSynchronizedDn()) {
                    throw new ValidationException('Only users synchronised from the directory can sign in with their directory password.');
                }
                $e->SetUserPrefixPin(1);
                $e->SetUserRequestLdapPassword(1);
                break;
        }
        $this->write();
        return $pin;
    }

    /**
     * Creates a user with a software TOTP token (random seed) or a hardware token.
     * @return array{user: string, otpauth: ?string}
     */
    public function create(array $input): array
    {
        $user = trim((string) $input['user']);
        if (null !== ($error = self::validateName($user))) {
            throw new ValidationException($error);
        }
        if ($this->exists($user)) {
            throw new ValidationException('A SohobOTP user with this name already exists.');
        }
        $email = trim((string) ($input['email'] ?? ''));
        if ('' !== $email && false === filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new ValidationException('The email address is not valid.');
        }
        $serial = trim((string) ($input['token_serial'] ?? ''));
        if ('' !== $serial && !in_array($serial, $this->freeTokens(), true)) {
            throw new ValidationException('This hardware token does not exist or is already assigned.');
        }
        $created = $this->engine->CreateUser(
            $user, 0, 'totp', bin2hex(random_bytes(20)), '', 6, 30,
            $email, trim((string) ($input['sms'] ?? '')), trim((string) ($input['description'] ?? '')),
            trim((string) ($input['group'] ?? '')), '', 1, 0, 0
        );
        if (!$created) {
            throw new \RuntimeException('SohobOTP could not create the user.');
        }
        $this->engine->SetUser($user);
        $this->engine->SetUserDisplayName(trim((string) ($input['display_name'] ?? '')));
        $this->engine->WriteUserData();
        if ('' !== $serial) {
            if (!$this->engine->AssignTokenToUser($user, $serial)) {
                throw new \RuntimeException('The user was created, but the hardware token could not be assigned.');
            }
            return ['user' => $user, 'otpauth' => null];
        }
        return ['user' => $user, 'otpauth' => (string) $this->engine->GetUserTokenUrlLink($user) ?: null];
    }

    public function update(string $user, array $input): array
    {
        $email = trim((string) ($input['email'] ?? ''));
        if ('' !== $email && false === filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new ValidationException('The email address is not valid.');
        }
        $before = $this->get($user);
        $e = $this->engine;
        $e->SetUser($user);
        $e->SetUserDisplayName(trim((string) ($input['display_name'] ?? '')));
        $e->SetUserDescription(trim((string) ($input['description'] ?? '')));
        $e->SetUserEmail($email);
        $e->SetUserSms(trim((string) ($input['sms'] ?? '')));
        $e->SetUserGroup(trim((string) ($input['group'] ?? '')));
        $this->write();
        $after = $this->get($user);
        $changes = [];
        foreach (['display_name', 'description', 'email', 'sms', 'group'] as $field) {
            if ($before[$field] !== $after[$field]) {
                $changes[$field] = ['from' => $before[$field], 'to' => $after[$field]];
            }
        }
        return $changes;
    }

    public function setEnabled(string $user, bool $enabled): void
    {
        $this->engine->SetUser($user);
        $this->engine->SetUserActivated($enabled ? 1 : 0);
        $this->write();
    }

    public function unlock(string $user): void
    {
        if (!$this->engine->UnlockUser($user)) {
            throw new \RuntimeException('SohobOTP could not unlock the user.');
        }
    }

    public function delete(string $user): void
    {
        $this->engine->SetUser($user);
        $serial = (string) $this->engine->GetUserTokenSerialNumber();
        if ('' !== $serial) {
            $this->engine->RemoveTokenFromUser($user);
        }
        if (!$this->engine->DeleteUser($user, true)) {
            throw new \RuntimeException('SohobOTP could not delete the user.');
        }
    }

    /** New random TOTP seed; returns the otpauth:// URI to show once as a QR code. */
    public function enrollSoftwareToken(string $user): string
    {
        $e = $this->engine;
        $e->SetUser($user);
        if ('' !== (string) $e->GetUserTokenSerialNumber()) {
            throw new ValidationException('This user has a hardware token. Remove it first.');
        }
        $e->SetUserAlgorithm('totp');
        $e->SetUserTokenAlgoSuite('');
        $e->SetUserTokenSeed(bin2hex(random_bytes(20)));
        $e->SetUserTokenNumberOfDigits(6);
        $e->SetUserTokenTimeInterval(30);
        $e->SetUserTokenLastEvent(-1);
        $e->SetUserTokenDeltaTime(0);
        $this->write();
        $uri = (string) $e->GetUserTokenUrlLink($user);
        if ('' === $uri) {
            throw new \RuntimeException('SohobOTP could not build the provisioning link.');
        }
        return $uri;
    }

    public function resync(string $user, string $first, string $second): bool
    {
        $first = preg_replace('/\D/', '', $first) ?? '';
        $second = preg_replace('/\D/', '', $second) ?? '';
        if ('' === $first || '' === $second || $first === $second) {
            throw new ValidationException('Enter two different, consecutive codes from the token.');
        }
        return (bool) $this->engine->ResyncUserToken($user, $first, $second);
    }

    /** @return list<string> replaces any previous recovery codes */
    public function newRecoveryCodes(string $user): array
    {
        $codes = [];
        while (count($codes) < self::RECOVERY_CODES) {
            $code = str_pad((string) random_int(0, 10 ** self::RECOVERY_DIGITS - 1), self::RECOVERY_DIGITS, '0', STR_PAD_LEFT);
            $codes[$code] = true;
        }
        $codes = array_keys($codes);
        $codes = array_map('strval', $codes);
        $this->engine->SetUser($user);
        $this->engine->SetUserAttribute('scratch_passwords', implode(',', $codes));
        $this->write();
        return $codes;
    }

    public function assignToken(string $user, string $serial): void
    {
        if (!in_array($serial, $this->freeTokens(), true)) {
            throw new ValidationException('This hardware token does not exist or is already assigned.');
        }
        if (!$this->engine->AssignTokenToUser($user, $serial)) {
            throw new \RuntimeException('SohobOTP could not assign the token.');
        }
    }

    /** Removes the hardware token; the user gets a fresh random software seed (to be enrolled). */
    public function removeToken(string $user): string
    {
        $this->engine->SetUser($user);
        $serial = (string) $this->engine->GetUserTokenSerialNumber();
        if ('' === $serial) {
            throw new ValidationException('This user has no hardware token.');
        }
        if (!$this->engine->RemoveTokenFromUser($user)) {
            throw new \RuntimeException('SohobOTP could not remove the token.');
        }
        $this->enrollSoftwareToken($user); // replaces the engine's md5-based seed
        return $serial;
    }

    /** @return list<string> serial numbers of hardware tokens not assigned to anyone */
    public function freeTokens(): array
    {
        return array_values(array_map(static fn (array $t): string => $t['serial'],
            array_filter((new Tokens())->all(), static fn (array $t): bool => [] === $t['users'])));
    }

    private function write(): void
    {
        if (!$this->engine->WriteUserData()) {
            throw new \RuntimeException('SohobOTP could not save the user.');
        }
    }
}
