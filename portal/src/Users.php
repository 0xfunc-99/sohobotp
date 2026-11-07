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
        ];
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
            throw new ValidationException('A multiOTP user with this name already exists.');
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
            throw new \RuntimeException('multiOTP could not create the user.');
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
            throw new \RuntimeException('multiOTP could not unlock the user.');
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
            throw new \RuntimeException('multiOTP could not delete the user.');
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
            throw new \RuntimeException('multiOTP could not build the provisioning link.');
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
            throw new \RuntimeException('multiOTP could not assign the token.');
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
            throw new \RuntimeException('multiOTP could not remove the token.');
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
            throw new \RuntimeException('multiOTP could not save the user.');
        }
    }
}
