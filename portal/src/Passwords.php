<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

final class Passwords
{
    public static function hash(string $password): string
    {
        return password_hash($password, defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT);
    }

    public static function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT);
    }

    public static function verify(string $password, ?string $hash): bool
    {
        // Always spend the same effort, even for unknown accounts
        static $dummy = null;
        $dummy ??= self::hash(bin2hex(random_bytes(16)));
        $ok = password_verify($password, $hash ?? $dummy);
        return $ok && null !== $hash;
    }

    /** Returns an error message, or null when the password is acceptable. */
    public static function validate(string $password, string $username): ?string
    {
        $min = Config::minPasswordLength();
        if (mb_strlen($password) < $min) {
            return "The password must be at least $min characters long.";
        }
        if (mb_strlen($password) > 256) {
            return 'The password is too long.';
        }
        if (false !== mb_stripos($password, $username)) {
            return 'The password must not contain the username.';
        }
        if (count(array_unique(mb_str_split($password))) < 5) {
            return 'The password is too repetitive.';
        }
        return null;
    }

    /** 20 characters, no look-alike characters. */
    public static function temporary(): string
    {
        $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
        $out = '';
        for ($i = 0; $i < 20; $i++) {
            $out .= $alphabet[random_int(0, strlen($alphabet) - 1)];
        }
        return implode('-', str_split($out, 5));
    }
}
