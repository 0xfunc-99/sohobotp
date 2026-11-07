<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Authenticated encryption (libsodium secretbox) for secrets the portal
 * stores itself, such as administrators' TOTP seeds. The key lives in
 * portal.key inside the portal data folder (mode 0600), so a copy of
 * admins.json alone does not reveal any seed.
 */
final class Crypto
{
    private const PREFIX = 'sb1:';

    public static function encrypt(string $plaintext): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return self::PREFIX . base64_encode($nonce . sodium_crypto_secretbox($plaintext, $nonce, self::key()));
    }

    public static function decrypt(string $encoded): string
    {
        if (!str_starts_with($encoded, self::PREFIX)) {
            throw new \RuntimeException('Unknown secret format.');
        }
        $raw = base64_decode(substr($encoded, strlen(self::PREFIX)), true);
        if (false === $raw || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new \RuntimeException('Malformed secret.');
        }
        $plain = sodium_crypto_secretbox_open(
            substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            self::key()
        );
        if (false === $plain) {
            throw new \RuntimeException('Secret cannot be decrypted (wrong portal.key?).');
        }
        return $plain;
    }

    private static function key(): string
    {
        static $key = null;
        if (null !== $key) {
            return $key;
        }
        if (!function_exists('sodium_crypto_secretbox')) {
            throw new \RuntimeException('The PHP sodium extension is required.');
        }
        $file = Config::ensureDataDir() . '/portal.key';
        if (!is_file($file)) {
            $new = base64_encode(random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES));
            // "x" mode fails if another request created the key in the meantime
            $handle = @fopen($file, 'x');
            if (false !== $handle) {
                fwrite($handle, $new . "\n");
                fclose($handle);
                @chmod($file, 0600);
            }
        }
        $decoded = base64_decode(trim((string) file_get_contents($file)), true);
        if (false === $decoded || SODIUM_CRYPTO_SECRETBOX_KEYBYTES !== strlen($decoded)) {
            throw new \RuntimeException('Invalid portal.key file.');
        }
        return $key = $decoded;
    }
}
