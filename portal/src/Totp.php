<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/** RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30 s), used for portal-only administrator MFA. */
final class Totp
{
    public const PERIOD = 30;
    public const DIGITS = 6;

    public static function newSecret(): string
    {
        return random_bytes(20);
    }

    public static function code(string $secret, int $step): string
    {
        $hash = hash_hmac('sha1', pack('J', $step), $secret, true);
        $offset = ord($hash[19]) & 0x0f;
        $value = ((ord($hash[$offset]) & 0x7f) << 24)
               | (ord($hash[$offset + 1]) << 16)
               | (ord($hash[$offset + 2]) << 8)
               | ord($hash[$offset + 3]);
        return str_pad((string) ($value % (10 ** self::DIGITS)), self::DIGITS, '0', STR_PAD_LEFT);
    }

    /**
     * Returns the matching time step, or null. Steps at or before $lastStep
     * are refused, so a code can only be used once.
     */
    public static function verify(string $secret, string $code, int $lastStep = -1, ?int $now = null, int $window = 1): ?int
    {
        $code = preg_replace('/\s+/', '', $code) ?? '';
        if (!preg_match('/^\d{' . self::DIGITS . '}$/', $code)) {
            return null;
        }
        $current = intdiv($now ?? time(), self::PERIOD);
        $matched = null;
        for ($step = $current - $window; $step <= $current + $window; $step++) {
            // Constant-time comparison, and no early exit
            if (hash_equals(self::code($secret, $step), $code) && $step > $lastStep) {
                $matched = $step;
            }
        }
        return $matched;
    }

    public static function base32(string $binary): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $bits = '';
        foreach (str_split($binary) as $char) {
            $bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            $out .= $alphabet[bindec(str_pad($chunk, 5, '0'))];
        }
        return $out;
    }

    public static function uri(string $issuer, string $account, string $secret): string
    {
        return 'otpauth://totp/' . rawurlencode($issuer) . ':' . rawurlencode($account)
            . '?secret=' . self::base32($secret)
            . '&issuer=' . rawurlencode($issuer)
            . '&algorithm=SHA1&digits=' . self::DIGITS . '&period=' . self::PERIOD;
    }
}
