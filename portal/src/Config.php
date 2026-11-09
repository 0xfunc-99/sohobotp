<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Portal settings. Every value can be overridden with an environment
 * variable (set it in the PHP-FPM pool, the Docker environment or the shell).
 */
final class Config
{
    /** Folder that contains multiotp.class.php. */
    public static function multiotpDir(): string
    {
        return rtrim(self::env('MULTIOTP_DIR') ?? dirname(PORTAL_ROOT), '/');
    }

    /** multiOTP data folder (the /etc/multiotp volume on Linux and Docker). */
    public static function etcDir(): string
    {
        return rtrim(self::env('MULTIOTP_ETC_DIR') ?? '/etc/multiotp', '/');
    }

    public static function hasEtcDir(): bool
    {
        return is_dir(self::etcDir() . '/config');
    }

    public static function logDir(): string
    {
        return rtrim(self::env('MULTIOTP_LOG_DIR') ?? '/var/log/multiotp', '/') . '/';
    }

    /** Portal data: administrator accounts, audit trail, throttling, key. */
    public static function dataDir(): string
    {
        $dir = self::env('MULTIOTP_PORTAL_DATA');
        if (null === $dir) {
            $dir = self::hasEtcDir() ? self::etcDir() . '/portal' : self::multiotpDir() . '/config/portal';
        }
        return rtrim($dir, '/');
    }

    public static function ensureDataDir(): string
    {
        $dir = self::dataDir();
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new \RuntimeException('Cannot create the portal data folder.');
        }
        return $dir;
    }

    public static function auditFile(): string
    {
        return self::env('MULTIOTP_PORTAL_AUDIT_FILE') ?? self::dataDir() . '/audit.jsonl';
    }

    /** Plain HTTP is refused unless explicitly allowed (local development only). */
    public static function allowHttp(): bool
    {
        return '1' === self::env('MULTIOTP_PORTAL_ALLOW_HTTP');
    }

    /** Product name shown in the portal and used for the agent. */
    public static function brandName(): string
    {
        return self::env('MULTIOTP_PORTAL_BRAND') ?? 'SohobOTP';
    }

    /** Company behind the product (logo: assets/brand-logo.png, icon: assets/brand-icon.png). */
    public static function companyName(): string
    {
        return self::env('MULTIOTP_PORTAL_COMPANY') ?? 'Sohobcom';
    }

    /** Issuer label shown in authenticator apps. */
    public static function issuer(): string
    {
        return self::env('MULTIOTP_PORTAL_ISSUER') ?? self::brandName();
    }

    public static function idleTimeout(): int       { return self::int('MULTIOTP_PORTAL_IDLE_TIMEOUT', 900); }
    public static function absoluteTimeout(): int   { return self::int('MULTIOTP_PORTAL_ABSOLUTE_TIMEOUT', 28800); }
    public static function mfaStepTimeout(): int    { return self::int('MULTIOTP_PORTAL_MFA_TIMEOUT', 300); }
    public static function maxMfaAttempts(): int    { return self::int('MULTIOTP_PORTAL_MAX_MFA_ATTEMPTS', 5); }
    public static function maxFailures(): int       { return self::int('MULTIOTP_PORTAL_MAX_FAILURES', 5); }
    public static function lockoutSeconds(): int    { return self::int('MULTIOTP_PORTAL_LOCKOUT', 900); }
    public static function ipMaxFailures(): int     { return self::int('MULTIOTP_PORTAL_IP_MAX_FAILURES', 20); }
    public static function ipWindow(): int          { return self::int('MULTIOTP_PORTAL_IP_WINDOW', 900); }
    public static function tempPasswordLifetime(): int { return self::int('MULTIOTP_PORTAL_TEMP_PASSWORD_LIFETIME', 86400); }
    public static function minPasswordLength(): int { return self::int('MULTIOTP_PORTAL_MIN_PASSWORD_LENGTH', 12); }

    private static function env(string $name): ?string
    {
        $value = getenv($name);
        return (false === $value || '' === $value) ? null : $value;
    }

    private static function int(string $name, int $default): int
    {
        $value = self::env($name);
        return (null !== $value && ctype_digit($value) && (int) $value > 0) ? (int) $value : $default;
    }
}
