<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Creates the multiOTP engine with the same folders as multiotp.server.php,
 * so the portal, the CLI and RADIUS all see the same users and tokens.
 */
final class MultiotpService
{
    private static ?\Multiotp $instance = null;

    public static function get(): \Multiotp
    {
        if (null !== self::$instance) {
            return self::$instance;
        }
        return self::$instance = self::create(false);
    }

    /** A new engine instance (not shared); $initializeBackend: for a database switch (Database). */
    public static function create(bool $initializeBackend): \Multiotp
    {
        if (!class_exists('Multiotp', false)) {
            $cwd = getcwd();
            chdir(Config::multiotpDir());
            try {
                require_once Config::multiotpDir() . '/multiotp.class.php';
            } finally {
                if (false !== $cwd) {
                    chdir($cwd);
                }
            }
        }
        $etc = Config::hasEtcDir() ? Config::etcDir() : '';
        $multiotp = new \Multiotp('DefaultCliEncryptionKey', $initializeBackend, '', '' === $etc ? '' : $etc . '/config');
        $multiotp->SetHashSalt(_MULTIOTP_DEFAULT_HASH_SALT_);
        $multiotp->ForceNoDisplayLog();
        if ('' !== $etc) {
            $multiotp->SetLogFolder(Config::logDir());
            $multiotp->SetConfigFolder($etc . '/config/');
            $multiotp->SetDdnsFolder($etc . '/ddns/');
            $multiotp->SetDevicesFolder($etc . '/devices/');
            $multiotp->SetGroupsFolder($etc . '/groups/');
            $multiotp->SetTokensFolder($etc . '/tokens/');
            $multiotp->SetUsersFolder($etc . '/users/');
            $multiotp->SetCacheFolder(sys_get_temp_dir() . '/cache/');
            $multiotp->SetLinuxFileMode('0666');
        }
        $multiotp->ReadConfigData();
        // the name authenticator apps show for the account (otpauth://totp/<issuer>:<user>):
        // the engine's own default is "multiOTP"
        $multiotp->SetIssuer(Config::issuer());
        return $multiotp;
    }

    /**
     * The legacy multiOTP admin API (web service "Prefer: api=vuejs") signs in "admin" with the
     * password 1234 when none is set. SohobOTP never uses it: give it a long random password that
     * nobody knows. Returns true when it was changed.
     */
    public static function lockLegacyAdmin(): bool
    {
        $engine = self::get();
        $hash = (string) $engine->GetConfigAttribute('admin_password_hash');
        if ('' !== $hash && !$engine->CheckAdminPassword(_MULTIOTP_DEFAULT_PASSWORD_)) {
            return false;
        }
        $engine->SetAdminPassword(bin2hex(random_bytes(24)));
        $engine->WriteConfigData();
        return true;
    }

    /** Used by tests to start from a fresh engine. */
    public static function reset(): void
    {
        self::$instance = null;
    }
}
