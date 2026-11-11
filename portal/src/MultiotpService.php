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
        return $multiotp;
    }

    /** Used by tests to start from a fresh engine. */
    public static function reset(): void
    {
        self::$instance = null;
    }
}
