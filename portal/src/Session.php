<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Hardened PHP session for the portal.
 *
 * - Cookie is HttpOnly, SameSite=Strict and Secure; over HTTPS it uses the
 *   "__Host-" prefix, which browsers only accept for Secure, host-only, path=/ cookies.
 * - Strict mode: ids the server did not issue are refused (no session fixation).
 * - The id is regenerated at every privilege change (password step, MFA, logout).
 * - Idle and absolute timeouts are enforced server-side.
 *
 * Authentication stages kept in the session:
 *   (none) -> "mfa" | "enroll" (password accepted) -> "full" (signed in)
 */
final class Session
{
    /** $name: the self-service set-up page (enrol.php) uses its own cookie, never the administrators' one. */
    public static function start(bool $https, string $name = 'motp_portal'): void
    {
        if (PHP_SESSION_ACTIVE === session_status()) {
            return;
        }
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.use_trans_sid', '0');
        session_cache_limiter(''); // keep our own Cache-Control: no-store
        ini_set('session.gc_maxlifetime', (string) max(Config::idleTimeout(), 1440));
        session_name($https ? '__Host-' . $name : $name);
        session_set_cookie_params([
            'lifetime' => 0,
            'path'     => '/',
            'secure'   => $https,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        session_start();

        $now = time();
        $created = $_SESSION['created_at'] ?? $now;
        $lastSeen = $_SESSION['last_seen'] ?? $now;
        if ($now - $lastSeen > Config::idleTimeout() || $now - $created > Config::absoluteTimeout()) {
            $expired = isset($_SESSION['stage']);
            self::reset();
            if ($expired) {
                self::flash('info', 'Your session expired. Please sign in again.');
            }
        }
        $_SESSION['created_at'] ??= $now;
        $_SESSION['last_seen'] = $now;
    }

    /** New session id, keeping the data (call at every privilege change). */
    public static function regenerate(): void
    {
        session_regenerate_id(true);
        $_SESSION['created_at'] = time();
    }

    /** Drop all authentication data and issue a new id. */
    public static function reset(): void
    {
        $_SESSION = [];
        session_regenerate_id(true);
        $_SESSION['created_at'] = time();
    }

    public static function stage(): ?string
    {
        return $_SESSION['stage'] ?? null;
    }

    public static function adminId(): ?string
    {
        return $_SESSION['admin_id'] ?? null;
    }

    /** Password accepted; the second factor is still required. */
    public static function beginSecondFactor(array $admin, string $stage): void
    {
        self::reset();
        $_SESSION['stage'] = $stage;
        $_SESSION['admin_id'] = $admin['id'];
        $_SESSION['stage_since'] = time();
        $_SESSION['mfa_attempts'] = 0;
    }

    public static function completeLogin(array $admin): void
    {
        self::reset();
        $_SESSION['stage'] = 'full';
        $_SESSION['admin_id'] = $admin['id'];
        $_SESSION['session_version'] = $admin['session_version'];
        $_SESSION['auth_at'] = time();
    }

    public static function flash(string $type, string $message): void
    {
        $_SESSION['flash'][] = ['type' => $type, 'message' => $message];
    }

    /** @return list<array{type: string, message: string}> */
    public static function takeFlashes(): array
    {
        $flashes = $_SESSION['flash'] ?? [];
        unset($_SESSION['flash']);
        return $flashes;
    }
}
