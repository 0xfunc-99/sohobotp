<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * CSRF protection for every state-changing request: a per-session token in a
 * hidden form field, plus a same-origin check on the Origin/Referer headers.
 * (SameSite=Strict cookies already stop most cross-site requests; this is the
 * second layer.)
 */
final class Csrf
{
    public const FIELD = '_csrf';

    public static function token(): string
    {
        if (empty($_SESSION['csrf'])) {
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf'];
    }

    public static function valid(?string $submitted): bool
    {
        return is_string($submitted)
            && !empty($_SESSION['csrf'])
            && hash_equals($_SESSION['csrf'], $submitted)
            && self::sameOrigin();
    }

    /** Browsers send Origin (or at least Referer) on POST; it must name this host. */
    private static function sameOrigin(): bool
    {
        $host = $_SERVER['HTTP_HOST'] ?? '';
        $source = $_SERVER['HTTP_ORIGIN'] ?? ($_SERVER['HTTP_REFERER'] ?? '');
        if ('' === $source || 'null' === $source) {
            // Non-browser clients may omit both; the token check still applies
            return '' === $source;
        }
        $parts = parse_url($source);
        if (!is_array($parts) || !isset($parts['host'])) {
            return false;
        }
        $origin = $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
        return 0 === strcasecmp($origin, $host);
    }
}
