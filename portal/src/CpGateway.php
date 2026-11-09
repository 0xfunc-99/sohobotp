<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Server side of SohobOTP Sign-in (fork of the multiOTP Credential Provider) for managed Windows endpoints
 * (portal/cp.php?e=<endpoint id>). The CP's bundled multiOTP client speaks the legacy
 * client/server XML protocol; this gateway answers it with the engine's own XmlServer(),
 * but with the endpoint's OWN shared secret (pushed sealed by the agent) instead of the
 * single global secret, and with the endpoint group's offline-cache policy.
 *
 * A stolen laptop therefore only holds its own secret, which disabling the endpoint
 * replaces. Unknown, disabled, pending or Linux endpoints get 403 with no XML.
 */
final class CpGateway
{
    public static function run(): void
    {
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        Audit::setIp($ip);
        $throttle = new Throttle(new JsonStore(Config::dataDir() . '/agent-throttle.json'));
        if (!self::isHttps() && !Config::allowHttp()) {
            self::refuse(403, 'HTTPS is required.');
        }
        if ('POST' !== ($_SERVER['REQUEST_METHOD'] ?? '')) {
            self::refuse(405, 'Use POST.');
        }
        if ($throttle->isBlocked($ip)) {
            self::refuse(429, 'Too many failed requests from this address.');
        }
        $id = (string) ($_GET['e'] ?? '');
        $endpoints = new Endpoints();
        $endpoint = preg_match('/^[0-9a-f]{20}$/', $id) ? $endpoints->endpoint($id) : null;
        if (null === $endpoint || 'windows' !== $endpoint['os'] || 'active' !== $endpoint['status']) {
            $throttle->fail($ip);
            self::refuse(403, 'Unknown or inactive endpoint.');
        }
        $data = (string) ($_POST['data'] ?? '');
        if ('' === $data || strlen($data) > 65536 || !str_contains($data, '<multiOTP')) {
            self::refuse(400, 'Not a multiOTP client request.');
        }
        $policy = Endpoints::effectivePolicy($endpoints->group($endpoint['group_id'])['policy'] ?? [])['windows'];

        $engine = MultiotpService::get();
        $engine->SetServerSecret($endpoints->cpSecret($id));
        // Offline cache: only when the endpoint group allows it, for at most its lifetime
        $engine->SetServerCacheLevel($policy['cache_enabled'] ? 1 : 0);
        $engine->SetServerCacheLifetime($policy['cache_enabled'] ? 86400 * (int) $policy['cache_days'] : 0);
        $endpoints->touchCp($id, $ip);
        $engine->XmlServer($data); // sends its own headers and the XML answer
        exit;
    }

    private static function refuse(int $status, string $message): never
    {
        http_response_code($status);
        header('Content-Type: text/plain');
        echo $message;
        exit;
    }

    private static function isHttps(): bool
    {
        return (!empty($_SERVER['HTTPS']) && 'off' !== strtolower((string) $_SERVER['HTTPS']))
            || '443' === (string) ($_SERVER['SERVER_PORT'] ?? '');
    }
}
