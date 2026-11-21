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
 * replaces. Unknown, disabled, pending or Linux endpoints get 403 with no XML; only
 * made-up ids count against the IP throttle.
 *
 * A computer marked lost or stolen keeps its secret: every request gets a refusal signed
 * with it ("user disabled"), which Sign-in obeys. A 403, or an answer it cannot verify,
 * makes Sign-in fall back to its offline copy, where the right code would still work.
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
            // only made-up ids count against the IP: a disabled or deleted machine whose users
            // keep trying to sign in must not block the other machines behind the same address
            if (null === $endpoint && !$endpoints->wasDeleted($id)) {
                $throttle->fail($ip);
            }
            self::refuse(403, 'Unknown or inactive endpoint.');
        }
        if (Endpoints::isLost($endpoint)) {
            $endpoints->touchCp($id, $ip);
            $data = (string) ($_POST['data'] ?? '');
            $user = preg_match('#<UserId>([^<]{1,255})</UserId>#', $data, $m) ? html_entity_decode($m[1], ENT_QUOTES | ENT_XML1, 'UTF-8') : '';
            if ('enrol' === ($_GET['a'] ?? '')) {
                // set-up at the sign-in screen (sealed, no user name): the code check that follows is counted
                self::refuse(403, 'This computer is reported lost or stolen.');
            }
            $endpoints->lostAttempt($id, mb_substr($user, 0, 120), $ip);
            $refusal = strlen($data) > 65536 ? null : self::lostRefusal($data, $endpoints->cpSecret($id));
            if (null === $refusal) {
                self::refuse(403, 'This computer is reported lost or stolen.');
            }
            header('Content-Type: text/xml');
            echo $refusal;
            exit;
        }
        if ('enrol' === ($_GET['a'] ?? '')) {
            // set-up of a user's authenticator on the sign-in screen (sealed with the endpoint's secret)
            $endpoints->touchCp($id, $ip);
            CpEnrol::handle($endpoint, Endpoints::effectivePolicy($endpoints->group($endpoint['group_id'])['policy'] ?? [])['windows'], $endpoints->cpSecret($id), $ip);
        }
        $data = (string) ($_POST['data'] ?? '');
        if ('' === $data || strlen($data) > 65536 || !str_contains($data, '<multiOTP')) {
            self::refuse(400, 'Not a multiOTP client request.');
        }
        $policy = Endpoints::effectivePolicy($endpoints->group($endpoint['group_id'])['policy'] ?? [])['windows'];

        $data = self::normaliseUserIds($data, static fn (string $user): bool => (new Users())->exists($user));
        $engine = MultiotpService::get();
        $engine->SetServerSecret($endpoints->cpSecret($id));
        // Offline cache: only when the endpoint group allows it, for at most its lifetime
        $engine->SetServerCacheLevel($policy['cache_enabled'] ? 1 : 0);
        $engine->SetServerCacheLifetime($policy['cache_enabled'] ? 86400 * (int) $policy['cache_days'] : 0);
        if (preg_match('#<ReadUserData[\s>]#i', $data)) {
            // Sign-in reads a user's token settings; the engine's answer leaves out only the
            // encrypted attributes. Any endpoint can ask about any user, so personal details
            // (e-mail, phone, directory DN, ...) are left out too: a compromised laptop must not
            // be a way to read the user directory. Read only: nothing is written with this list.
            $engine->SetAttributesToEncrypt(rtrim((string) $engine->GetAttributesToEncrypt(), '*') . '*' . implode('*', self::PRIVATE_ATTRIBUTES) . '*');
        }
        $endpoints->touchCp($id, $ip);
        $engine->XmlServer($data); // sends its own headers and the XML answer
        exit;
    }

    /**
     * Sign-in sends the user name as typed: ".\alice", "PC01\alice", "CONTOSO\alice" (the
     * engine may show the backslash as "/"). SohobOTP users are named without that prefix (the
     * set-up at sign-in creates "alice", directory sync uses the account name), and the engine
     * never strips it, so ".\alice" was refused with the right code. The prefix is dropped when
     * the name without it is a SohobOTP user and the name with it is not. The user id is plain
     * text in the request (no hash covers it), so changing it is safe.
     *
     * @param callable(string): bool $exists
     */
    public static function normaliseUserIds(string $data, callable $exists): string
    {
        return (string) preg_replace_callback('#<UserId>([^<]{1,255})</UserId>#', static function (array $m) use ($exists): string {
            $raw = html_entity_decode($m[1], ENT_QUOTES | ENT_XML1, 'UTF-8');
            if (!preg_match('#^[^\\\\/]{1,64}[\\\\/]([^\\\\/]{1,128})$#u', $raw, $p)) {
                return $m[0];
            }
            $short = mb_strtolower($p[1]);
            if (null !== Users::validateName($short) || !$exists($short)) {
                return $m[0];
            }
            return '<UserId>' . htmlspecialchars($short, ENT_XML1 | ENT_QUOTES, 'UTF-8') . '</UserId>';
        }, $data);
    }

    /**
     * The engine's answer for a disabled user (error 38), signed for this request: the server
     * password is md5(command . secret . challenge), with the challenge the client sent
     * encrypted with the shared secret (multiotp.class.php XmlServer / CheckUserTokenOnServer).
     * Sign-in stops at this answer (no offline fallback). null when the request is not one
     * (a challenge not made with this secret: a plain 403 then).
     */
    public static function lostRefusal(string $data, string $secret): ?string
    {
        if (!preg_match('#<ServerChallenge>([^<]{1,512})</ServerChallenge>#i', $data, $m)) {
            return null;
        }
        $encrypted = base64_decode(trim(html_entity_decode($m[1], ENT_QUOTES | ENT_XML1, 'UTF-8')), true);
        if (false === $encrypted || '' === $secret) {
            return null;
        }
        $challenge = '';
        $key = 'ServerChallenge';
        for ($i = 0, $n = strlen($encrypted); $i < $n; $i++) {
            $challenge .= chr(ord($secret[$i % strlen($secret)]) ^ ord($key[$i % strlen($key)]) ^ ord($encrypted[$i]));
        }
        if (!str_starts_with($challenge, 'MOSH')) {
            return null;
        }
        $command = 'CheckUserToken';
        foreach (['CheckUserToken', 'ReadUserData', 'CheckUserExists'] as $name) {
            if (preg_match('#<' . $name . '[\s>]#i', $data)) {
                $command = $name;
                break;
            }
        }
        return '<?xml version="1.0" encoding="UTF-8" standalone="yes" ?>' . "\n"
            . '<multiOTP version="4.0" xmlns="http://www.sysco.ch/namespaces/multiotp">' . "\n"
            . '<DebugCode>' . $command . '</DebugCode>' . "\n"
            . '<ServerPassword>' . md5($command . $secret . $challenge) . '</ServerPassword>' . "\n"
            . '<ErrorCode>' . self::LOST_ERROR . '</ErrorCode>' . "\n"
            . '<ErrorDescription>ERROR: This computer is reported lost or stolen</ErrorDescription>' . "\n"
            . '</multiOTP>';
    }

    /** User attributes never sent to an endpoint (ReadUserData). */
    public const PRIVATE_ATTRIBUTES = [
        'email', 'sms', 'description', 'display_name', 'group', 'user_principal_name', 'language',
        'synchronized', 'synchronized_dn', 'synchronized_server', 'synchronized_channel', 'synchronized_time',
        'last_login', 'user_last_login', 'last_error', 'last_failed_time', 'last_success_credential',
        'last_failed_credential', 'last_cached_credential', 'create_host', 'last_update_host',
        'token_serial', 'private_id', 'key_id', 'mosid', 'mouid', 'push_gateway',
    ];

    /** _MULTIOTP_USER_DISABLED_: an error the client stops at (22..69), without deleting the cached user. */
    public const LOST_ERROR = 38;

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
