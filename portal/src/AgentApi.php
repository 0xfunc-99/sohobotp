<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * HTTP entry point for endpoint agents (portal/agent.php). No session, no cookies:
 * every request except enrolment is signed by the endpoint key (docs/agent-protocol.md).
 */
final class AgentApi
{
    public static function run(): void
    {
        header('Content-Type: application/json');
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        Audit::setIp($ip);
        $throttle = new Throttle(new JsonStore(Config::dataDir() . '/agent-throttle.json'));
        try {
            if (!self::isHttps() && !Config::allowHttp()) {
                throw new AgentError('bad_request', 403, 'HTTPS is required.');
            }
            if ('POST' !== ($_SERVER['REQUEST_METHOD'] ?? '')) {
                throw new AgentError('bad_request', 405, 'Use POST.');
            }
            if ($throttle->isBlocked($ip)) {
                throw new AgentError('rate_limited', 429, 'Too many failed requests from this address. Try again later.');
            }
            $length = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
            if ($length > Endpoints::MAX_BODY) {
                throw new AgentError('bad_request', 413, 'Request too large.');
            }
            $body = (string) file_get_contents('php://input', false, null, 0, Endpoints::MAX_BODY + 1);
            if (strlen($body) > Endpoints::MAX_BODY) {
                throw new AgentError('bad_request', 413, 'Request too large.');
            }
            $request = json_decode($body, true);
            if (!is_array($request)) {
                throw new AgentError('bad_request', 400, 'The body must be a JSON object.');
            }
            $endpoints = new Endpoints();
            switch ((string) ($_GET['a'] ?? '')) {
                case 'enroll':
                    $host = (string) ($_SERVER['HTTP_HOST'] ?? '');
                    if (!preg_match('/^(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]{1,253})(:\d{1,5})?$/', $host)) {
                        throw new AgentError('bad_request', 400, 'Invalid Host header.');
                    }
                    Audit::setActor('agent-enrolment');
                    try {
                        $result = $endpoints->enroll($request, $ip, strtolower($host));
                    } catch (AgentError $error) {
                        if ('bad_token' === $error->errorCode) {
                            Audit::default()->record('endpoint.enroll', 'failure', (string) ($request['inventory']['hostname'] ?? ''), ['reason' => $error->errorCode]);
                        }
                        throw $error;
                    }
                    $endpoint = $endpoints->endpoint($result['endpoint_id']);
                    Audit::setActor('agent:' . $result['endpoint_id']);
                    Audit::default()->record('endpoint.enroll', 'success', $endpoint['inventory']['hostname'] ?? '', [
                        'endpoint' => $result['endpoint_id'], 'os' => $endpoint['os'], 'group' => $endpoint['group_id'], 'token' => $endpoint['token_id'],
                    ]);
                    self::respond(200, $result);
                    // no break: respond() exits
                case 'checkin':
                    $id = $endpoints->authenticate(self::headers(), 'POST', (string) ($_SERVER['REQUEST_URI'] ?? ''), $body);
                    self::respond(200, $endpoints->checkin($id, $request, $ip));
                    // no break
                case 'release':
                    $id = $endpoints->authenticate(self::headers(), 'POST', (string) ($_SERVER['REQUEST_URI'] ?? ''), $body);
                    $file = $endpoints->releaseFile($id, $request);
                    header('Content-Type: application/octet-stream');
                    header('Content-Length: ' . filesize($file));
                    readfile($file);
                    exit;
                case 'package':
                    // SohobOTP Sign-in / Visual C++ runtime the agent installs (the policy names them)
                    $id = $endpoints->authenticate(self::headers(), 'POST', (string) ($_SERVER['REQUEST_URI'] ?? ''), $body);
                    $file = $endpoints->packageFile($id, $request);
                    header('Content-Type: application/octet-stream');
                    header('Content-Length: ' . filesize($file));
                    readfile($file);
                    exit;
                default:
                    throw new AgentError('bad_request', 404, 'Unknown action.');
            }
        } catch (AgentError $error) {
            // Counted against the IP: guessed tokens, forged signatures, made-up endpoint ids.
            // Not counted: machines the portal knows (disabled, pending, or deleted with the
            // agent still installed); many of them behind one NAT address must not block
            // every other machine there.
            $counted = in_array($error->errorCode, ['bad_token', 'bad_signature'], true)
                || ('unknown_endpoint' === $error->errorCode && !(new Endpoints())->wasDeleted((string) ($_SERVER['HTTP_X_AGENT_ID'] ?? '')));
            if ($counted) {
                $throttle->fail($ip);
            }
            self::respond($error->status, ['error' => $error->errorCode, 'message' => $error->getMessage()]);
        } catch (\Throwable $error) {
            error_log('multiOTP portal agent API: ' . $error);
            self::respond(500, ['error' => 'server_error', 'message' => 'The request could not be completed.']);
        }
    }

    /** @return array<string, string> the X-Agent-* headers, lower-case names */
    private static function headers(): array
    {
        $headers = [];
        foreach (['id', 'time', 'nonce', 'signature'] as $name) {
            $headers["x-agent-$name"] = (string) ($_SERVER['HTTP_X_AGENT_' . strtoupper($name)] ?? '');
        }
        return $headers;
    }

    private static function respond(int $status, array $data): never
    {
        http_response_code($status);
        echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        exit;
    }

    private static function isHttps(): bool
    {
        return (!empty($_SERVER['HTTPS']) && 'off' !== strtolower((string) $_SERVER['HTTPS']))
            || '443' === (string) ($_SERVER['SERVER_PORT'] ?? '');
    }
}
