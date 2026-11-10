<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * REST API (portal/api.php), version 1. JSON in and out, no session and no cookies: every
 * call except /v1/health carries an API key (Authorization: Bearer sohob_..., see ApiKeys)
 * with the scope the call needs. State changes are audited as "api:<key name>".
 *
 *   GET    /v1/health                       no key
 *   GET    /v1/me                           the key itself
 *   GET    /v1/users?q=&status=&page=&per_page=        users.read
 *   GET    /v1/users/{user}                             users.read
 *   POST   /v1/users                                    users.write  (returns provisioning_uri)
 *   PATCH  /v1/users/{user}                             users.write  display_name, email, sms,
 *                                                                    description, group, enabled
 *   DELETE /v1/users/{user}                             users.write
 *   POST   /v1/users/{user}/unlock                      users.write
 *   POST   /v1/users/{user}/route   {"route": "sohobotp"|"vip"}  users.write (Symantec VIP)
 *   POST   /v1/users/{user}/enroll                      tokens.write (returns provisioning_uri)
 *   POST   /v1/auth/check           {"user", "code"}    auth.check   accepted|rejected|locked|unknown
 *   GET    /v1/endpoints                                endpoints.read
 *   GET    /v1/radius/servers                           radius.read  (no secrets)
 *   GET    /v1/audit?action=&limit=                     audit.read
 *
 * The path comes from PATH_INFO (/portal/api.php/v1/users) or, without it, from ?path=.
 */
final class Api
{
    private const MAX_BODY = 65536;

    public static function run(): void
    {
        ob_start(); // anything the engine prints (warnings, notices) never reaches the JSON answer
        header('Content-Type: application/json');
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        Audit::setIp($ip);
        $throttle = new Throttle(new JsonStore(Config::dataDir() . '/api-throttle.json'));
        try {
            if (!self::isHttps() && !Config::allowHttp()) {
                throw new ApiError('https_required', 403, 'HTTPS is required.');
            }
            $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
            $path = '/' . trim((string) ($_SERVER['PATH_INFO'] ?? ($_GET['path'] ?? '')), '/');
            if ('GET' === $method && '/v1/health' === $path) {
                self::respond(200, ['status' => 'ok', 'product' => Config::brandName(), 'api' => 1]);
            }
            if ($throttle->isBlocked($ip)) {
                throw new ApiError('rate_limited', 429, 'Too many failed requests from this address. Try again later.');
            }
            $auth = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
            try {
                $key = (new ApiKeys())->authenticate(preg_replace('/^Bearer\s+/i', '', trim($auth)) ?? '', $ip);
            } catch (ApiError $error) {
                if (401 === $error->status) {
                    $throttle->fail($ip);
                }
                throw $error;
            }
            Audit::setActor('api:' . $key['name'], 'api');
            $body = [];
            if (in_array($method, ['POST', 'PATCH', 'PUT'], true)) {
                $raw = (string) file_get_contents('php://input', false, null, 0, self::MAX_BODY + 1);
                if (strlen($raw) > self::MAX_BODY) {
                    throw new ApiError('bad_request', 413, 'Request body too large.');
                }
                if ('' !== trim($raw)) {
                    $body = json_decode($raw, true);
                    if (!is_array($body)) {
                        throw new ApiError('bad_request', 400, 'The body must be a JSON object.');
                    }
                }
            }
            self::respond(...self::route($method, $path, $body, $key));
        } catch (ApiError $error) {
            self::respond($error->status, ['error' => $error->errorCode, 'message' => $error->getMessage()]);
        } catch (ValidationException $invalid) {
            self::respond(422, ['error' => 'invalid', 'message' => $invalid->getMessage()]);
        } catch (\Throwable $error) {
            error_log('SohobOTP API: ' . $error);
            self::respond(500, ['error' => 'server_error', 'message' => 'The request could not be completed.']);
        }
    }

    /** @return array{0: int, 1: array} */
    public static function route(string $method, string $path, array $body, array $key): array
    {
        $need = static function (string $scope) use ($key): void {
            if (!in_array($scope, $key['scopes'], true)) {
                throw new ApiError('forbidden', 403, "This API key does not have the \"$scope\" permission.");
            }
        };
        $audit = Audit::default();
        $users = new Users();
        $userOr404 = static function (string $name) use ($users): array {
            return $users->get($name) ?? throw new ApiError('not_found', 404, 'This user does not exist.');
        };
        $segments = array_values(array_filter(explode('/', $path), 'strlen'));
        $route = implode('/', array_map(static fn (string $s, int $i): string => (2 === $i && 'users' === ($segments[1] ?? '')) ? '{user}' : $s, $segments, array_keys($segments)));
        $name = isset($segments[2]) && 'users' === $segments[1] ? rawurldecode($segments[2]) : '';

        switch ("$method $route") {
            case 'GET v1/me':
                return [200, array_intersect_key($key, array_flip(['id', 'name', 'scopes', 'networks', 'expires_at', 'rate']))];

            case 'GET v1/users':
                $need('users.read');
                $perPage = max(1, min(500, (int) ($_GET['per_page'] ?? 100)));
                $page = max(1, (int) ($_GET['page'] ?? 1));
                $found = $users->search(mb_substr((string) ($_GET['q'] ?? ''), 0, 128), mb_substr((string) ($_GET['status'] ?? ''), 0, 16), $page, $perPage);
                return [200, ['total' => $found['total'], 'page' => $page, 'per_page' => $perPage, 'users' => array_map(self::listedUser(...), $found['users'])]];

            case 'GET v1/users/{user}':
                $need('users.read');
                return [200, self::user($userOr404($name))];

            case 'POST v1/users':
                $need('users.write');
                $input = [];
                foreach (['user', 'display_name', 'email', 'sms', 'description', 'group', 'token_serial'] as $field) {
                    $input[$field] = mb_substr(trim((string) ($body[$field] ?? '')), 0, 255);
                }
                if ($users->exists($input['user'])) {
                    throw new ApiError('conflict', 409, 'A user with this name already exists.');
                }
                $created = $users->create($input);
                (new VipMigration())->export();
                $audit->record('user.create', 'success', $created['user'], ['token' => '' === $input['token_serial'] ? 'software' : 'hardware ' . $input['token_serial'], 'via' => 'api']);
                return [201, ['user' => self::user($userOr404($created['user'])), 'provisioning_uri' => $created['otpauth']]];

            case 'PATCH v1/users/{user}':
                $need('users.write');
                $current = $userOr404($name);
                $fields = [];
                foreach (['display_name', 'email', 'sms', 'description', 'group'] as $field) {
                    $fields[$field] = array_key_exists($field, $body) ? mb_substr(trim((string) $body[$field]), 0, 255) : $current[$field];
                }
                $changes = $users->update($name, $fields);
                if (array_key_exists('enabled', $body)) {
                    if (!is_bool($body['enabled'])) {
                        throw new ApiError('invalid', 422, '"enabled" must be true or false.');
                    }
                    if ($body['enabled'] !== $current['enabled']) {
                        $users->setEnabled($name, $body['enabled']);
                        $changes['enabled'] = ['from' => $current['enabled'], 'to' => $body['enabled']];
                    }
                }
                if (isset($changes['group']) || isset($changes['enabled'])) {
                    (new VipMigration())->export();
                }
                $audit->record('user.update', 'success', $name, ['changes' => $changes, 'via' => 'api']);
                return [200, self::user($userOr404($name))];

            case 'DELETE v1/users/{user}':
                $need('users.write');
                $userOr404($name);
                $users->delete($name);
                (new VipMigration())->forget($name);
                $audit->record('user.delete', 'success', $name, ['via' => 'api']);
                return [200, ['deleted' => $name]];

            case 'POST v1/users/{user}/unlock':
                $need('users.write');
                $userOr404($name);
                $users->unlock($name);
                $audit->record('user.unlock', 'success', $name, ['via' => 'api']);
                return [200, self::user($userOr404($name))];

            case 'POST v1/users/{user}/route':
                $need('users.write');
                $userOr404($name);
                $routeTo = (string) ($body['route'] ?? '');
                if (!isset(VipMigration::STATES[$routeTo])) {
                    throw new ApiError('invalid', 422, '"route" must be "sohobotp" or "vip".');
                }
                (new VipMigration())->set([$name], $routeTo, 'api:' . $key['name'], 'by the API');
                $audit->record('user.vip_route', 'success', $name, ['route' => $routeTo, 'via' => 'api']);
                return [200, ['user' => $name, 'route' => $routeTo]];

            case 'POST v1/users/{user}/enroll':
                $need('tokens.write');
                $userOr404($name);
                $uri = $users->enrollSoftwareToken($name);
                (new VipMigration())->set([$name], 'sohobotp', 'api:' . $key['name'], 'authenticator enrolled');
                $audit->record('user.token_enrolled', 'success', $name, ['type' => 'software TOTP', 'via' => 'api']);
                return [200, ['user' => $name, 'provisioning_uri' => $uri]];

            case 'POST v1/auth/check':
                $need('auth.check');
                $user = mb_substr(trim((string) ($body['user'] ?? '')), 0, 128);
                $code = mb_substr(trim((string) ($body['code'] ?? '')), 0, 256);
                if ('' === $user || '' === $code) {
                    throw new ApiError('invalid', 422, '"user" and "code" are required.');
                }
                $result = 'unknown';
                if ($users->exists($user)) {
                    $engine = MultiotpService::get();
                    $engine->SetUser($user);
                    $rc = (int) $engine->CheckToken($code);
                    $result = match (true) {
                        0 === $rc                                 => 'accepted',
                        in_array($rc, [24, 25], true)             => 'locked',   // locked or delayed after failures
                        38 === $rc                                => 'disabled',
                        default                                   => 'rejected',
                    };
                }
                $audit->record('api.auth_check', 'accepted' === $result ? 'success' : 'failure', $user, ['result' => $result]);
                return [200, ['user' => $user, 'result' => $result]];

            case 'GET v1/endpoints':
                $need('endpoints.read');
                $list = array_map(static fn (array $e): array => array_diff_key($e, ['sign_key' => true, 'box_key' => true]), (new Endpoints())->endpoints());
                return [200, ['endpoints' => $list]];

            case 'GET v1/radius/servers':
                $need('radius.read');
                $radius = new Radius();
                return [200, ['groups' => $radius->groups(), 'servers' => $radius->clients()]];

            case 'GET v1/audit':
                $need('audit.read');
                $limit = max(1, min(1000, (int) ($_GET['limit'] ?? 100)));
                $filters = array_filter(['action' => mb_substr((string) ($_GET['action'] ?? ''), 0, 64)], 'strlen');
                return [200, ['entries' => $audit->search($filters, 1, $limit)['entries']]];
        }
        if ([] === $segments || 'v1' !== $segments[0]) {
            throw new ApiError('not_found', 404, 'Unknown API path. Version 1 is under /v1/.');
        }
        throw new ApiError('not_found', 404, "No API call $method /$path.");
    }

    private static function user(array $u): array
    {
        return ['user' => $u['user'], 'display_name' => $u['display_name'], 'email' => $u['email'], 'sms' => $u['sms'],
            'description' => $u['description'], 'group' => $u['group'], 'enabled' => $u['enabled'], 'locked' => $u['locked'],
            'token' => '' !== $u['token_serial'] ? 'hardware ' . $u['token_serial'] : 'software ' . $u['algorithm'],
            'login_format' => $u['login_format'], 'last_login' => $u['last_login'], 'synchronized' => $u['synchronized'],
            'route' => (new VipMigration())->stateOf($u['user'])['state'] ?? null];
    }

    private static function listedUser(array $u): array
    {
        return ['user' => $u['user'], 'display_name' => $u['display_name'] ?? '', 'email' => $u['email'] ?? '', 'group' => $u['group'] ?? '',
            'enabled' => (bool) ($u['enabled'] ?? false), 'locked' => (bool) ($u['locked'] ?? false), 'token' => (string) ($u['token'] ?? ''),
            'synchronized' => (bool) (int) ($u['synchronized'] ?? 0)];
    }

    private static function respond(int $status, array $data): never
    {
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
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
