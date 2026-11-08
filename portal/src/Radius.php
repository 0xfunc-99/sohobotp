<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * FreeRADIUS clients ("servers": VPN gateways, firewalls, Wi-Fi controllers...) grouped
 * into server groups.
 *
 * - A server group holds the authentication policy; every client in it inherits it.
 * - Each client is written as a multiOTP device (so the engine applies the policy at login,
 *   found through the FreeRADIUS short name "<name>-<id>") and as a FreeRADIUS client in a
 *   generated file. Shared secrets are sealed in radius.json with the portal key and only
 *   appear in clear in the generated FreeRADIUS file.
 * - Applying writes a candidate file; the root helper (bin/multiotp-portal-radius, run with
 *   sudo) validates it, installs it, checks the whole FreeRADIUS configuration and restarts
 *   FreeRADIUS, or rolls back.
 *
 * radius.json: { groups: {id: group}, clients: {id: client}, diagnostics_secret, pending,
 *                last_apply: {job, status, at, output} }
 */
final class Radius
{
    public const NAS_TYPES = ['other' => 'Other / generic', 'cisco' => 'Cisco', 'juniper' => 'Juniper'];
    public const DEFAULT_POLICY = [
        'challenge_response'   => false,
        'text_token_challenge' => 'Please enter the code displayed on the token',
        'sms_challenge'        => false,
        'text_sms_challenge'   => 'Please enter the code received on your mobile phone',
        'cache_result'         => false,
        'cache_timeout'        => 3600,
        'dont_send_groups'     => false,
        'force_no_prefix_pin'  => false,
    ];
    /** Used by the portal's own test login; must not be used by a real client. */
    public const DIAGNOSTICS_ADDRESS = '127.0.0.2';
    /** Already defined in the stock clients.conf ("localhost"). */
    private const RESERVED = ['127.0.0.1/32', '127.0.0.2/32', '::1/128'];
    public const HELPER = '/usr/local/sbin/multiotp-portal-radius';

    private JsonStore $store;

    public function __construct(?JsonStore $store = null)
    {
        $this->store = $store ?? new JsonStore(Config::dataDir() . '/radius.json');
    }

    public static function candidateFile(): string
    {
        $dir = Config::ensureDataDir() . '/radius';
        if (!is_dir($dir) && !@mkdir($dir, 0700) && !is_dir($dir)) {
            throw new \RuntimeException('Cannot create the RADIUS folder.');
        }
        return $dir . '/clients.candidate.conf';
    }

    // ------------------------------------------------------------------
    // Server groups
    // ------------------------------------------------------------------

    /** @return list<array> sorted by name, each with "clients" (count) */
    public function groups(): array
    {
        $data = $this->store->read();
        $groups = array_values($data['groups'] ?? []);
        foreach ($groups as &$group) {
            $group['clients'] = count(array_filter($data['clients'] ?? [], static fn (array $c): bool => $c['group_id'] === $group['id']));
        }
        unset($group);
        usort($groups, static fn (array $a, array $b): int => strcasecmp($a['name'], $b['name']));
        return $groups;
    }

    public function group(string $id): ?array
    {
        return $this->store->read()['groups'][$id] ?? null;
    }

    public function saveGroup(?string $id, array $input): array
    {
        $name = trim((string) ($input['name'] ?? ''));
        if (!preg_match('/^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,63}$/u', $name)) {
            throw new ValidationException('Group names are 1-64 characters: letters, digits, space, dot, dash, underscore.');
        }
        $policy = self::policyFromInput($input);
        $group = $this->store->update(static function (array &$data) use ($id, $name, $input, $policy): array {
            foreach ($data['groups'] ?? [] as $existing) {
                if ($existing['id'] !== $id && 0 === strcasecmp($existing['name'], $name)) {
                    throw new ValidationException('A server group with this name already exists.');
                }
            }
            if (null !== $id && !isset($data['groups'][$id])) {
                throw new ValidationException('This server group no longer exists.');
            }
            $now = time();
            $group = null === $id
                ? ['id' => bin2hex(random_bytes(6)), 'created_at' => $now]
                : $data['groups'][$id];
            $group['name'] = $name;
            $group['description'] = trim(mb_substr((string) ($input['description'] ?? ''), 0, 255));
            $group['policy'] = $policy;
            $group['updated_at'] = $now;
            $data['groups'][$group['id']] = $group;
            $data['pending'] = true;
            return $group;
        });
        foreach ($this->clients() as $client) {
            if ($client['group_id'] === $group['id']) {
                $this->writeDevice($client, $group);
            }
        }
        return $group;
    }

    public function deleteGroup(string $id): array
    {
        return $this->store->update(static function (array &$data) use ($id): array {
            $group = $data['groups'][$id] ?? throw new ValidationException('This server group does not exist.');
            foreach ($data['clients'] ?? [] as $client) {
                if ($client['group_id'] === $id) {
                    throw new ValidationException('Move or delete the servers in this group first.');
                }
            }
            unset($data['groups'][$id]);
            return $group;
        });
    }

    // ------------------------------------------------------------------
    // RADIUS clients
    // ------------------------------------------------------------------

    /** @return list<array> sorted by name, secrets removed */
    public function clients(): array
    {
        $clients = array_values(array_map([self::class, 'public'], $this->store->read()['clients'] ?? []));
        usort($clients, static fn (array $a, array $b): int => strcmp($a['name'], $b['name']));
        return $clients;
    }

    public function client(string $id): ?array
    {
        $client = $this->store->read()['clients'][$id] ?? null;
        return null === $client ? null : self::public($client);
    }

    /** @return array{0: array, 1: string} the client and its secret (show once) */
    public function createClient(array $input): array
    {
        [$fields, $group] = $this->validateClient(null, $input);
        $secret = '' !== trim((string) ($input['secret'] ?? '')) ? self::validSecret((string) $input['secret']) : self::newSecret();
        $client = $this->store->update(static function (array &$data) use ($fields, $secret): array {
            self::assertUniqueAddress($data, $fields['address'], null);
            self::assertUniqueName($data, $fields['name'], null);
            $now = time();
            $client = $fields + [
                'id'             => bin2hex(random_bytes(6)),
                'secret'         => Crypto::encrypt($secret),
                'secret_set_at'  => $now,
                'created_at'     => $now,
                'updated_at'     => $now,
            ];
            $data['clients'][$client['id']] = $client;
            $data['pending'] = true;
            return $client;
        });
        $this->writeDevice($client, $group);
        return [self::public($client), $secret];
    }

    public function updateClient(string $id, array $input): array
    {
        [$fields, $group] = $this->validateClient($id, $input);
        $client = $this->store->update(static function (array &$data) use ($id, $fields): array {
            $client = $data['clients'][$id] ?? throw new ValidationException('This server does not exist.');
            self::assertUniqueAddress($data, $fields['address'], $id);
            self::assertUniqueName($data, $fields['name'], $id);
            $client = $fields + $client;
            $client['updated_at'] = time();
            $data['clients'][$id] = $client;
            $data['pending'] = true;
            return $client;
        });
        $this->writeDevice($client, $group);
        return self::public($client);
    }

    public function rotateSecret(string $id, string $custom = ''): string
    {
        $secret = '' !== trim($custom) ? self::validSecret($custom) : self::newSecret();
        $this->store->update(static function (array &$data) use ($id, $secret): void {
            if (!isset($data['clients'][$id])) {
                throw new ValidationException('This server does not exist.');
            }
            $data['clients'][$id]['secret'] = Crypto::encrypt($secret);
            $data['clients'][$id]['secret_set_at'] = time();
            $data['clients'][$id]['updated_at'] = time();
            $data['pending'] = true;
        });
        return $secret;
    }

    public function deleteClient(string $id): array
    {
        $client = $this->store->update(static function (array &$data) use ($id): array {
            $client = $data['clients'][$id] ?? throw new ValidationException('This server does not exist.');
            unset($data['clients'][$id]);
            $data['pending'] = true;
            return $client;
        });
        MultiotpService::get()->DeleteDevice($id, true);
        return self::public($client);
    }

    // ------------------------------------------------------------------
    // FreeRADIUS configuration
    // ------------------------------------------------------------------

    /** The generated FreeRADIUS clients file (contains shared secrets in clear). */
    public function render(): string
    {
        $data = $this->store->read();
        $out = "# Generated by the multiOTP management portal. Do not edit: changes are overwritten.\n";
        $out .= '# Servers: ' . count($data['clients'] ?? []) . "\n\n";
        $clients = $data['clients'] ?? [];
        uasort($clients, static fn (array $a, array $b): int => strcmp($a['name'], $b['name']));
        foreach ($clients as $client) {
            $out .= self::block(self::shortname($client), $client['address'], Crypto::decrypt($client['secret']), $client['nas_type'], (bool) $client['require_message_authenticator']);
        }
        $out .= "# Portal diagnostics (test login from the portal itself)\n";
        $out .= self::block('multiotp-portal-diagnostics', self::DIAGNOSTICS_ADDRESS . '/32', $this->diagnosticsSecret(), 'other', true);
        return $out;
    }

    public function state(): array
    {
        $data = $this->store->read();
        return ['pending' => (bool) ($data['pending'] ?? false), 'last_apply' => $data['last_apply'] ?? null];
    }

    /**
     * Write the candidate file and ask the root helper to install it. Runs in the worker.
     * @return array{ok: bool, available: bool, output: string}
     */
    public function apply(): array
    {
        $candidate = self::candidateFile();
        $content = $this->render();
        $tmp = $candidate . '.tmp';
        file_put_contents($tmp, $content);
        @chmod($tmp, 0600);
        rename($tmp, $candidate);
        $result = self::helper('apply');
        $this->store->update(static function (array &$data) use ($result, $content): void {
            if ($result['ok']) {
                $data['pending'] = false;
            }
            $data['last_apply'] = ['status' => $result['ok'] ? 'applied' : ($result['available'] ? 'rejected' : 'not available'),
                'at' => time(), 'hash' => hash('sha256', $content), 'output' => $result['output']];
        });
        return $result;
    }

    /** @return array{available: bool, running: ?bool, default_client: ?bool, output: string} */
    public static function status(): array
    {
        $result = self::helper('status');
        if (!$result['available']) {
            return ['available' => false, 'running' => null, 'default_client' => null, 'output' => $result['output']];
        }
        return [
            'available'      => true,
            'running'        => str_contains($result['output'], 'freeradius=running'),
            'default_client' => str_contains($result['output'], 'default_client=active'),
            'output'         => $result['output'],
        ];
    }

    public static function disableDefaultClient(): array
    {
        return self::helper('disable-default-client');
    }

    /**
     * Run the root helper with a fixed command (no other arguments are ever passed).
     * @return array{ok: bool, available: bool, output: string}
     */
    public static function helper(string $command): array
    {
        if (!in_array($command, ['apply', 'status', 'check', 'restart', 'disable-default-client'], true)) {
            throw new \InvalidArgumentException('Unknown helper command.');
        }
        $helper = getenv('MULTIOTP_PORTAL_RADIUS_HELPER') ?: self::HELPER;
        if (!is_file($helper)) {
            return ['ok' => false, 'available' => false, 'output' => 'The FreeRADIUS helper is not installed on this system (' . $helper . ').'];
        }
        $argv = function_exists('posix_geteuid') && 0 === posix_geteuid()
            ? [$helper, $command]
            : ['sudo', '-n', $helper, $command];
        $process = proc_open($argv, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($process)) {
            return ['ok' => false, 'available' => false, 'output' => 'The FreeRADIUS helper could not be started.'];
        }
        $output = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($process);
        if (str_contains($output, 'a password is required') || str_contains($output, 'sudo:')) {
            return ['ok' => false, 'available' => false, 'output' => 'sudo does not allow the web server user to run the FreeRADIUS helper. ' . trim($output)];
        }
        return ['ok' => 0 === $code, 'available' => true, 'output' => trim(mb_substr($output, 0, 20000))];
    }

    // ------------------------------------------------------------------
    // Diagnostics
    // ------------------------------------------------------------------

    public function diagnosticsSecret(): string
    {
        $sealed = $this->store->update(static function (array &$data): string {
            if (empty($data['diagnostics_secret'])) {
                $data['diagnostics_secret'] = Crypto::encrypt(self::newSecret());
                $data['pending'] = true;
            }
            return $data['diagnostics_secret'];
        });
        return Crypto::decrypt($sealed);
    }

    /** Send a real Access-Request through the local FreeRADIUS, as a NAS would. */
    public function testLogin(string $user, string $password): array
    {
        $host = getenv('MULTIOTP_PORTAL_RADIUS_HOST') ?: '127.0.0.1';
        return RadiusClient::authenticate($host, 1812, $this->diagnosticsSecret(), $user, $password, self::DIAGNOSTICS_ADDRESS, 10);
    }

    /**
     * Recent logins from the multiOTP engine log (category "User"), newest first.
     * @return list<array{time: string, level: string, user: string, message: string}>
     */
    public static function recentLogins(string $userFilter = '', string $result = '', int $limit = 100): array
    {
        $engine = MultiotpService::get();
        $file = $engine->GetLogFolder() . $engine->GetLogFileName();
        if (!is_file($file)) {
            return [];
        }
        $size = (int) filesize($file);
        $handle = fopen($file, 'r');
        if (false === $handle) {
            return [];
        }
        fseek($handle, max(0, $size - 2_000_000));
        $lines = preg_split('/\r?\n/', (string) stream_get_contents($handle)) ?: [];
        fclose($handle);
        $events = [];
        foreach (array_reverse($lines) as $line) {
            $c = explode("\t", $line);
            if (count($c) < 5 || 'User' !== $c[3]) {
                continue;
            }
            $message = trim($c[4]);
            if (str_starts_with($message, 'Debug:') || str_starts_with($message, 'Developer:')) {
                continue;
            }
            $ok = (bool) preg_match('/successfully logged in/i', $message);
            if ('' !== $userFilter && false === stripos($c[2] . ' ' . $message, $userFilter)) {
                continue;
            }
            if (('accepted' === $result && !$ok) || ('rejected' === $result && $ok)) {
                continue;
            }
            $events[] = ['time' => $c[0], 'level' => $c[1], 'user' => $c[2], 'message' => $message, 'ok' => $ok];
            if (count($events) >= $limit) {
                break;
            }
        }
        return $events;
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    public static function shortname(array $client): string
    {
        return $client['name'] . '-' . $client['id'];
    }

    public static function newSecret(): string
    {
        $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
        $out = '';
        for ($i = 0; $i < 24; $i++) {
            $out .= $alphabet[random_int(0, strlen($alphabet) - 1)];
        }
        return $out;
    }

    /** Printable ASCII without quote, backslash, $ and % (FreeRADIUS config syntax), 16-128 chars. */
    public static function validSecret(string $secret): string
    {
        if (!preg_match('/^[A-Za-z0-9!#&\'()*+,\-.\/:;<=>?@\[\]^_`{|}~]{16,128}$/', $secret)) {
            throw new ValidationException('Custom secrets need 16-128 characters: letters, digits and punctuation except quotes, backslash, $, % and spaces.');
        }
        return $secret;
    }

    /** Normalise "10.0.0.5", "10.0.0.0/24", "2001:db8::/64" to network/prefix. */
    public static function normaliseAddress(string $input): string
    {
        $input = trim($input);
        [$ip, $prefix] = array_pad(explode('/', $input, 2), 2, null);
        $binary = @inet_pton((string) $ip);
        if (false === $binary || !filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new ValidationException('Enter an IP address or network, e.g. 10.0.0.5 or 10.0.0.0/24 (host names are not accepted).');
        }
        $bits = 8 * strlen($binary);
        if (null === $prefix) {
            $prefix = $bits;
        } elseif (!ctype_digit($prefix) || (int) $prefix > $bits) {
            throw new ValidationException('Invalid network prefix.');
        }
        $prefix = (int) $prefix;
        if ($prefix < 8) {
            throw new ValidationException('Networks larger than /8 are not accepted: list the real servers or subnets.');
        }
        $masked = '';
        for ($i = 0; $i < strlen($binary); $i++) {
            $keep = max(0, min(8, $prefix - 8 * $i));
            $masked .= chr(ord($binary[$i]) & (0xff << (8 - $keep)) & 0xff);
        }
        $normalised = inet_ntop($masked) . '/' . $prefix;
        if (in_array($normalised, self::RESERVED, true)) {
            throw new ValidationException('This address is reserved for local clients on the server.');
        }
        return $normalised;
    }

    private function validateClient(?string $id, array $input): array
    {
        $name = mb_strtolower(trim((string) ($input['name'] ?? '')));
        if (!preg_match('/^[a-z0-9][a-z0-9-]{0,39}$/', $name)) {
            throw new ValidationException('Server names are 1-40 characters: lowercase letters, digits and dashes.');
        }
        $group = $this->group((string) ($input['group_id'] ?? '')) ?? throw new ValidationException('Choose a server group.');
        $nas = (string) ($input['nas_type'] ?? 'other');
        if (!isset(self::NAS_TYPES[$nas])) {
            throw new ValidationException('Unknown device type.');
        }
        return [[
            'name'                          => $name,
            'description'                   => trim(mb_substr((string) ($input['description'] ?? ''), 0, 255)),
            'address'                       => self::normaliseAddress((string) ($input['address'] ?? '')),
            'group_id'                      => $group['id'],
            'nas_type'                      => $nas,
            'require_message_authenticator' => !empty($input['require_message_authenticator']),
        ], $group];
    }

    private static function assertUniqueAddress(array $data, string $address, ?string $except): void
    {
        foreach ($data['clients'] ?? [] as $client) {
            if ($client['id'] !== $except && $client['address'] === $address) {
                throw new ValidationException('Another server already uses ' . $address . '.');
            }
        }
    }

    private static function assertUniqueName(array $data, string $name, ?string $except): void
    {
        foreach ($data['clients'] ?? [] as $client) {
            if ($client['id'] !== $except && $client['name'] === $name) {
                throw new ValidationException('Another server already uses this name.');
            }
        }
    }

    private static function policyFromInput(array $input): array
    {
        $timeout = (string) ($input['cache_timeout'] ?? '3600');
        if (!ctype_digit($timeout) || (int) $timeout < 60 || (int) $timeout > 86400) {
            throw new ValidationException('The cache duration must be between 60 and 86400 seconds.');
        }
        $text = static fn (string $key): string => trim(mb_substr(preg_replace('/[\x00-\x1f]/u', ' ', (string) ($input[$key] ?? '')) ?? '', 0, 200)) ?: self::DEFAULT_POLICY[$key];
        return [
            'challenge_response'   => !empty($input['challenge_response']),
            'text_token_challenge' => $text('text_token_challenge'),
            'sms_challenge'        => !empty($input['sms_challenge']),
            'text_sms_challenge'   => $text('text_sms_challenge'),
            'cache_result'         => !empty($input['cache_result']),
            'cache_timeout'        => (int) $timeout,
            'dont_send_groups'     => !empty($input['dont_send_groups']),
            'force_no_prefix_pin'  => !empty($input['force_no_prefix_pin']),
        ];
    }

    /** Mirror the client and its group policy into the multiOTP device the engine reads at login. */
    private function writeDevice(array $client, array $group): void
    {
        $engine = MultiotpService::get();
        $id = $client['id'];
        [$network, $prefix] = explode('/', $client['address']);
        $isV4 = false !== filter_var($network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
        $mask = $isV4 ? long2ip(-1 << (32 - (int) $prefix) & 0xffffffff) : '';
        $p = $group['policy'] + self::DEFAULT_POLICY;
        if (!$engine->ReadDeviceData($id, false, true)) {
            $engine->CreateDevice(['id' => $id, 'description' => $client['name'], 'ip_or_fqdn' => $network, 'subnet' => $mask, 'shortname' => self::shortname($client), 'with_radius_update' => false]);
            $engine->ReadDeviceData($id, false, true);
        }
        $engine->SetDevice($id);
        $engine->SetDeviceDescription($client['name'] . ('' !== $client['description'] ? ' — ' . $client['description'] : ''));
        $engine->SetDeviceIpOrFqdn($network);
        $engine->SetDeviceSubnet($mask);
        $engine->SetDeviceShortname(self::shortname($client));
        $engine->SetDeviceChallengeEnabled($p['challenge_response'] ? 1 : 0);
        $engine->SetDeviceTextTokenChallenge($p['text_token_challenge']);
        $engine->SetDeviceSmsChallengeEnabled($p['sms_challenge'] ? 1 : 0);
        $engine->SetDeviceTextSmsChallenge($p['text_sms_challenge']);
        $engine->SetDeviceCacheResultEnabled($p['cache_result'] ? 1 : 0);
        $engine->SetDeviceCacheTimeout($p['cache_timeout']);
        $engine->SetDeviceDontSendGroups($p['dont_send_groups'] ? 1 : 0);
        $engine->SetDeviceForceNoPrefixEnabled($p['force_no_prefix_pin'] ? 1 : 0);
        if (!$engine->WriteDeviceData(['with_radius_update' => false])) {
            throw new \RuntimeException('multiOTP could not save the device for ' . $client['name'] . '.');
        }
    }

    private static function block(string $name, string $address, string $secret, string $nas, bool $requireAuthenticator): string
    {
        // Every value is validated before it gets here; the helper re-validates the file.
        return "client $name {\n"
            . "\tipaddr = $address\n"
            . "\tsecret = \"$secret\"\n"
            . "\tshortname = $name\n"
            . "\tnastype = $nas\n"
            . "\trequire_message_authenticator = " . ($requireAuthenticator ? 'yes' : 'no') . "\n"
            . "}\n\n";
    }

    private static function public(array $client): array
    {
        unset($client['secret']);
        return $client;
    }
}
