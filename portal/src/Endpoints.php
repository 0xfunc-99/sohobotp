<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Managed endpoints (Windows and Linux machines running the SohobOTP agent), endpoint
 * groups (shared policy), enrolment tokens, and the agent side of the protocol in
 * docs/agent-protocol.md.
 *
 * Storage (portal data folder):
 *   endpoints.json        { groups: {id: group}, tokens: {id: token}, signing_key: sealed seed }
 *   endpoints/<id>.json   one file per endpoint (check-ins only lock their own file)
 *
 * Security:
 * - the portal signs every configuration with its Ed25519 key (seed sealed with portal.key);
 *   agents pin the public key at install time;
 * - endpoints authenticate every request with their own Ed25519 key (portal keeps only the
 *   public key); time window and nonces stop replays;
 * - secrets inside a configuration are sealed to the endpoint's X25519 key;
 * - enrolment tokens are stored as SHA-256 hashes, expire and have a use limit.
 */
final class Endpoints
{
    public const OS = ['linux' => 'Linux', 'windows' => 'Windows'];
    public const LINUX_SERVICES = ['sshd' => 'SSH', 'sudo' => 'sudo', 'login' => 'Console login', 'su' => 'su'];
    public const CP_MODES = ['0' => 'Local and remote desktop', '1' => 'Remote desktop only', '2' => 'Local only', '3' => 'Off'];
    public const DEFAULT_POLICY = [
        'checkin_interval' => 60,
        'agent_version' => '', // self-update target ('' = no automatic update)
        'linux' => [
            'enabled'          => true,
            'radius_group_id'  => '',
            'radius_servers'   => '',
            'timeout'          => 5,
            'services'         => ['sshd', 'sudo'],
            'excluded_users'   => '',
            'excluded_groups'  => 'mfa-breakglass',
            'ssh_keys_need_code' => true,
            'require_message_authenticator' => false,
        ],
        'windows' => [
            'cpus_logon'       => '0e',
            'cpus_unlock'      => '0e',
            'cpus_credui'      => '0e',
            'excluded_account' => '',
            'cache_enabled'    => false,
            'cache_days'       => 7,
            'upn_format'       => false,
            'default_prefix'   => '',
            'timeout_unlock'   => 0,
            'without2fa'       => false,
            'two_step_hide_otp'      => false,
            'two_step_send_password' => false,
            'login_text'       => 'SohobOTP',
            'otp_text'         => '',
            'server_timeout'   => 5,
        ],
    ];
    public const APPROVAL = [
        'none'      => 'Active immediately',
        'manual'    => 'An administrator approves each machine',
        'directory' => 'Approved automatically when the computer is in Active Directory (else an administrator approves)',
    ];
    public const RULE_TYPES = ['ou' => 'Computer is in OU (or below)', 'group' => 'Computer is member of AD group (nested included)'];
    /** How often the worker re-reads computer accounts when rules or AD approvals exist. */
    public const DIRECTORY_CHECK_SECONDS = 900;
    public const TIME_WINDOW = 300;
    public const NONCE_TTL = 600;
    public const MAX_BODY = 262144;
    private const ID = '/^[0-9a-f]{20}$/';

    private JsonStore $store;

    public function __construct(?JsonStore $store = null)
    {
        $this->store = $store ?? new JsonStore(Config::dataDir() . '/endpoints.json');
    }

    // ------------------------------------------------------------------
    // Portal signing key
    // ------------------------------------------------------------------

    /** Ed25519 key pair (libsodium format); the seed is created once and sealed with portal.key. */
    public function signingKeypair(): string
    {
        $sealed = $this->store->read()['signing_key'] ?? null;
        if (null === $sealed) {
            $sealed = $this->store->update(static function (array &$data): string {
                return $data['signing_key'] ??= Crypto::encrypt(random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES));
            });
        }
        return sodium_crypto_sign_seed_keypair(Crypto::decrypt($sealed));
    }

    public function publicKey(): string
    {
        return sodium_crypto_sign_publickey($this->signingKeypair());
    }

    /** Pin given to the agent at install: SHA-256 (hex) of the public key. */
    public function pin(): string
    {
        return hash('sha256', $this->publicKey());
    }

    // ------------------------------------------------------------------
    // Endpoint groups
    // ------------------------------------------------------------------

    /** @return list<array> sorted by name, each with "endpoints" (count) */
    public function groups(): array
    {
        $counts = array_count_values(array_column($this->endpoints(), 'group_id'));
        $groups = array_values($this->store->read()['groups'] ?? []);
        foreach ($groups as &$group) {
            $group['endpoints'] = $counts[$group['id']] ?? 0;
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
                    throw new ValidationException('An endpoint group with this name already exists.');
                }
            }
            if (null !== $id && !isset($data['groups'][$id])) {
                throw new ValidationException('This endpoint group no longer exists.');
            }
            $now = time();
            $group = null === $id ? ['id' => bin2hex(random_bytes(6)), 'created_at' => $now] : $data['groups'][$id];
            $group['name'] = $name;
            $group['description'] = trim(mb_substr((string) ($input['description'] ?? ''), 0, 255));
            $group['policy'] = $policy;
            $group['updated_at'] = $now;
            $data['groups'][$group['id']] = $group;
            return $group;
        });
        $this->syncRadiusClients(fn (array $e): bool => $e['group_id'] === $group['id']);
        return $group;
    }

    public function deleteGroup(string $id): array
    {
        foreach ($this->endpoints() as $endpoint) {
            if ($endpoint['group_id'] === $id) {
                throw new ValidationException('Move or delete the endpoints in this group first.');
            }
        }
        return $this->store->update(static function (array &$data) use ($id): array {
            $group = $data['groups'][$id] ?? throw new ValidationException('This endpoint group does not exist.');
            foreach ($data['tokens'] ?? [] as $token) {
                if ($token['group_id'] === $id && self::tokenUsable($token)) {
                    throw new ValidationException('Revoke the enrolment tokens of this group first.');
                }
            }
            foreach ($data['rules'] ?? [] as $rule) {
                if ($rule['group_id'] === $id) {
                    throw new ValidationException('Delete the Active Directory rules that assign machines to this group first.');
                }
            }
            unset($data['groups'][$id]);
            return $group;
        });
    }

    public static function policyFromInput(array $input): array
    {
        $d = self::DEFAULT_POLICY;
        $flag = static fn (string $key): bool => !empty($input[$key]);
        $int = static function (string $key, int $min, int $max, string $label) use ($input): int {
            $value = trim((string) ($input[$key] ?? ''));
            if (!ctype_digit($value) || (int) $value < $min || (int) $value > $max) {
                throw new ValidationException("$label must be a number from $min to $max.");
            }
            return (int) $value;
        };
        $text = static fn (string $key, int $max): string => trim(mb_substr(str_replace(["\r", "\n", "\0"], ' ', (string) ($input[$key] ?? '')), 0, $max));
        $names = static function (string $key, string $label) use ($input): string {
            $list = preg_split('/[\s,;]+/', trim((string) ($input[$key] ?? '')), -1, PREG_SPLIT_NO_EMPTY);
            foreach ($list as $name) {
                if (!preg_match('/^[a-z_][a-z0-9_.-]{0,31}\$?$/i', $name)) {
                    throw new ValidationException("$label: \"$name\" is not a valid Linux user or group name.");
                }
            }
            return implode(', ', array_unique($list));
        };

        $linuxServices = array_values(array_intersect(array_keys(self::LINUX_SERVICES), (array) ($input['linux_services'] ?? [])));
        $servers = [];
        foreach (preg_split('/[\s,;]+/', trim((string) ($input['linux_radius_servers'] ?? '')), -1, PREG_SPLIT_NO_EMPTY) as $server) {
            if (null === self::parseServer($server)) {
                throw new ValidationException("RADIUS server \"$server\" is not a host name or IP address (optionally :port).");
            }
            $servers[] = $server;
        }
        $radiusGroup = trim((string) ($input['linux_radius_group_id'] ?? ''));
        $linuxEnabled = $flag('linux_enabled');
        if ($linuxEnabled && (null === (new Radius())->group($radiusGroup))) {
            throw new ValidationException('Choose the RADIUS server group that Linux endpoints of this group join (create one under RADIUS servers first).');
        }
        if ($linuxEnabled && [] === $linuxServices) {
            throw new ValidationException('Choose at least one Linux service to protect, or turn Linux 2FA off.');
        }
        $mode = static function (string $key) use ($input): string {
            $value = (string) ($input[$key] ?? '');
            if (!preg_match('/^[0-3][ed]$/', $value)) {
                throw new ValidationException('Invalid Windows sign-in mode.');
            }
            return $value;
        };
        $agentVersion = trim((string) ($input['agent_version'] ?? ''));
        if ('' !== $agentVersion && (!AgentReleases::validVersion($agentVersion) || !in_array($agentVersion, AgentReleases::versions(), true))) {
            throw new ValidationException('Choose an agent version that has been added as a release (portal-admin.php agent-release-add).');
        }
        $excludedAccount = $text('win_excluded_account', 128);
        if ('' !== $excludedAccount && !preg_match('/^[^\\\\\/:*?"<>|]{1,64}\\\\[^\\\\\/:*?"<>|@]{1,64}$/', $excludedAccount)) {
            throw new ValidationException('The excluded Windows account must look like DOMAIN\\user or COMPUTER\\user.');
        }

        return [
            'checkin_interval' => $int('checkin_interval', 30, 3600, 'Check-in interval'),
            'agent_version' => $agentVersion,
            'linux' => [
                'enabled'          => $linuxEnabled,
                'radius_group_id'  => $linuxEnabled ? $radiusGroup : ('' !== $radiusGroup && null !== (new Radius())->group($radiusGroup) ? $radiusGroup : ''),
                'radius_servers'   => implode(', ', $servers),
                'timeout'          => $int('linux_timeout', 1, 60, 'RADIUS timeout'),
                'services'         => $linuxServices,
                'excluded_users'   => $names('linux_excluded_users', 'Excluded users'),
                'excluded_groups'  => $names('linux_excluded_groups', 'Excluded groups'),
                'ssh_keys_need_code' => $flag('linux_ssh_keys_need_code'),
                'require_message_authenticator' => $flag('linux_require_message_authenticator'),
            ],
            'windows' => [
                'cpus_logon'       => $mode('win_cpus_logon'),
                'cpus_unlock'      => $mode('win_cpus_unlock'),
                'cpus_credui'      => $mode('win_cpus_credui'),
                'excluded_account' => $excludedAccount,
                'cache_enabled'    => $flag('win_cache_enabled'),
                'cache_days'       => $int('win_cache_days', 1, 30, 'Offline cache lifetime'),
                'upn_format'       => $flag('win_upn_format'),
                'default_prefix'   => $text('win_default_prefix', 64),
                'timeout_unlock'   => $int('win_timeout_unlock', 0, 1440, 'Unlock grace period'),
                'without2fa'       => $flag('win_without2fa'),
                'two_step_hide_otp'      => $flag('win_two_step_hide_otp'),
                'two_step_send_password' => $flag('win_two_step_send_password'),
                'login_text'       => $text('win_login_text', 100),
                'otp_text'         => $text('win_otp_text', 100),
                'server_timeout'   => $int('win_server_timeout', 1, 60, 'Server timeout'),
            ],
        ] + $d;
    }

    /**
     * A saved policy completed with defaults. Each OS section is merged key by key, never
     * recursively: a saved list (e.g. services ["sshd"]) replaces the default list entirely.
     */
    public static function effectivePolicy(array $policy): array
    {
        $d = self::DEFAULT_POLICY;
        return [
            'checkin_interval' => $policy['checkin_interval'] ?? $d['checkin_interval'],
            'agent_version' => (string) ($policy['agent_version'] ?? ''),
            'linux' => array_replace($d['linux'], (array) ($policy['linux'] ?? [])),
            'windows' => array_replace($d['windows'], (array) ($policy['windows'] ?? [])),
        ];
    }

    /** Flat form values for a policy (inverse of policyFromInput). */
    public static function policyToInput(array $policy): array
    {
        $policy = self::effectivePolicy($policy);
        $input = ['checkin_interval' => $policy['checkin_interval'], 'agent_version' => $policy['agent_version']];
        foreach ($policy['linux'] as $key => $value) {
            $input['linux_' . $key] = $value;
        }
        foreach ($policy['windows'] as $key => $value) {
            $input['win_' . $key] = $value;
        }
        return $input;
    }

    // ------------------------------------------------------------------
    // Enrolment tokens
    // ------------------------------------------------------------------

    /** @return list<array> newest first, without hashes */
    public function tokens(): array
    {
        $tokens = array_values(array_map(static function (array $t): array {
            unset($t['hash']);
            $t['usable'] = self::tokenUsable($t);
            return $t;
        }, $this->store->read()['tokens'] ?? []));
        usort($tokens, static fn (array $a, array $b): int => $b['created_at'] <=> $a['created_at']);
        return $tokens;
    }

    /** @return array{0: array, 1: string} the token record and the token itself (show once) */
    public function createToken(string $groupId, string $label, int $hours, int $maxUses, string $createdBy, string $approval = 'none'): array
    {
        if (!isset(self::APPROVAL[$approval])) {
            throw new ValidationException('Unknown approval mode.');
        }
        if (null === $this->group($groupId)) {
            throw new ValidationException('Choose an endpoint group.');
        }
        if ($hours < 1 || $hours > 720) {
            throw new ValidationException('Validity must be 1 to 720 hours.');
        }
        if ($maxUses < 1 || $maxUses > 10000) {
            throw new ValidationException('Maximum uses must be 1 to 10000.');
        }
        $label = trim(mb_substr(str_replace(["\r", "\n"], ' ', $label), 0, 100));
        $id = bin2hex(random_bytes(6));
        $secret = rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '=');
        $now = time();
        $record = [
            'id' => $id, 'hash' => hash('sha256', $secret), 'group_id' => $groupId, 'label' => $label,
            'created_by' => $createdBy, 'created_at' => $now, 'expires_at' => $now + 3600 * $hours,
            'max_uses' => $maxUses, 'uses' => 0, 'revoked' => false, 'approval' => $approval,
        ];
        $this->store->update(static function (array &$data) use ($record): void {
            foreach ($data['tokens'] ?? [] as $key => $token) {
                // keep the list short: drop tokens that ended more than 30 days ago
                if (!self::tokenUsable($token) && max($token['expires_at'], $token['revoked_at'] ?? 0) < time() - 30 * 86400) {
                    unset($data['tokens'][$key]);
                }
            }
            $data['tokens'][$record['id']] = $record;
        });
        unset($record['hash']);
        return [$record, "$id.$secret"];
    }

    public function revokeToken(string $id): array
    {
        return $this->store->update(static function (array &$data) use ($id): array {
            $token = $data['tokens'][$id] ?? throw new ValidationException('This enrolment token does not exist.');
            $token['revoked'] = true;
            $token['revoked_at'] = time();
            $data['tokens'][$id] = $token;
            unset($token['hash']);
            return $token;
        });
    }

    private static function tokenUsable(array $token): bool
    {
        return !$token['revoked'] && $token['expires_at'] > time() && $token['uses'] < $token['max_uses'];
    }

    // ------------------------------------------------------------------
    // Endpoints
    // ------------------------------------------------------------------

    public static function dir(): string
    {
        $dir = Config::ensureDataDir() . '/endpoints';
        if (!is_dir($dir) && !@mkdir($dir, 0700) && !is_dir($dir)) {
            throw new \RuntimeException('Cannot create the endpoints folder.');
        }
        return $dir;
    }

    private static function endpointStore(string $id): JsonStore
    {
        if (!preg_match(self::ID, $id)) {
            throw new \InvalidArgumentException('Invalid endpoint id.');
        }
        return new JsonStore(self::dir() . "/$id.json");
    }

    /** @return list<array> public records sorted by host name */
    public function endpoints(): array
    {
        $list = [];
        foreach (glob(self::dir() . '/*.json') ?: [] as $file) {
            $id = basename($file, '.json');
            if (preg_match(self::ID, $id)) {
                $record = self::endpointStore($id)->read();
                if ([] !== $record) {
                    $list[] = self::public($record);
                }
            }
        }
        usort($list, static fn (array $a, array $b): int => strcasecmp($a['inventory']['hostname'] ?? '', $b['inventory']['hostname'] ?? ''));
        return $list;
    }

    public function endpoint(string $id): ?array
    {
        if (!preg_match(self::ID, $id) || !is_file(self::dir() . "/$id.json")) {
            return null;
        }
        $record = self::endpointStore($id)->read();
        return [] === $record ? null : self::public($record);
    }

    /** online | offline | never | disabled */
    public function health(array $endpoint): string
    {
        if ('disabled' === $endpoint['status']) {
            return 'disabled';
        }
        if ('pending' === $endpoint['status']) {
            return 'pending';
        }
        if (null === ($endpoint['last_seen'] ?? null)) {
            return 'never';
        }
        $interval = (int) ($this->group($endpoint['group_id'])['policy']['checkin_interval'] ?? 60);
        return $endpoint['last_seen'] >= time() - 3 * $interval ? 'online' : 'offline';
    }

    public function setStatus(string $id, bool $active): array
    {
        $endpoint = self::endpointStore($id)->update(static function (array &$data) use ($active): array {
            if ([] === $data) {
                throw new ValidationException('This endpoint does not exist.');
            }
            $data['status'] = $active ? 'active' : 'disabled';
            if (!$active) {
                // a revoked machine must not keep a usable Credential Provider secret
                $data['cp_secret'] = Crypto::encrypt(bin2hex(random_bytes(24)));
            }
            return $data;
        });
        $this->syncRadiusClients(fn (array $e): bool => $e['id'] === $id);
        return self::public($endpoint);
    }

    public function moveEndpoint(string $id, string $groupId): array
    {
        if (null === $this->group($groupId)) {
            throw new ValidationException('Choose an endpoint group.');
        }
        $endpoint = self::endpointStore($id)->update(static function (array &$data) use ($groupId): array {
            if ([] === $data) {
                throw new ValidationException('This endpoint does not exist.');
            }
            $data['group_id'] = $groupId;
            $data['assigned_by'] = 'admin';
            $data['group_locked'] = true; // AD rules no longer move this machine
            return $data;
        });
        $this->syncRadiusClients(fn (array $e): bool => $e['id'] === $id);
        return self::public($endpoint);
    }

    /** Let the Active Directory rules choose the group again. */
    public function unlockGroup(string $id): void
    {
        self::endpointStore($id)->update(static function (array &$data): void {
            if ([] === $data) {
                throw new ValidationException('This endpoint does not exist.');
            }
            $data['group_locked'] = false;
        });
    }

    public function approve(string $id): array
    {
        $endpoint = self::endpointStore($id)->update(static function (array &$data): array {
            if ([] === $data || 'pending' !== $data['status']) {
                throw new ValidationException('This endpoint is not waiting for approval.');
            }
            $data['status'] = 'active';
            $data['approved_at'] = time();
            $data['approval_note'] = '';
            return $data;
        });
        $this->syncRadiusClients(fn (array $e): bool => $e['id'] === $id);
        return self::public($endpoint);
    }

    // ------------------------------------------------------------------
    // Active Directory: assignment rules and computer checks
    // ------------------------------------------------------------------

    /** @return list<array> rules in evaluation order (first match wins) */
    public function rules(): array
    {
        return array_values($this->store->read()['rules'] ?? []);
    }

    public function addRule(string $type, string $value, string $groupId): array
    {
        $value = trim(preg_replace('/\s*,\s*/', ',', $value) ?? '');
        if (!isset(self::RULE_TYPES[$type])) {
            throw new ValidationException('Unknown rule type.');
        }
        if ('ou' === $type && !preg_match('/^(OU|CN)=[^,]+(,(OU|CN|DC)=[^,]+)*,DC=[^,]+$/i', $value)) {
            throw new ValidationException('Enter the OU as a distinguished name, e.g. OU=Laptops,OU=Paris,DC=example,DC=com.');
        }
        if ('group' === $type && !preg_match('/^[^"\/\\\[\]:;|=,+*?<>]{1,64}$/', $value)) {
            throw new ValidationException('Enter the AD group name (sAMAccountName), e.g. MFA-Servers.');
        }
        if (null === $this->group($groupId)) {
            throw new ValidationException('Choose an endpoint group.');
        }
        return $this->store->update(static function (array &$data) use ($type, $value, $groupId): array {
            $rule = ['id' => bin2hex(random_bytes(6)), 'type' => $type, 'value' => $value, 'group_id' => $groupId, 'created_at' => time()];
            $data['rules'] = array_values($data['rules'] ?? []);
            $data['rules'][] = $rule;
            return $rule;
        });
    }

    public function deleteRule(string $id): array
    {
        return $this->store->update(static function (array &$data) use ($id): array {
            foreach ($data['rules'] ?? [] as $i => $rule) {
                if ($rule['id'] === $id) {
                    unset($data['rules'][$i]);
                    $data['rules'] = array_values($data['rules']);
                    return $rule;
                }
            }
            throw new ValidationException('This rule does not exist.');
        });
    }

    public function moveRule(string $id, int $direction): void
    {
        $this->store->update(static function (array &$data) use ($id, $direction): void {
            $rules = array_values($data['rules'] ?? []);
            foreach ($rules as $i => $rule) {
                $j = $i + ($direction < 0 ? -1 : 1);
                if ($rule['id'] === $id && isset($rules[$j])) {
                    [$rules[$i], $rules[$j]] = [$rules[$j], $rules[$i]];
                    break;
                }
            }
            $data['rules'] = $rules;
        });
    }

    /** First rule matching a computer account, or null. */
    public static function matchRule(array $rules, array $computer): ?array
    {
        $dn = strtolower(preg_replace('/\s*,\s*/', ',', $computer['dn']) ?? '');
        $groups = array_map('strtolower', $computer['groups']);
        foreach ($rules as $rule) {
            $value = strtolower($rule['value']);
            if (('ou' === $rule['type'] && str_ends_with($dn, ',' . $value))
                || ('group' === $rule['type'] && in_array($value, $groups, true))) {
                return $rule;
            }
        }
        return null;
    }

    /** Whether the worker should re-check computer accounts now. */
    public function isDirectoryCheckDue(int $now): bool
    {
        $data = $this->store->read();
        $hasRules = [] !== ($data['rules'] ?? []);
        $needed = $hasRules;
        foreach ($this->endpoints() as $endpoint) {
            $waiting = 'pending' === $endpoint['status'] && 'directory' === ($endpoint['approval'] ?? '');
            // enrolled after the last check started (a failed check does not loop: its start time counts)
            $unchecked = 'disabled' !== $endpoint['status'] && null === ($endpoint['directory'] ?? null)
                && ($data['directory_check_at'] ?? 0) <= $endpoint['enrolled_at'];
            if (($waiting || $hasRules) && $unchecked) {
                return true; // a machine enrolled since the last check: do not wait for the interval
            }
            $needed = $needed || $waiting;
        }
        return $needed && ($data['directory_check_at'] ?? 0) + self::DIRECTORY_CHECK_SECONDS <= $now;
    }

    /**
     * Read the computer accounts of the endpoints (all, or one), then:
     * - approve pending machines enrolled with an "Active Directory" token when the computer
     *   account exists, is enabled, its DNS name resolves to the enrolment address and no
     *   other active endpoint already uses it;
     * - move machines to the group of the first matching rule (unless an administrator
     *   placed them by hand).
     * Runs in the worker. $resolver(host) returns the host's IP addresses (tests replace it).
     */
    public function checkDirectory(?string $onlyId = null, ?callable $resolver = null): array
    {
        $resolver ??= static function (string $host): array {
            $ips = [];
            foreach (@dns_get_record($host, DNS_A | DNS_AAAA) ?: [] as $record) {
                $ips[] = $record['ip'] ?? $record['ipv6'] ?? '';
            }
            return [] !== array_filter($ips) ? $ips : (@gethostbynamel($host) ?: []);
        };
        $all = $this->endpoints();
        // The computer name is bound at the first match: a machine that later reports another
        // host name keeps its computer account (and cannot switch to someone else's).
        $nameOf = static fn (array $e): string => '' !== ($e['ad_name'] ?? '') ? $e['ad_name'] : $e['inventory']['hostname'];
        $targets = array_values(array_filter($all, static fn (array $e): bool => 'disabled' !== $e['status']
            && '' !== $nameOf($e) && (null === $onlyId || $e['id'] === $onlyId)));
        $this->store->update(static function (array &$data): void {
            $data['directory_check_at'] = time();
        });
        $summary = ['checked' => count($targets), 'found' => 0, 'not_found' => [], 'approved' => [], 'moved' => []];
        if ([] === $targets) {
            return $summary;
        }
        try {
            $computers = (new Directory())->computers(array_map($nameOf, $targets));
        } catch (ValidationException $error) {
            // remember the attempt, so machines wait for the next interval instead of re-queuing
            foreach ($targets as $endpoint) {
                self::endpointStore($endpoint['id'])->update(static function (array &$data) use ($error): void {
                    if ([] !== $data && null === ($data['directory'] ?? null)) {
                        $data['directory'] = ['found' => false, 'error' => $error->getMessage(), 'checked_at' => time()];
                    }
                });
            }
            throw $error;
        }
        $rules = $this->rules();
        $changed = [];
        $claimed = []; // computer DNs approved in this run: never two endpoints for one computer
        foreach ($targets as $endpoint) {
            $name = $nameOf($endpoint);
            $computer = $computers[strtolower($name)] ?? null;
            $note = '';
            $approve = false;
            if (null === $computer) {
                $summary['not_found'][] = $name;
                $note = 'No computer account named ' . strtoupper(substr(explode('.', $name)[0], 0, 15)) . ' in Active Directory.';
            } else {
                $summary['found']++;
                if ('pending' === $endpoint['status'] && 'directory' === ($endpoint['approval'] ?? '')) {
                    $duplicate = false;
                    foreach ($all as $other) {
                        if ($other['id'] !== $endpoint['id'] && 'active' === $other['status'] && 0 === strcasecmp($other['directory']['dn'] ?? '', $computer['dn'])) {
                            $duplicate = true;
                        }
                    }
                    $resolved = '' !== $computer['dns_host'] ? $resolver($computer['dns_host']) : [];
                    $duplicate = $duplicate || isset($claimed[strtolower($computer['dn'])]);
                    if (!$computer['enabled']) {
                        $note = 'The computer account is disabled in Active Directory.';
                    } elseif ($duplicate) {
                        $note = 'Another active endpoint already uses this computer account (re-installed machine?).';
                    } elseif (!in_array($endpoint['enrolled_ip'], $resolved, true)) {
                        $note = 'The computer\'s DNS name (' . ($computer['dns_host'] ?: 'none') . ') does not resolve to the enrolment address ' . $endpoint['enrolled_ip'] . '.';
                    } else {
                        $approve = true;
                        $claimed[strtolower($computer['dn'])] = true;
                    }
                }
            }
            $target = null;
            if (null !== $computer && !($endpoint['group_locked'] ?? false)) {
                $rule = self::matchRule($rules, $computer);
                if (null !== $rule && $rule['group_id'] !== $endpoint['group_id'] && null !== $this->group($rule['group_id'])) {
                    $target = $rule;
                }
            }
            self::endpointStore($endpoint['id'])->update(static function (array &$data) use ($computer, $note, $approve, $target, $name): void {
                if ([] === $data) {
                    return;
                }
                if (null !== $computer && '' === ($data['ad_name'] ?? '')) {
                    $data['ad_name'] = strtolower($name);
                }
                $data['directory'] = null === $computer ? ['found' => false, 'checked_at' => time()] : ['found' => true, 'checked_at' => time()] + $computer;
                $data['approval_note'] = 'pending' === $data['status'] && !$approve ? $note : '';
                if ($approve && 'pending' === $data['status']) {
                    $data['status'] = 'active';
                    $data['approved_at'] = time();
                }
                if (null !== $target) {
                    $data['group_id'] = $target['group_id'];
                    $data['assigned_by'] = 'rule:' . $target['id'];
                }
            });
            if ($approve) {
                $summary['approved'][] = $endpoint['id'];
                $changed[$endpoint['id']] = true;
            }
            if (null !== $target) {
                $summary['moved'][] = ['endpoint' => $endpoint['id'], 'from' => $endpoint['group_id'], 'to' => $target['group_id'], 'rule' => $target['id']];
                $changed[$endpoint['id']] = true;
            }
        }
        if ([] !== $changed) {
            $this->syncRadiusClients(static fn (array $e): bool => isset($changed[$e['id']]));
        }
        return $summary;
    }

    public function deleteEndpoint(string $id): array
    {
        $endpoint = $this->endpoint($id) ?? throw new ValidationException('This endpoint does not exist.');
        @unlink(self::dir() . "/$id.json");
        @unlink(self::dir() . "/$id.json.lock");
        if ('' !== ($endpoint['radius_client_id'] ?? '')) {
            $this->removeRadiusClient($endpoint);
            $this->retryRadiusErrors();
        }
        return $endpoint;
    }

    // ------------------------------------------------------------------
    // RADIUS clients for Linux endpoints
    // ------------------------------------------------------------------

    /**
     * Make the RADIUS clients match the endpoints selected by $filter: an active Linux
     * endpoint whose group has Linux 2FA on gets a client (its enrolment address, its own
     * secret) in the group's RADIUS server group; any other gets none. Queues a FreeRADIUS
     * apply when something changed.
     */
    public function syncRadiusClients(callable $filter): void
    {
        $changed = false;
        $freed = false;
        foreach ($this->endpoints() as $endpoint) {
            if (!$filter($endpoint) || 'linux' !== $endpoint['os']) {
                continue;
            }
            $linux = $this->group($endpoint['group_id'])['policy']['linux'] ?? null;
            $wanted = 'active' === $endpoint['status'] && null !== $linux && $linux['enabled'];
            $radius = new Radius();
            $client = '' !== ($endpoint['radius_client_id'] ?? '') ? $radius->client($endpoint['radius_client_id']) : null;
            $error = '';
            if ($wanted) {
                $input = [
                    'name' => 'ep-' . substr($endpoint['id'], 0, 12),
                    'description' => 'Endpoint ' . ($endpoint['inventory']['hostname'] ?? $endpoint['id']) . ' (managed by the agent)',
                    'address' => $endpoint['enrolled_ip'],
                    'group_id' => $linux['radius_group_id'],
                    'nas_type' => 'other',
                    'require_message_authenticator' => $linux['require_message_authenticator'],
                ];
                try {
                    if (null === $client) {
                        [$client] = $radius->createClient($input);
                        $changed = true;
                    } elseif ($client['group_id'] !== $input['group_id'] || $client['require_message_authenticator'] !== $input['require_message_authenticator']) {
                        $client = $radius->updateClient($client['id'], $input + ['secret' => '']);
                        $changed = true;
                    }
                } catch (ValidationException $invalid) {
                    $error = 'RADIUS client not created: ' . $invalid->getMessage();
                    $client = null;
                }
            } elseif (null !== $client) {
                $radius->deleteClient($client['id']);
                $client = null;
                $changed = $freed = true;
            }
            self::endpointStore($endpoint['id'])->update(static function (array &$data) use ($client, $error): void {
                if ([] !== $data) {
                    $data['radius_client_id'] = $client['id'] ?? '';
                    $data['radius_error'] = $error;
                }
            });
        }
        if ($changed) {
            Jobs::enqueue('radius.apply', [], 'endpoints');
        }
        if ($freed) {
            $this->retryRadiusErrors();
        }
    }

    /**
     * An address freed by a removed client (e.g. the old endpoint of a re-installed machine)
     * lets endpoints that are waiting for it get their client now.
     */
    private function retryRadiusErrors(): void
    {
        $waiting = static fn (array $e): bool => '' !== ($e['radius_error'] ?? '');
        foreach ($this->endpoints() as $endpoint) {
            if ($waiting($endpoint)) {
                $this->syncRadiusClients($waiting);
                return;
            }
        }
    }

    private function removeRadiusClient(array $endpoint): void
    {
        try {
            (new Radius())->deleteClient($endpoint['radius_client_id']);
            Jobs::enqueue('radius.apply', [], 'endpoints');
        } catch (ValidationException) {
            // already gone
        }
    }

    // ------------------------------------------------------------------
    // Agent protocol
    // ------------------------------------------------------------------

    /** a=enroll. $host is the portal host name the agent used (from its URL). */
    public function enroll(array $request, string $ip, string $host): array
    {
        $token = (string) ($request['token'] ?? '');
        $signKey = self::decodeKey($request['sign_key'] ?? null, SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES);
        $boxKey = self::decodeKey($request['box_key'] ?? null, SODIUM_CRYPTO_BOX_PUBLICKEYBYTES);
        $proof = base64_decode((string) ($request['proof'] ?? ''), true);
        $inventory = self::inventory($request['inventory'] ?? null);
        if (null === $signKey || null === $boxKey || false === $proof || SODIUM_CRYPTO_SIGN_BYTES !== strlen($proof) || '' === $inventory['os']) {
            throw new AgentError('bad_request', 400, 'Missing or malformed enrolment fields.');
        }
        if (!sodium_crypto_sign_verify_detached($proof, self::enrollMessage($token, $signKey, $boxKey), $signKey)) {
            throw new AgentError('bad_request', 400, 'The key possession proof is invalid.');
        }
        if (!preg_match('/^([0-9a-f]{12})\.([A-Za-z0-9_-]{32})$/', $token, $m)) {
            throw new AgentError('bad_token', 401, 'Invalid enrolment token.');
        }
        $groupId = $this->store->update(static function (array &$data) use ($m): array {
            $record = $data['tokens'][$m[1]] ?? null;
            if (null === $record || !hash_equals($record['hash'], hash('sha256', $m[2])) || !self::tokenUsable($record) || !isset($data['groups'][$record['group_id']])) {
                throw new AgentError('bad_token', 401, 'Invalid, expired or used-up enrolment token.');
            }
            $data['tokens'][$m[1]]['uses']++;
            return [$record['group_id'], $record['approval'] ?? 'none'];
        });
        [$groupId, $approval] = $groupId;

        $id = bin2hex(random_bytes(10));
        $now = time();
        $record = [
            'id' => $id, 'group_id' => $groupId, 'status' => 'none' === $approval ? 'active' : 'pending', 'os' => $inventory['os'],
            'approval' => $approval, 'approval_note' => '', 'assigned_by' => 'token', 'group_locked' => false, 'directory' => null,
            'sign_key' => base64_encode($signKey), 'box_key' => base64_encode($boxKey),
            'enrolled_at' => $now, 'enrolled_ip' => $ip, 'token_id' => $m[1], 'portal_host' => $host,
            'inventory' => $inventory, 'last_seen' => null, 'last_ip' => $ip,
            'applied' => ['version' => 0, 'status' => 'none', 'error' => '', 'at' => null],
            'config' => ['version' => 0, 'fingerprint' => '', 'at' => null, 'error' => ''],
            'cp_secret' => Crypto::encrypt(bin2hex(random_bytes(24))),
            'radius_client_id' => '', 'radius_error' => '', 'nonces' => [],
        ];
        self::endpointStore($id)->update(static function (array &$data) use ($record): void {
            $data = $record;
        });
        $this->syncRadiusClients(fn (array $e): bool => $e['id'] === $id);
        if ('directory' === $approval || [] !== $this->rules()) {
            Jobs::enqueue('endpoints.directory', [], 'agent-enrolment');
        }
        return [
            'endpoint_id' => $id,
            'portal_key' => base64_encode($this->publicKey()),
            'checkin_interval' => (int) $this->group($groupId)['policy']['checkin_interval'],
        ];
    }

    /**
     * Check the signature headers of a request. Returns the endpoint id.
     * $headers: lower-case names. $uri: path + query exactly as received.
     */
    public function authenticate(array $headers, string $method, string $uri, string $body): string
    {
        $id = (string) ($headers['x-agent-id'] ?? '');
        $time = (string) ($headers['x-agent-time'] ?? '');
        $nonce = (string) ($headers['x-agent-nonce'] ?? '');
        $signature = base64_decode((string) ($headers['x-agent-signature'] ?? ''), true);
        $rawNonce = base64_decode($nonce, true);
        if (!preg_match(self::ID, $id) || !ctype_digit($time) || false === $rawNonce || 16 !== strlen($rawNonce) || false === $signature || SODIUM_CRYPTO_SIGN_BYTES !== strlen($signature)) {
            throw new AgentError('bad_request', 400, 'Missing or malformed signature headers.');
        }
        $endpoint = $this->endpoint($id) ?? throw new AgentError('unknown_endpoint', 401, 'Unknown endpoint.');
        if ('disabled' === $endpoint['status']) {
            throw new AgentError('disabled', 403, 'This endpoint has been disabled in the portal.');
        }
        if (abs(time() - (int) $time) > self::TIME_WINDOW) {
            throw new AgentError('clock_skew', 401, 'The endpoint clock differs from the portal by more than 5 minutes.');
        }
        $key = base64_decode(self::endpointStore($id)->read()['sign_key'], true);
        if (!sodium_crypto_sign_verify_detached($signature, self::requestMessage($method, $uri, $time, $nonce, $body), $key)) {
            throw new AgentError('bad_signature', 401, 'Invalid request signature.');
        }
        self::endpointStore($id)->update(static function (array &$data) use ($nonce): void {
            $now = time();
            $data['nonces'] = array_filter($data['nonces'] ?? [], static fn (int $seen): bool => $seen > $now - self::NONCE_TTL);
            if (isset($data['nonces'][$nonce])) {
                throw new AgentError('replay', 401, 'This request was already received.');
            }
            $data['nonces'][$nonce] = $now;
        });
        return $id;
    }

    /** a=checkin for an authenticated endpoint. */
    public function checkin(string $id, array $request, string $ip): array
    {
        $inventory = self::inventory($request['inventory'] ?? null);
        $applied = is_array($request['applied'] ?? null) ? $request['applied'] : [];
        $appliedVersion = is_int($applied['version'] ?? null) && $applied['version'] >= 0 ? $applied['version'] : 0;
        $appliedStatus = in_array($applied['status'] ?? '', ['applied', 'failed', 'none'], true) ? $applied['status'] : 'none';

        $endpoint = $this->endpoint($id) ?? throw new AgentError('unknown_endpoint', 401, 'Unknown endpoint.');
        $group = $this->group($endpoint['group_id']);
        if ('pending' === $endpoint['status']) {
            self::endpointStore($id)->update(static function (array &$data) use ($inventory, $ip): void {
                if ('' !== $inventory['os']) {
                    $inventory['os'] = $data['os'];
                    $data['inventory'] = $inventory;
                }
                $data['last_seen'] = time();
                $data['last_ip'] = $ip;
            });
            return ['checkin_interval' => (int) ($group['policy']['checkin_interval'] ?? 60), 'state' => 'pending', 'config' => null, 'update' => null];
        }
        [$policy, $secrets, $error] = $this->desired($endpoint, $group);
        $fingerprint = null === $policy ? '' : hash('sha256', json_encode([$endpoint['os'], $policy, $secrets], JSON_UNESCAPED_SLASHES));

        $record = self::endpointStore($id)->update(static function (array &$data) use ($inventory, $appliedVersion, $appliedStatus, $applied, $ip, $fingerprint, $error): array {
            $now = time();
            if ('' !== $inventory['os']) {
                $inventory['os'] = $data['os']; // the OS chosen at enrolment cannot change
                $data['inventory'] = $inventory;
            }
            $data['last_seen'] = $now;
            $data['last_ip'] = $ip;
            $data['applied'] = [
                'version' => $appliedVersion, 'status' => $appliedStatus,
                'error' => mb_substr(str_replace(["\r", "\n"], ' ', (string) ($applied['error'] ?? '')), 0, 500),
                'at' => is_int($applied['at'] ?? null) ? $applied['at'] : null,
            ];
            $config = $data['config'];
            $config['error'] = $error;
            if ('' !== $fingerprint && $fingerprint !== $config['fingerprint']) {
                $config = ['version' => max($config['version'], $appliedVersion) + 1, 'fingerprint' => $fingerprint, 'at' => $now, 'error' => ''];
            } elseif ($appliedVersion > $config['version']) {
                // e.g. the portal data was restored from an older backup: never go backwards
                $config['version'] = $appliedVersion + 1;
                $config['at'] = $now;
            }
            $data['config'] = $config;
            return $data;
        });

        $config = null;
        if (null !== $policy && $appliedVersion < $record['config']['version']) {
            $config = $this->envelope($record, $policy, $secrets);
        }
        return [
            'checkin_interval' => (int) ($group['policy']['checkin_interval'] ?? 60),
            'state' => 'active',
            'config' => $config,
            'update' => self::updateOffer($record, $group),
        ];
    }

    /**
     * A signed release to offer: the group has a target version, the machine reports an
     * older one, and a release exists for its OS and architecture. The agent verifies the
     * release signature itself (release key built in) and never downgrades.
     */
    private static function updateOffer(array $record, ?array $group): ?array
    {
        $target = (string) ($group['policy']['agent_version'] ?? '');
        $current = (string) ($record['inventory']['agent_version'] ?? '');
        if ('' === $target || !AgentReleases::validVersion($current) || version_compare($target, $current, '<=')) {
            return null;
        }
        $m = AgentReleases::find($target, $record['os'], (string) ($record['inventory']['arch'] ?? ''));
        return null === $m ? null : array_intersect_key($m, array_flip(['version', 'os', 'arch', 'sha256', 'size', 'signature']));
    }

    /** a=release: the binary of a release for an authenticated, active endpoint. */
    public function releaseFile(string $id, array $request): string
    {
        $endpoint = $this->endpoint($id) ?? throw new AgentError('unknown_endpoint', 401, 'Unknown endpoint.');
        if ('active' !== $endpoint['status']) {
            throw new AgentError('disabled', 403, 'This endpoint is not active.');
        }
        $version = (string) ($request['version'] ?? '');
        $m = AgentReleases::validVersion($version) ? AgentReleases::find($version, $endpoint['os'], (string) ($endpoint['inventory']['arch'] ?? '')) : null;
        if (null === $m || ($request['os'] ?? '') !== $m['os'] || ($request['arch'] ?? '') !== $m['arch']) {
            throw new AgentError('bad_request', 404, 'No such release for this machine.');
        }
        return AgentReleases::file($m);
    }

    /**
     * The configuration an endpoint should have: [policy, secrets in clear, error].
     * policy is null when it cannot be built (error says why).
     */
    private function desired(array $endpoint, ?array $group): array
    {
        if (null === $group) {
            return [null, [], 'The endpoint group no longer exists.'];
        }
        $p = self::effectivePolicy($group['policy']);
        $host = $endpoint['portal_host'];
        if ('linux' === $endpoint['os']) {
            $l = $p['linux'];
            if (!$l['enabled']) {
                return [['enabled' => false], [], ''];
            }
            $secret = '' !== ($endpoint['radius_client_id'] ?? '') ? (new Radius())->clientSecret($endpoint['radius_client_id']) : null;
            if (null === $secret) {
                return [null, [], '' !== ($endpoint['radius_error'] ?? '') ? $endpoint['radius_error'] : 'No RADIUS client for this endpoint yet.'];
            }
            $servers = [];
            $list = preg_split('/[\s,;]+/', $l['radius_servers'], -1, PREG_SPLIT_NO_EMPTY) ?: [preg_replace('/:\d+$/', '', $host)];
            foreach ($list as $server) {
                $parsed = self::parseServer($server);
                if (null !== $parsed) {
                    $servers[] = $parsed;
                }
            }
            $split = static fn (string $list): array => preg_split('/[\s,;]+/', $list, -1, PREG_SPLIT_NO_EMPTY);
            return [[
                'enabled' => true,
                'radius_servers' => $servers,
                'timeout' => $l['timeout'],
                'services' => array_values($l['services']),
                'excluded_users' => array_values(array_unique(array_merge(['root'], $split($l['excluded_users'])))),
                'excluded_groups' => $split($l['excluded_groups']),
                'ssh_keys_need_code' => $l['ssh_keys_need_code'],
            ], ['radius_secret' => $secret], ''];
        }
        $w = $p['windows'];
        return [[
            'server_url' => 'https://' . $host . '/portal/cp.php?e=' . $endpoint['id'],
            'server_timeout' => $w['server_timeout'],
            'cpus_logon' => $w['cpus_logon'],
            'cpus_unlock' => $w['cpus_unlock'],
            'cpus_credui' => $w['cpus_credui'],
            'excluded_account' => $w['excluded_account'],
            'cache_enabled' => $w['cache_enabled'],
            'upn_format' => $w['upn_format'],
            'default_prefix' => $w['default_prefix'],
            'timeout_unlock' => $w['timeout_unlock'],
            'without2fa' => $w['without2fa'],
            'two_step_hide_otp' => $w['two_step_hide_otp'],
            'two_step_send_password' => $w['two_step_send_password'],
            'login_text' => $w['login_text'],
            'otp_text' => $w['otp_text'],
        ], ['cp_shared_secret' => Crypto::decrypt($endpoint['cp_secret'] ?? self::endpointStore($endpoint['id'])->read()['cp_secret'])], ''];
    }

    /** The endpoint's Credential Provider secret in clear (CP gateway only). */
    public function cpSecret(string $id): string
    {
        return Crypto::decrypt((string) (self::endpointStore($id)->read()['cp_secret'] ?? ''));
    }

    /** Remember the last Credential Provider request (health), at most once a minute. */
    public function touchCp(string $id, string $ip): void
    {
        $record = self::endpointStore($id)->read();
        if (($record['cp_last_seen'] ?? 0) > time() - 60 && ($record['cp_last_ip'] ?? '') === $ip) {
            return;
        }
        self::endpointStore($id)->update(static function (array &$data) use ($ip): void {
            if ([] !== $data) {
                $data['cp_last_seen'] = time();
                $data['cp_last_ip'] = $ip;
            }
        });
    }

    /** Signed configuration envelope (docs/agent-protocol.md section 4). */
    private function envelope(array $record, array $policy, array $secrets): array
    {
        $box = base64_decode($record['box_key'], true);
        $sealed = [];
        foreach ($secrets as $name => $value) {
            $sealed[$name] = base64_encode(sodium_crypto_box_seal($value, $box));
        }
        $payload = json_encode([
            'endpoint_id' => $record['id'],
            'version' => $record['config']['version'],
            'issued_at' => time(),
            'os' => $record['os'],
            'policy' => $policy,
            'secrets' => (object) $sealed,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        return [
            'payload' => base64_encode($payload),
            'signature' => base64_encode(self::signConfig($payload, sodium_crypto_sign_secretkey($this->signingKeypair()))),
        ];
    }

    /** Bytes signed by the agent's enrolment proof (protocol section 1). */
    public static function enrollMessage(string $token, string $signKey, string $boxKey): string
    {
        return "multiotp-agent-enroll-v1\n$token\n" . base64_encode($signKey) . "\n" . base64_encode($boxKey);
    }

    /** Bytes signed for every agent request (protocol section 2). */
    public static function requestMessage(string $method, string $uri, string $time, string $nonce, string $body): string
    {
        return "multiotp-agent-v1\n$method\n$uri\n$time\n$nonce\n" . hash('sha256', $body);
    }

    public static function signConfig(string $payload, string $secretKey): string
    {
        return sodium_crypto_sign_detached("multiotp-config-v1\n" . $payload, $secretKey);
    }

    /** host, host:port, IPv4, [IPv6]:port or bare IPv6 → {host, port}; null if invalid. */
    public static function parseServer(string $server): ?array
    {
        $port = 1812;
        if (preg_match('/^\[([0-9a-fA-F:.]+)\](?::(\d{1,5}))?$/', $server, $m)) {
            $host = $m[1];
            $port = isset($m[2]) ? (int) $m[2] : $port;
            if (!filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                return null;
            }
        } elseif (filter_var($server, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $host = $server;
        } elseif (preg_match('/^([A-Za-z0-9.-]{1,253})(?::(\d{1,5}))?$/', $server, $m)) {
            $host = $m[1];
            $port = isset($m[2]) ? (int) $m[2] : $port;
            if (!filter_var($host, FILTER_VALIDATE_IP) && !filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
                return null;
            }
        } else {
            return null;
        }
        return $port >= 1 && $port <= 65535 ? ['host' => $host, 'port' => $port] : null;
    }

    private static function decodeKey(mixed $value, int $length): ?string
    {
        $raw = is_string($value) ? base64_decode($value, true) : false;
        return false !== $raw && $length === strlen($raw) ? $raw : null;
    }

    /** Inventory as reported by an agent, reduced to known fields and safe sizes. */
    public static function inventory(mixed $raw): array
    {
        $raw = is_array($raw) ? $raw : [];
        $text = static function (array $from, string $key): string {
            $value = $from[$key] ?? '';
            return is_scalar($value) ? trim(mb_substr(preg_replace('/[\x00-\x1f\x7f]/u', ' ', (string) $value) ?? '', 0, 255)) : '';
        };
        $ips = [];
        foreach (is_array($raw['ips'] ?? null) ? array_slice($raw['ips'], 0, 32) : [] as $ip) {
            if (is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP)) {
                $ips[] = $ip;
            }
        }
        $component = is_array($raw['component'] ?? null) ? $raw['component'] : [];
        return [
            'hostname' => $text($raw, 'hostname'),
            'os' => array_key_exists($text($raw, 'os'), self::OS) ? $text($raw, 'os') : '',
            'os_name' => $text($raw, 'os_name'),
            'os_version' => $text($raw, 'os_version'),
            'kernel' => $text($raw, 'kernel'),
            'arch' => $text($raw, 'arch'),
            'domain' => $text($raw, 'domain'),
            'ips' => $ips,
            'agent_version' => $text($raw, 'agent_version'),
            'component' => ['name' => $text($component, 'name'), 'version' => $text($component, 'version')],
        ];
    }

    private static function public(array $record): array
    {
        unset($record['cp_secret'], $record['nonces']);
        return $record;
    }
}
