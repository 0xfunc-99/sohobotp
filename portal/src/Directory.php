<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * AD/LDAP integration on top of the multiOTP engine.
 *
 * Settings live in the engine configuration (so the CLI, RADIUS and the engine
 * keep working), EXCEPT the service-account password: it is sealed in
 * <data>/directory.json with the portal key and only handed to the engine in
 * memory while a test, preview or sync runs. RADIUS logins never need it
 * (they bind as the user), so it is removed from the engine configuration,
 * where it was only obfuscated.
 */
final class Directory
{
    public const TYPES = [
        1 => 'Active Directory',
        2 => 'Generic LDAP (OpenLDAP, posixAccount users)',
        4 => 'eDirectory',
    ];

    /** Form field => [getter, setter, kind] */
    private const FIELDS = [
        'enabled'               => ['IsLdapActivated', 'SetLdapActivated', 'bool'],
        'domain_controllers'    => ['GetLdapDomainControllers', 'SetLdapDomainControllers', 'text'],
        'port'                  => ['GetLdapPort', 'SetLdapPort', 'text'],
        'ssl'                   => ['IsLdapSsl', 'SetLdapSsl', 'bool'],
        'base_dn'               => ['GetLdapBaseDn', 'SetLdapBaseDn', 'text'],
        'users_dn'              => ['GetLdapUsersDn', 'SetLdapUsersDn', 'text'],
        'bind_dn'               => ['GetLdapBindDn', 'SetLdapBindDn', 'text'],
        'account_suffix'        => ['GetLdapAccountSuffix', 'SetLdapAccountSuffix', 'text'],
        'in_groups'             => ['GetLdapInGroup', 'SetLdapInGroup', 'text'],
        'ldap_filter'           => ['GetLdapFilter', 'SetLdapFilter', 'text'],
        'recursive_groups'      => ['IsLdapRecursiveGroups', 'SetLdapRecursiveGroups', 'bool'],
        'without2fa_groups'     => ['GetLdapWithout2faInGroup', 'SetLdapWithout2faInGroup', 'text'],
        'opt_in_2fa'            => ['GetLdap2faOptIn', 'SetLdap2faOptIn', 'bool'],
        'cn_identifier'         => ['GetLdapCnIdentifier', 'SetLdapCnIdentifier', 'text'],
        'group_attribute'       => ['GetLdapGroupAttribute', 'SetLdapGroupAttribute', 'text'],
        'group_cn_identifier'   => ['GetLdapGroupCnIdentifier', 'SetLdapGroupCnIdentifier', 'text'],
        'synced_user_attribute' => ['GetLdapSyncedUserAttribute', 'SetLdapSyncedUserAttribute', 'text'],
        'language_attribute'    => ['GetLdapLanguageAttribute', 'SetLdapLanguageAttribute', 'text'],
        'default_algorithm'     => ['GetLdapDefaultAlgorithm', 'SetLdapDefaultAlgorithm', 'text'],
        'request_ldap_password' => ['GetDefaultRequestLdapPwd', 'SetDefaultRequestLdapPwd', 'bool'],
        'dont_auto_disable'     => ['GetLdapDontAutoDisable', 'SetLdapDontAutoDisable', 'bool'],
        'dont_auto_enable'      => ['GetLdapDontAutoEnable', 'SetLdapDontAutoEnable', 'bool'],
        'delete_retention_days' => ['GetSyncDeleteRetentionDays', 'SetSyncDeleteRetentionDays', 'int'],
        'network_timeout'       => ['GetLdapNetworkTimeout', 'SetLdapNetworkTimeout', 'int'],
        'tls_reqcert'           => ['GetLdapTlsReqcert', 'SetLdapTlsReqcert', 'text'],
    ];

    private JsonStore $store;

    public function __construct(?JsonStore $store = null)
    {
        $this->store = $store ?? new JsonStore(Config::dataDir() . '/directory.json');
    }

    // ------------------------------------------------------------------
    // Settings
    // ------------------------------------------------------------------

    public function settings(): array
    {
        $engine = MultiotpService::get();
        $engine->ReadConfigData();
        $values = ['server_type' => (int) $engine->GetLdapServerType()];
        foreach (self::FIELDS as $field => [$getter, , $kind]) {
            $value = $engine->$getter();
            $values[$field] = match ($kind) {
                'bool'  => (bool) (int) $value,
                'int'   => (int) $value,
                default => (string) $value,
            };
        }
        $state = $this->state();
        $values['has_password'] = !empty($state['bind_password']) || '' !== (string) $engine->GetLdapServerPassword();
        $values['schedule_enabled'] = (bool) ($state['schedule']['enabled'] ?? false);
        $values['schedule_minutes'] = (int) ($state['schedule']['minutes'] ?? 60);
        return $values;
    }

    /**
     * @param string|null $password new service-account password, null to keep the current one
     * @return array<string, array{from: mixed, to: mixed}> changed fields (password shown as "changed")
     */
    public function save(array $input, ?string $password): array
    {
        $before = $this->settings();
        $type = (int) ($input['server_type'] ?? 1);
        if (!isset(self::TYPES[$type])) {
            throw new ValidationException('Unknown directory type.');
        }
        foreach (['port', 'network_timeout', 'delete_retention_days', 'schedule_minutes'] as $numeric) {
            if (isset($input[$numeric]) && '' !== $input[$numeric] && !ctype_digit((string) $input[$numeric])) {
                throw new ValidationException('Port, timeout, retention and interval must be whole numbers.');
            }
        }
        if (!in_array((string) ($input['tls_reqcert'] ?? 'demand'), ['demand', 'never', 'auto'], true)) {
            throw new ValidationException('Unknown certificate check mode.');
        }
        if (!in_array((string) ($input['default_algorithm'] ?? 'totp'), ['totp', 'hotp', 'without2fa'], true)) {
            throw new ValidationException('Unknown default token type.');
        }
        $minutes = (int) ($input['schedule_minutes'] ?? 60);
        if (!empty($input['schedule_enabled']) && ($minutes < 5 || $minutes > 10080)) {
            throw new ValidationException('The sync interval must be between 5 minutes and 7 days.');
        }
        // The engine's group filtering only works with Active Directory; with generic LDAP
        // or eDirectory it crashes the sync (TypeError in GetLdapUsersInfoArray).
        if (1 !== $type && ('' !== trim((string) ($input['in_groups'] ?? '')) || '' !== trim((string) ($input['without2fa_groups'] ?? '')))) {
            throw new ValidationException('Group lists are only supported for Active Directory. For generic LDAP, limit the users with the LDAP filter, e.g. (&(objectClass=posixAccount)({cn_identifier}={username})(memberOf=cn=MFA,ou=groups,dc=example,dc=org)).');
        }
        if (!empty($input['enabled']) && ('' === trim((string) ($input['domain_controllers'] ?? '')) || '' === trim((string) ($input['base_dn'] ?? '')))) {
            throw new ValidationException('Domain controllers and base DN are required to enable the directory.');
        }

        $engine = MultiotpService::get();
        $engine->ReadConfigData();
        $legacyPassword = (string) $engine->GetLdapServerPassword();
        // The server type resets the attribute mapping, so it goes first
        $engine->SetLdapServerType($type);
        foreach (self::FIELDS as $field => [, $setter, $kind]) {
            $value = $input[$field] ?? null;
            $value = match ($kind) {
                'bool'  => !empty($value) ? 1 : 0,
                'int'   => (int) ($value ?? 0),
                default => trim((string) ($value ?? '')),
            };
            if ('' === $value && in_array($field, ['cn_identifier', 'group_attribute', 'group_cn_identifier'], true)) {
                continue; // keep the default of the directory type
            }
            $engine->$setter($value);
        }
        // Never keep the service password in the engine configuration
        $engine->SetLdapServerPassword('');
        if (!$engine->WriteConfigData()) {
            throw new \RuntimeException('The SohobOTP engine configuration could not be written.');
        }

        $this->store->update(static function (array &$state) use ($password, $legacyPassword, $input, $minutes): void {
            if (null !== $password && '' !== $password) {
                $state['bind_password'] = Crypto::encrypt($password);
            } elseif (empty($state['bind_password']) && '' !== $legacyPassword) {
                // One-time migration of a password stored by the legacy GUI or CLI
                $state['bind_password'] = Crypto::encrypt($legacyPassword);
            }
            $state['schedule'] = ['enabled' => !empty($input['schedule_enabled']), 'minutes' => $minutes];
        });

        $after = $this->settings();
        $changes = [];
        foreach ($after as $field => $value) {
            if ('has_password' !== $field && ($before[$field] ?? null) !== $value) {
                $changes[$field] = ['from' => $before[$field] ?? null, 'to' => $value];
            }
        }
        if (null !== $password && '' !== $password) {
            $changes['bind_password'] = 'changed';
        }
        return $changes;
    }

    public function state(): array
    {
        return $this->store->read();
    }

    public function updateState(callable $mutate): void
    {
        $this->store->update($mutate);
    }

    // ------------------------------------------------------------------
    // Operations (the engine gets the password in memory only)
    // ------------------------------------------------------------------

    /** Bind with the service account. Quick; runs in the web request. */
    public function testConnection(): array
    {
        $engine = $this->engineWithPassword();
        $capture = new EngineLog($engine);
        $ok = (bool) $engine->CheckLdapAuthentication();
        $engine->SetLdapServerPassword('');
        return [
            'ok'      => $ok,
            'message' => $ok
                ? 'Connected and authenticated with the service account.'
                : 'The connection or the service-account bind failed. Check the servers, port, SSL, bind DN and password.',
            'log'     => $capture->lines(),
        ];
    }

    /** What a sync would do, without changing anything. Runs in the worker. */
    public function preview(): array
    {
        $engine = $this->engineWithPassword();
        $capture = new EngineLog($engine);
        $remote = $engine->GetLdapUsersInfoArray();
        $error = (bool) $engine->IsLdapError();
        $engine->SetLdapServerPassword('');
        if ($error) {
            return ['ok' => false, 'error' => 'The directory could not be read.', 'log' => $capture->lines()];
        }
        $local = self::snapshot();
        $create = $update = $disable = $reenable = $orphans = [];
        $remoteAccounts = [];
        foreach ($remote as $entry) {
            $account = mb_strtolower((string) ($entry['user'] ?? ''));
            if ('' === $account) {
                continue;
            }
            $remoteAccounts[$account] = true;
            $disabledThere = !empty($entry['accountdisable']);
            $row = ['user' => $account, 'name' => (string) ($entry['displayname'] ?? ''), 'email' => (string) ($entry['mail'] ?? ''), 'groups' => (string) ($entry['groups'] ?? '')];
            if (!isset($local[$account])) {
                $create[] = $row + ['disabled_in_directory' => $disabledThere];
            } elseif ($disabledThere && $local[$account]['enabled'] && !$engine->IsLdapDontAutoDisable()) {
                $disable[] = $row;
            } elseif (!$disabledThere && !$local[$account]['enabled'] && $local[$account]['synchronized'] && !$engine->IsLdapDontAutoEnable()) {
                $reenable[] = $row;
            } else {
                $update[] = $row;
            }
        }
        foreach ($local as $account => $info) {
            if ($info['synchronized'] && !isset($remoteAccounts[$account])) {
                $orphans[] = ['user' => $account, 'name' => $info['name'], 'enabled' => $info['enabled']];
            }
        }
        return [
            'ok'          => true,
            'found'       => count($remoteAccounts),
            'create'      => $create,
            'update'      => $update,
            'disable'     => $disable,
            'reenable'    => $reenable,
            'missing'     => $orphans,
            'retention'   => (int) $engine->GetSyncDeleteRetentionDays(),
            'auto_disable'=> !$engine->IsLdapDontAutoDisable(),
            'log'         => $capture->lines(),
        ];
    }

    /** Run the engine's synchronisation and report what changed. Runs in the worker. */
    public function sync(): array
    {
        $before = self::snapshot();
        $engine = $this->engineWithPassword();
        $capture = new EngineLog($engine);
        // The engine treats a synced user as "no longer in the directory" only when its
        // synchronized_time (whole seconds) is older than this sync's start. A sync started in
        // the same second as the previous one would keep out-of-scope users enabled.
        $marker = Config::dataDir() . '/directory-last-sync';
        $last = is_file($marker) ? (int) @file_get_contents($marker) : 0;
        $until = microtime(true) + 2.0;
        while (time() <= $last && microtime(true) < $until) {
            usleep(100_000);
        }
        // Engine progress is written to its lock file every 2 seconds
        $ok = (bool) $engine->SyncLdapUsers('*', true, false, 2, true);
        @file_put_contents($marker, (string) time(), LOCK_EX);
        $error = (bool) $engine->IsLdapError();
        $engine->SetLdapServerPassword('');
        $log = $capture->lines();
        MultiotpService::reset();
        $after = self::snapshot();

        $created = $disabled = $enabled = $deleted = [];
        foreach ($after as $user => $info) {
            if (!isset($before[$user])) {
                $created[] = $user;
            } elseif ($before[$user]['enabled'] && !$info['enabled']) {
                $disabled[] = $user;
            } elseif (!$before[$user]['enabled'] && $info['enabled']) {
                $enabled[] = $user;
            }
        }
        foreach ($before as $user => $info) {
            if (!isset($after[$user])) {
                $deleted[] = $user;
            }
        }
        $alreadyRunning = (bool) preg_grep('/synchronization in progress/i', $log);
        return [
            'ok'              => $ok && !$error && !$alreadyRunning,
            'already_running' => $alreadyRunning,
            'created'         => $created,
            'disabled'        => $disabled,
            'enabled'         => $enabled,
            'deleted'         => $deleted,
            'local_users'     => count($after),
            'log'             => $log,
        ];
    }

    /**
     * Look up computer accounts in Active Directory (managed endpoints). Read-only, with the
     * service account. Keys are the host names asked for (lower case); null = not found.
     *
     * @param list<string> $hostnames
     * @return array<string, ?array{dn: string, dns_host: string, enabled: bool, groups: list<string>}>
     */
    public function computers(array $hostnames): array
    {
        [$connection, $settings] = $this->adConnection();
        $results = [];
        foreach (array_unique(array_map('strtolower', $hostnames)) as $hostname) {
            // NetBIOS name: first label, at most 15 characters; computer accounts end with "$"
            $netbios = strtoupper(substr(explode('.', $hostname)[0], 0, 15));
            if (!preg_match('/^[A-Z0-9][A-Z0-9-]{0,14}$/', $netbios)) {
                $results[$hostname] = null;
                continue;
            }
            $search = @ldap_search($connection, $settings['base_dn'], '(&(objectCategory=computer)(sAMAccountName=' . ldap_escape($netbios . '$', '', LDAP_ESCAPE_FILTER) . '))', ['distinguishedName', 'dNSHostName', 'userAccountControl'], 0, 2);
            $entries = false === $search ? ['count' => 0] : ldap_get_entries($connection, $search);
            if (1 !== (int) $entries['count']) {
                $results[$hostname] = null;
                continue;
            }
            $dn = (string) $entries[0]['distinguishedname'][0];
            $groups = [];
            // LDAP_MATCHING_RULE_IN_CHAIN: direct and nested group memberships
            $search = @ldap_search($connection, $settings['base_dn'], '(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:=' . ldap_escape($dn, '', LDAP_ESCAPE_FILTER) . '))', ['sAMAccountName'], 0, 500);
            if (false !== $search) {
                $found = ldap_get_entries($connection, $search);
                for ($i = 0; $i < (int) $found['count']; $i++) {
                    $groups[] = (string) $found[$i]['samaccountname'][0];
                }
            }
            sort($groups, SORT_FLAG_CASE | SORT_STRING);
            $results[$hostname] = [
                'dn' => $dn,
                'dns_host' => strtolower((string) ($entries[0]['dnshostname'][0] ?? '')),
                'enabled' => 0 === ((int) ($entries[0]['useraccountcontrol'][0] ?? 0) & 2),
                'groups' => $groups,
            ];
        }
        ldap_unbind($connection);
        return $results;
    }

    /**
     * Every computer account in the base DN (paged, at most $limit), for the endpoint coverage check.
     * @return array{computers: list<array{name: string, dn: string, dns_host: string, os: string, enabled: bool, last_logon: ?int}>, truncated: bool}
     */
    public function computerAccounts(int $limit = 20000): array
    {
        [$connection, $settings] = $this->adConnection();
        $attributes = ['sAMAccountName', 'distinguishedName', 'dNSHostName', 'operatingSystem', 'userAccountControl', 'lastLogonTimestamp'];
        $computers = [];
        $cookie = '';
        $truncated = false;
        do {
            $controls = [['oid' => LDAP_CONTROL_PAGEDRESULTS, 'value' => ['size' => 500, 'cookie' => $cookie]]];
            $search = @ldap_search($connection, $settings['base_dn'], '(objectCategory=computer)', $attributes, 0, 0, 0, LDAP_DEREF_NEVER, $controls);
            if (false === $search) {
                $reason = ldap_error($connection);
                ldap_unbind($connection);
                throw new ValidationException('Active Directory refused the computer search: ' . $reason);
            }
            $responseControls = [];
            ldap_parse_result($connection, $search, $code, $matched, $message, $referrals, $responseControls);
            $entries = ldap_get_entries($connection, $search);
            for ($i = 0; $i < (int) $entries['count']; $i++) {
                if (count($computers) >= $limit) {
                    $truncated = true;
                    break 2;
                }
                $e = $entries[$i];
                $filetime = (int) ($e['lastlogontimestamp'][0] ?? 0);
                $computers[] = [
                    'name'       => strtolower(rtrim((string) ($e['samaccountname'][0] ?? ''), '$')),
                    'dn'         => (string) ($e['distinguishedname'][0] ?? ''),
                    'dns_host'   => strtolower((string) ($e['dnshostname'][0] ?? '')),
                    'os'         => (string) ($e['operatingsystem'][0] ?? ''),
                    'enabled'    => 0 === ((int) ($e['useraccountcontrol'][0] ?? 0) & 2),
                    // Windows FILETIME (100 ns since 1601) to Unix time; replicated within ~14 days
                    'last_logon' => $filetime > 0 ? intdiv($filetime, 10_000_000) - 11_644_473_600 : null,
                ];
            }
            $cookie = (string) ($responseControls[LDAP_CONTROL_PAGEDRESULTS]['value']['cookie'] ?? '');
        } while ('' !== $cookie);
        ldap_unbind($connection);
        usort($computers, static fn (array $a, array $b): int => strcmp($a['name'], $b['name']));
        return ['computers' => $computers, 'truncated' => $truncated];
    }

    /**
     * A bound LDAP connection to Active Directory with the service account.
     * @return array{0: \LDAP\Connection, 1: array}
     */
    private function adConnection(): array
    {
        $settings = $this->settings();
        if (!$settings['enabled'] || 1 !== $settings['server_type']) {
            throw new ValidationException('Active Directory is not configured (Directory page).');
        }
        $engine = $this->engineWithPassword(); // also applies the TLS options (LDAPTLS_*)
        $password = (string) $engine->GetLdapServerPassword();
        $engine->SetLdapServerPassword('');
        $bindName = $settings['bind_dn'];
        if (!str_contains($bindName, '=') && !str_contains($bindName, '@') && !str_contains($bindName, '\\')) {
            $bindName .= $settings['account_suffix'];
        }
        $port = (int) ($settings['port'] ?: ($settings['ssl'] ? 636 : 389));
        foreach (preg_split('/[\s,;]+/', $settings['domain_controllers'], -1, PREG_SPLIT_NO_EMPTY) as $server) {
            $candidate = @ldap_connect(($settings['ssl'] ? 'ldaps://' : 'ldap://') . $server . ':' . $port);
            if (false === $candidate) {
                continue;
            }
            ldap_set_option($candidate, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_set_option($candidate, LDAP_OPT_REFERRALS, 0);
            ldap_set_option($candidate, LDAP_OPT_NETWORK_TIMEOUT, max(1, $settings['network_timeout'] ?: 5));
            if (@ldap_bind($candidate, $bindName, $password)) {
                return [$candidate, $settings];
            }
        }
        throw new ValidationException('Could not connect to Active Directory with the service account.');
    }

    /** Ask a running engine sync to stop (the engine checks this file in its loop). */
    public function requestStop(): void
    {
        $engine = MultiotpService::get();
        @touch($engine->GetLockFolder() . $engine->GetLdapSyncStopFileName());
    }

    /** The engine's own progress line for a running sync, e.g. "started at 10:02:11, LDAP account #1200 at 10:03:40". */
    public function engineProgress(): string
    {
        $engine = MultiotpService::get();
        $file = $engine->GetLockFolder() . $engine->GetLdapSyncLockFileName();
        return is_file($file) ? trim((string) @file_get_contents($file)) : '';
    }

    public function isScheduleDue(int $now): bool
    {
        $state = $this->state();
        if (empty($state['schedule']['enabled'])) {
            return false;
        }
        $minutes = max(5, (int) ($state['schedule']['minutes'] ?? 60));
        return ($state['last_scheduled_at'] ?? 0) + $minutes * 60 <= $now;
    }

    private function engineWithPassword(): \Multiotp
    {
        MultiotpService::reset();
        $engine = MultiotpService::get();
        $state = $this->state();
        $password = !empty($state['bind_password']) ? Crypto::decrypt($state['bind_password']) : (string) $engine->GetLdapServerPassword();
        if ('' === $password) {
            throw new ValidationException('No service-account password is configured.');
        }
        if ('' === trim((string) $engine->GetLdapDomainControllers())) {
            throw new ValidationException('No directory server is configured.');
        }
        $engine->SetLdapTlsOptions();
        $engine->SetLdapServerPassword($password);
        return $engine;
    }

    /** @return array<string, array{enabled: bool, synchronized: bool, name: string}> */
    public static function snapshot(): array
    {
        $list = MultiotpService::get()->ApiGetUsersArray(['page' => 1, 'itemsPerPage' => 1000000]);
        $users = [];
        foreach ($list['users'] ?? [] as $user) {
            $users[mb_strtolower((string) $user['user'])] = [
                'enabled'      => (bool) $user['enabled'],
                'synchronized' => (bool) (int) $user['synchronized'],
                'name'         => (string) ($user['display_name'] ?: $user['description']),
            ];
        }
        return $users;
    }
}
