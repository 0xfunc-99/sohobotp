<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Where multiOTP keeps users, tokens, RADIUS devices and groups: files (default) or a
 * MariaDB / MySQL database, on this appliance (root helper bin/sohobotp-db creates it) or
 * on another server. Switching migrates everything in the worker (job database.migrate)
 * with the engine's own "migration from file" mode, checks the counts, and keeps the files
 * as a backup; any failure goes back to files.
 */
final class Database
{
    public const LOCAL = ['host' => '127.0.0.1', 'port' => 3306, 'database' => 'sohobotp', 'user' => 'sohobotp'];
    public const HELPER = '/usr/local/sbin/sohobotp-db';

    /** @return array{backend: string, server: string, database: string, user: string, local: bool} */
    public static function current(): array
    {
        $e = MultiotpService::get();
        $backend = 'mysql' === $e->GetBackendType() && $e->GetBackendTypeValidated() ? 'mysql' : 'files';
        $server = 'mysql' === $backend ? (string) $e->GetSqlServer() : '';
        return ['backend' => $backend, 'server' => $server, 'database' => 'mysql' === $backend ? (string) ($e->_config_data['sql_database'] ?? '') : '',
            'user' => 'mysql' === $backend ? (string) ($e->_config_data['sql_username'] ?? '') : '',
            'local' => in_array($server, ['127.0.0.1:3306', '127.0.0.1', 'localhost', 'localhost:3306'], true)];
    }

    /** @return array{host: string, port: int, database: string, user: string, password: string, tls: bool} */
    public static function validate(array $input): array
    {
        $host = trim((string) ($input['host'] ?? ''));
        if (!filter_var($host, FILTER_VALIDATE_IP) && !preg_match('/^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$/', $host)) {
            throw new ValidationException('Enter the database server as an IP address or a host name.');
        }
        $port = trim((string) ($input['port'] ?? '3306')) ?: '3306';
        if (!ctype_digit($port) || (int) $port < 1 || (int) $port > 65535) {
            throw new ValidationException('Invalid port.');
        }
        $database = trim((string) ($input['database'] ?? ''));
        $user = trim((string) ($input['user'] ?? ''));
        if (!preg_match('/^[A-Za-z0-9_]{1,64}$/', $database) || !preg_match('/^[A-Za-z0-9_.@-]{1,80}$/', $user)) {
            throw new ValidationException('Database and user names: letters, digits and underscore (user also . @ -).');
        }
        $password = (string) ($input['password'] ?? '');
        if ('' === $password || strlen($password) > 256 || preg_match('/[\x00-\x1f]/', $password)) {
            throw new ValidationException('Enter the database password (no control characters).');
        }
        return ['host' => $host, 'port' => (int) $port, 'database' => $database, 'user' => $user, 'password' => $password, 'tls' => !empty($input['tls'])];
    }

    /** @return array{ok: bool, message: string} */
    public static function test(array $c): array
    {
        if (!class_exists(\mysqli::class)) {
            return ['ok' => false, 'message' => 'PHP has no MySQL driver (mysqli) on this server.'];
        }
        mysqli_report(MYSQLI_REPORT_OFF);
        $db = mysqli_init();
        $db->options(MYSQLI_OPT_CONNECT_TIMEOUT, 5);
        if ($c['tls']) {
            $db->ssl_set(null, null, null, null, null);
        }
        $ok = @$db->real_connect($c['host'], $c['user'], $c['password'], $c['database'], $c['port'], null, $c['tls'] ? MYSQLI_CLIENT_SSL : 0);
        if (!$ok) {
            return ['ok' => false, 'message' => 'Cannot connect: ' . mysqli_connect_error()];
        }
        $version = (string) ($db->query('SELECT VERSION()')?->fetch_row()[0] ?? '');
        $canCreate = (bool) $db->query('CREATE TABLE IF NOT EXISTS `sohobotp_connection_test` (id INT)');
        if ($canCreate) {
            $db->query('DROP TABLE `sohobotp_connection_test`');
        }
        $db->close();
        return $canCreate
            ? ['ok' => true, 'message' => "Connected ($version); the user may create tables."]
            : ['ok' => false, 'message' => "Connected ($version), but the user may not create tables in this database."];
    }

    /** @return array{users: int, tokens: int, devices: int, groups: int} */
    public static function counts(?\Multiotp $engine = null): array
    {
        $e = $engine ?? MultiotpService::get();
        $count = static fn (string $list): int => '' === trim($list) ? 0 : count(array_filter(explode("\t", $list), 'strlen'));
        return ['users' => $count((string) $e->GetUsersList()), 'tokens' => $count((string) $e->GetTokensList()),
            'devices' => $count((string) $e->GetDevicesList()), 'groups' => $count((string) $e->GetGroupsList())];
    }

    /** Prepare MariaDB on this appliance (root helper): returns the connection to migrate to. */
    public static function prepareLocal(): array
    {
        $password = '';
        $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
        for ($i = 0; $i < 32; $i++) {
            $password .= $alphabet[random_int(0, strlen($alphabet) - 1)];
        }
        $dir = Config::ensureDataDir() . '/database';
        if (!is_dir($dir) && !@mkdir($dir, 0700) && !is_dir($dir)) {
            throw new \RuntimeException('Cannot create the database folder.');
        }
        $candidate = $dir . '/local.candidate';
        file_put_contents($candidate, "password=$password\n");
        @chmod($candidate, 0600);
        $result = self::helper('local-enable');
        @unlink($candidate);
        if (!$result['ok']) {
            throw new ValidationException('MariaDB on this appliance could not be prepared: ' . $result['output']);
        }
        return self::LOCAL + ['password' => $password, 'tls' => false];
    }

    /**
     * Move everything from files to the database (worker). Files are kept as a backup.
     * @return array{ok: bool, before: array, after: array, error: ?string}
     */
    public static function migrate(array $c, callable $progress): array
    {
        $files = MultiotpService::create(false);
        if ('files' !== self::current()['backend']) {
            return ['ok' => false, 'before' => [], 'after' => [], 'error' => 'The data is already in a database.'];
        }
        $lists = [];
        foreach (['users' => 'GetUsersList', 'tokens' => 'GetTokensList', 'devices' => 'GetDevicesList', 'groups' => 'GetGroupsList'] as $kind => $fn) {
            $lists[$kind] = array_values(array_filter(explode("\t", (string) $files->$fn()), 'strlen'));
        }
        $before = array_map('count', $lists);
        $progress('Creating the tables');
        $init = MultiotpService::create(true);
        $init->SetBackendType('mysql');
        $init->SetSqlServer($c['host'] . ':' . $c['port']);
        $init->SetSqlUsername($c['user']);
        $init->SetSqlPassword($c['password']);
        $init->SetSqlDatabase($c['database']);
        $init->WriteConfigData();
        $init->InitializeBackend();
        if (!$init->GetBackendTypeValidated()) {
            self::backToFiles();
            return ['ok' => false, 'before' => $before, 'after' => [], 'error' => 'The database refused the tables (see the engine log).'];
        }
        $db = MultiotpService::create(false);
        $db->SetMigrationFromFile(true);
        $done = 0;
        $total = array_sum($before);
        foreach ($lists['groups'] as $group) {
            $db->ReadGroupData($group, false, true) && $db->WriteGroupData();
            $done++;
        }
        foreach ($lists['devices'] as $device) {
            $db->ReadDeviceData($device, false, true) && $db->WriteDeviceData(['with_radius_update' => false]);
            $done++;
        }
        foreach ($lists['tokens'] as $token) {
            $db->ReadTokenData($token) && $db->WriteTokenData();
            $done++;
        }
        foreach ($lists['users'] as $i => $user) {
            if ($db->ReadUserData($user, false, true)) {
                $db->WriteUserData();
            }
            $done++;
            if (0 === $i % 200) {
                $progress("Copying users: $done of $total items");
            }
        }
        $db->SetMigrationFromFile(false);
        MultiotpService::reset();
        $after = self::counts(MultiotpService::create(false));
        foreach ($before as $kind => $n) {
            if (($after[$kind] ?? -1) < $n) {
                self::backToFiles();
                return ['ok' => false, 'before' => $before, 'after' => $after, 'error' => "Only {$after[$kind]} of $n $kind reached the database: back to files."];
            }
        }
        (new VipMigration())->export();
        return ['ok' => true, 'before' => $before, 'after' => $after, 'error' => null];
    }

    /** Back to the files (they were kept). */
    public static function backToFiles(): void
    {
        $e = MultiotpService::create(false);
        $e->SetBackendTypeValidated('files', true);
        $e->SetBackendType('files');
        $e->WriteConfigData();
        MultiotpService::reset();
    }

    /** @return array{ok: bool, available: bool, output: string} */
    public static function helper(string $command): array
    {
        if (!in_array($command, ['local-enable', 'status', 'ha-primary', 'ha-replica', 'ha-promote', 'ha-status'], true)) {
            throw new \InvalidArgumentException('Unknown helper command.');
        }
        $helper = getenv('SOHOBOTP_DB_HELPER') ?: self::HELPER;
        if (!is_file($helper)) {
            return ['ok' => false, 'available' => false, 'output' => 'The database helper is not installed on this system.'];
        }
        $argv = function_exists('posix_geteuid') && 0 === posix_geteuid() ? [$helper, $command] : ['sudo', '-n', $helper, $command];
        $process = proc_open($argv, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($process)) {
            return ['ok' => false, 'available' => false, 'output' => 'The database helper could not be started.'];
        }
        $output = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        return ['ok' => 0 === proc_close($process), 'available' => true, 'output' => trim(mb_substr($output, 0, 5000))];
    }
}
