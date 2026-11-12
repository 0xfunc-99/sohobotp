<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * High availability: two appliances, MariaDB replication (stage 6b).
 *
 * Primary: MariaDB on this appliance (Database page) with a binary log; it pairs with ONE
 * secondary and shows a pairing code (shown once). Secondary: a fresh appliance that joins
 * with the code: it copies the database from the primary and then replicates it continuously
 * (TLS, the primary's database certificate pinned), read-only. While the primary is up, the
 * secondary's engine uses the PRIMARY's database (TLS, pinned), because every login writes
 * (replay protection, failure counters). Every minute it copies the primary's RADIUS
 * configuration (clients, Symantec VIP servers, routing file) through portal/ha.php, encrypted
 * and authenticated with the pairing key. If the primary fails, "Promote" (by hand, or
 * automatically after N minutes) makes the secondary a primary: replication stopped, its own
 * database writable, the engine switched to it.
 *
 * ha.json: {role, primary_ip, secondary_ip, portal_url, key (sealed), local_password (sealed),
 *           paired_at, last_sync_at, last_sync_hash, last_sync_error, served_at,
 *           primary_down_since, auto_promote_minutes, promoted_at}
 */
final class Ha
{
    private const MAGIC = "sohobotp-ha-v1\n";
    private const WINDOW = 300;

    private JsonStore $store;

    public function __construct(?JsonStore $store = null)
    {
        $this->store = $store ?? new JsonStore(Config::dataDir() . '/ha.json');
    }

    public static function engineCaFile(): string
    {
        return Config::etcDir() . '/config/ha-primary-ca.pem';
    }

    /** @return array state without secrets */
    public function state(): array
    {
        $data = $this->store->read();
        unset($data['key'], $data['local_password']);
        return $data + ['role' => 'none'];
    }

    public static function isSecondary(): bool
    {
        return 'secondary' === ((new self())->store->read()['role'] ?? 'none');
    }

    private static function random(int $length = 32): string
    {
        $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
        $out = '';
        for ($i = 0; $i < $length; $i++) {
            $out .= $alphabet[random_int(0, strlen($alphabet) - 1)];
        }
        return $out;
    }

    private static function ipv4(string $ip, string $what): string
    {
        $ip = trim($ip);
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || str_starts_with($ip, '127.') || str_starts_with($ip, '0.')) {
            throw new ValidationException("Enter the IPv4 address of $what (not 127.x).");
        }
        return $ip;
    }

    private static function candidateDir(): string
    {
        $dir = Config::ensureDataDir() . '/database';
        if (!is_dir($dir) && !@mkdir($dir, 0700) && !is_dir($dir)) {
            throw new \RuntimeException('Cannot create the database folder.');
        }
        return $dir;
    }

    // ------------------------------------------------------------------ primary

    /** Pair this appliance (primary) with a secondary. Returns the pairing code (secret, shown once). */
    public function pair(string $primaryIp, string $secondaryIp, string $portalUrl): string
    {
        $db = Database::current();
        if ('mysql' !== $db['backend'] || !$db['local']) {
            throw new ValidationException('First move the data to MariaDB on this appliance (Database page).');
        }
        if ('none' !== ($this->store->read()['role'] ?? 'none')) {
            throw new ValidationException('This appliance is already part of a pair.');
        }
        $primaryIp = self::ipv4($primaryIp, 'this appliance (as the secondary reaches it)');
        $secondaryIp = self::ipv4($secondaryIp, 'the secondary appliance');
        if (!preg_match('{^https://[A-Za-z0-9.\-\[\]:]+(/[A-Za-z0-9._~/-]*)?$}', $portalUrl)) {
            throw new ValidationException('The portal address must look like https://10.0.0.5');
        }
        $repl = self::random();
        $app = self::random();
        $key = self::random();
        $candidate = self::candidateDir() . '/ha.candidate';
        file_put_contents($candidate, "role=primary\nprimary=$primaryIp\nreplica=$secondaryIp\nrepl_password=$repl\napp_password=$app\n");
        @chmod($candidate, 0600);
        $result = Database::helper('ha-primary');
        @unlink($candidate);
        if (!$result['ok'] || !preg_match('/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/s', $result['output'], $m)) {
            throw new ValidationException('The primary database could not be prepared: ' . mb_substr($result['output'], 0, 400));
        }
        $this->store->update(static function (array &$data) use ($primaryIp, $secondaryIp, $key, $portalUrl): void {
            $data = ['role' => 'primary', 'primary_ip' => $primaryIp, 'secondary_ip' => $secondaryIp, 'portal_url' => rtrim($portalUrl, '/'),
                'key' => Crypto::encrypt($key), 'paired_at' => time(), 'served_at' => null];
        });
        $code = ['v' => 1, 'primary' => $primaryIp, 'portal' => rtrim($portalUrl, '/'), 'repl' => $repl, 'app' => $app, 'key' => $key, 'ca' => $m[0]];
        return 'SOHOBOTP-HA-' . rtrim(strtr(base64_encode((string) json_encode($code)), '+/', '-_'), '=');
    }

    /** portal/ha.php on the primary: the RADIUS configuration for the secondary (encrypted, authenticated). */
    public static function serve(): void
    {
        header('Content-Type: application/json');
        header('Cache-Control: no-store');
        $ha = new self();
        $data = $ha->store->read();
        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        $time = (string) ($_SERVER['HTTP_X_HA_TIME'] ?? '');
        $signature = (string) ($_SERVER['HTTP_X_HA_SIGNATURE'] ?? '');
        $key = 'primary' === ($data['role'] ?? '') ? Crypto::decrypt((string) $data['key']) : '';
        $ok = '' !== $key && $ip === ($data['secondary_ip'] ?? '') && ctype_digit($time) && abs(time() - (int) $time) <= self::WINDOW
            && hash_equals(hash_hmac('sha256', self::MAGIC . $time, $key), $signature);
        if (!$ok) {
            http_response_code(403);
            echo json_encode(['error' => 'forbidden']);
            exit;
        }
        $radius = new Radius();
        $route = @file_get_contents(VipMigration::routeFile());
        // engine_key: the secondary reads the same database, so it must decrypt with the same key
        $payload = (string) json_encode(['clients' => $radius->render(), 'vip' => $radius->renderVip(), 'route' => false === $route ? '' : $route,
            'engine_key' => EngineKey::current(), 'at' => time()]);
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $box = sodium_crypto_secretbox($payload, $nonce, hash('sha256', self::MAGIC . $key, true));
        $ha->store->update(static function (array &$d): void {
            $d['served_at'] = time();
        });
        echo json_encode(['box' => base64_encode($nonce . $box)]);
        exit;
    }

    // ------------------------------------------------------------------ secondary

    /** Join a primary with its pairing code (this appliance must still be on files). */
    public function join(string $code): void
    {
        if ('none' !== ($this->store->read()['role'] ?? 'none')) {
            throw new ValidationException('This appliance is already part of a pair.');
        }
        if ('files' !== Database::current()['backend']) {
            throw new ValidationException('Join with a fresh appliance (its data is replaced by the primary\'s).');
        }
        $raw = base64_decode(strtr(preg_replace('/^SOHOBOTP-HA-/', '', trim($code)) ?? '', '-_', '+/'), true);
        $c = false === $raw ? null : json_decode($raw, true);
        $pw = '/^[A-Za-z0-9]{32}$/';
        if (!is_array($c) || 1 !== ($c['v'] ?? 0) || !filter_var($c['primary'] ?? '', FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
            || !preg_match($pw, (string) ($c['repl'] ?? '')) || !preg_match($pw, (string) ($c['app'] ?? '')) || !preg_match($pw, (string) ($c['key'] ?? ''))
            || !preg_match('{^https://}', (string) ($c['portal'] ?? '')) || !str_contains((string) ($c['ca'] ?? ''), 'BEGIN CERTIFICATE')) {
            throw new ValidationException('This is not a valid pairing code.');
        }
        $local = Database::prepareLocal();
        $dir = self::candidateDir();
        file_put_contents("$dir/primary-ca.pem", $c['ca']);
        file_put_contents("$dir/ha.candidate", "role=replica\nprimary={$c['primary']}\nrepl_password={$c['repl']}\napp_password={$c['app']}\n");
        @chmod("$dir/ha.candidate", 0600);
        $result = Database::helper('ha-replica');
        @unlink("$dir/ha.candidate");
        if (!$result['ok'] || !str_contains($result['output'], 'Slave_IO_Running:Yes') || !str_contains($result['output'], 'Slave_SQL_Running:Yes')) {
            throw new ValidationException('Replication from the primary could not start: ' . mb_substr($result['output'], 0, 500));
        }
        file_put_contents(self::engineCaFile(), $c['ca']);
        @chmod(self::engineCaFile(), 0644);
        self::engineTo($c['primary'], 'sohobotp', $c['app'], self::engineCaFile());
        $this->store->update(static function (array &$data) use ($c, $local): void {
            $data = ['role' => 'secondary', 'primary_ip' => $c['primary'], 'portal_url' => $c['portal'], 'key' => Crypto::encrypt($c['key']),
                'local_password' => Crypto::encrypt($local['password']), 'paired_at' => time(), 'last_sync_at' => null, 'last_sync_hash' => '',
                'last_sync_error' => '', 'primary_down_since' => null, 'auto_promote_minutes' => 0];
        });
        $this->sync(true);
    }

    /** Point the engine at a MariaDB (primary over TLS, or the local one after a promotion). */
    private static function engineTo(string $host, string $user, string $password, string $caFile): void
    {
        $e = MultiotpService::create(false);
        $e->SetBackendTypeValidated('mysql', true);
        $e->SetBackendType('mysql');
        $e->SetBackendTypeValidated('mysql', true);
        $e->SetSqlServer($host . ':3306');
        $e->SetSqlUsername($user);
        $e->SetSqlPassword($password);
        $e->SetSqlDatabase('sohobotp');
        $e->SetSqlCaFile($caFile);
        $e->WriteConfigData();
        MultiotpService::reset();
    }

    /** Copy the primary's RADIUS configuration (secondary). Returns true when FreeRADIUS was updated. */
    public function sync(bool $force = false): bool
    {
        $data = $this->store->read();
        if ('secondary' !== ($data['role'] ?? '')) {
            return false;
        }
        $key = Crypto::decrypt((string) $data['key']);
        $time = (string) time();
        $ctx = stream_context_create(['http' => ['method' => 'GET', 'timeout' => 15, 'ignore_errors' => true,
            'header' => "X-HA-Time: $time\r\nX-HA-Signature: " . hash_hmac('sha256', self::MAGIC . $time, $key) . "\r\n"],
            // the answer is encrypted and authenticated with the pairing key: TLS only adds privacy
            'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]]);
        $raw = @file_get_contents($data['portal_url'] . '/portal/ha.php', false, $ctx);
        $error = '';
        $changed = false;
        $answer = false === $raw ? null : json_decode($raw, true);
        $box = is_array($answer) ? base64_decode((string) ($answer['box'] ?? ''), true) : false;
        $plain = false === $box || strlen($box) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ? false
            : sodium_crypto_secretbox_open(substr($box, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), substr($box, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), hash('sha256', self::MAGIC . $key, true));
        $payload = false === $plain ? null : json_decode($plain, true);
        if (!is_array($payload)) {
            $error = false === $raw ? 'The primary portal does not answer.' : 'The primary refused the request or its answer could not be authenticated.';
        } else {
            $engineKey = (string) ($payload['engine_key'] ?? '');
            if ('' !== $engineKey && $engineKey !== (string) EngineKey::current()) {
                try {
                    EngineKey::protect($engineKey);
                } catch (\Throwable $keyError) {
                    $error = 'The primary\'s engine key could not be adopted: ' . $keyError->getMessage();
                }
            }
            $hash = hash('sha256', $payload['clients'] . "\n" . $payload['vip']);
            if ($force || $hash !== ($data['last_sync_hash'] ?? '')) {
                file_put_contents(Radius::candidateFile(), $payload['clients']);
                file_put_contents(Radius::vipCandidateFile(), $payload['vip']);
                $result = Radius::helper('apply');
                if ($result['ok']) {
                    $changed = true;
                    $data['last_sync_hash'] = $hash;
                } else {
                    $error = 'FreeRADIUS refused the configuration from the primary: ' . mb_substr($result['output'], 0, 300);
                }
            }
            if ('' !== $payload['route']) {
                $file = VipMigration::routeFile();
                @mkdir(dirname($file), 0750, true);
                if (false !== @file_put_contents("$file.tmp", $payload['route'])) {
                    @chmod("$file.tmp", 0640);
                    @rename("$file.tmp", $file);
                }
            }
        }
        $this->store->update(static function (array &$d) use ($error, $data): void {
            $d['last_sync_at'] = '' === $error ? time() : ($d['last_sync_at'] ?? null);
            $d['last_sync_error'] = $error;
            $d['last_sync_hash'] = $data['last_sync_hash'] ?? '';
        });
        return $changed;
    }

    /** Secondary: is the primary's database reachable (TLS, pinned)? */
    public function primaryReachable(): bool
    {
        $data = $this->store->read();
        $e = MultiotpService::get()->_config_data;
        mysqli_report(MYSQLI_REPORT_OFF);
        $db = mysqli_init();
        $db->options(MYSQLI_OPT_CONNECT_TIMEOUT, 5);
        $db->options(MYSQLI_OPT_SSL_VERIFY_SERVER_CERT, true);
        $db->ssl_set(null, null, self::engineCaFile(), null, null);
        $ok = @$db->real_connect((string) $data['primary_ip'], (string) $e['sql_username'], (string) $e['sql_password'], 'sohobotp', 3306, null, MYSQLI_CLIENT_SSL);
        if ($ok) {
            $db->close();
        }
        return (bool) $ok;
    }

    /** Make this secondary a primary (the old primary is gone). */
    public function promote(string $by): void
    {
        $data = $this->store->read();
        if ('secondary' !== ($data['role'] ?? '')) {
            throw new ValidationException('Only a secondary can be promoted.');
        }
        $result = Database::helper('ha-promote');
        if (!$result['ok']) {
            throw new ValidationException('Promotion failed: ' . $result['output']);
        }
        self::engineTo('127.0.0.1', 'sohobotp', Crypto::decrypt((string) $data['local_password']), '');
        $this->store->update(static function (array &$d) use ($by): void {
            $d['role'] = 'promoted';
            $d['promoted_at'] = time();
            $d['promoted_by'] = $by;
        });
        (new VipMigration())->export();
    }

    public function setAutoPromote(int $minutes): void
    {
        if ($minutes < 0 || $minutes > 1440) {
            throw new ValidationException('Automatic promotion: 0 (off) to 1440 minutes.');
        }
        $this->store->update(static function (array &$d) use ($minutes): void {
            $d['auto_promote_minutes'] = $minutes;
        });
    }

    /** Worker, every tick on a secondary: sync every minute, watch the primary, promote if configured. */
    public function tick(callable $log): void
    {
        $data = $this->store->read();
        if ('secondary' !== ($data['role'] ?? '')) {
            return;
        }
        if (null === ($data['last_sync_at'] ?? null) || $data['last_sync_at'] < time() - 60 || '' !== ($data['last_sync_error'] ?? '')) {
            if ($this->sync()) {
                $log('HA: RADIUS configuration updated from the primary');
            }
        }
        $up = $this->primaryReachable();
        $this->store->update(static function (array &$d) use ($up): void {
            $d['primary_down_since'] = $up ? null : ($d['primary_down_since'] ?? time());
        });
        $data = $this->store->read();
        $minutes = (int) ($data['auto_promote_minutes'] ?? 0);
        if (!$up && $minutes > 0 && null !== $data['primary_down_since'] && $data['primary_down_since'] <= time() - 60 * $minutes) {
            $this->promote('automatic');
            $log("HA: primary unreachable for $minutes minute(s): this secondary was promoted");
            Audit::default()->record('ha.promote', 'success', (string) $data['primary_ip'], ['by' => 'automatic', 'minutes' => $minutes]);
        }
    }
}
