<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Set-up of a user's authenticator on the Windows sign-in screen (SohobOTP Sign-in), for
 * endpoint groups with "Let users set up their code at sign-in":
 * portal/cp.php?e=<endpoint id>&a=enrol.
 *
 *   start   {user, password}: the directory password is checked here (LDAP bind as the user),
 *           then the same rules as the self-service page (SelfEnrol::refusal: only users with no
 *           authenticator in use, only once). Answer: scan + the QR code as a module matrix (the
 *           sign-in screen only draws it) + the key; or not_needed / bad_password (wrong directory password) / refused.
 *   start   {user, local: true} (policy "Also local Windows accounts"): a local account whose
 *           Windows password the computer checked itself (the password is not sent). Only an
 *           account this computer reported, with no code yet, and no directory user of that
 *           name; its SohobOTP user is created at confirm, after the first right code.
 *   confirm {user, code}: the first code from the app. done: the seed is written to SohobOTP and
 *           the sign-in screen continues with the Windows password.
 *
 * Messages are sealed with the endpoint's own Sign-in secret (AES-256-GCM, key =
 * SHA-256("sohobotp-cp-enrol-v1" || secret), additional data = endpoint id; the answer's
 * additional data also binds the request nonce), so neither the password nor the seed depends
 * on the TLS certificate check of the sign-in screen, and a recorded request cannot be replayed
 * (timestamp +/- 5 minutes, nonce kept 10 minutes). Wire format: base64(12-byte IV || ciphertext || 16-byte tag).
 */
final class CpEnrol
{
    private const PENDING_LIFETIME = 600;
    private const MAX_CODE_TRIES = 5;

    public static function key(string $secret): string
    {
        return hash('sha256', 'sohobotp-cp-enrol-v1' . $secret, true);
    }

    public static function seal(string $plain, string $key, string $aad): string
    {
        $iv = random_bytes(12);
        $tag = '';
        $cipher = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, $aad, 16);
        if (false === $cipher) {
            throw new \RuntimeException('Encryption failed.');
        }
        return base64_encode($iv . $cipher . $tag);
    }

    public static function open(string $sealed, string $key, string $aad): ?string
    {
        $raw = base64_decode($sealed, true);
        if (false === $raw || strlen($raw) < 29 || strlen($raw) > 16384) {
            return null;
        }
        $plain = openssl_decrypt(substr($raw, 12, -16), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, -16), $aad);
        return false === $plain ? null : $plain;
    }

    /** Handles one request for an active Windows endpoint; sends the sealed answer. */
    public static function handle(array $endpoint, array $policy, string $secret, string $ip): never
    {
        ob_start(); // the engine may print warnings: they must not corrupt the sealed answer
        $key = self::key($secret);
        $id = $endpoint['id'];
        $plain = self::open((string) file_get_contents('php://input'), $key, $id);
        $req = null === $plain ? null : json_decode($plain, true);
        if (!is_array($req) || 1 !== ($req['v'] ?? null) || !is_string($req['n'] ?? null) || !preg_match('/^[0-9a-f]{32}$/', $req['n'])
            || abs(time() - (int) ($req['t'] ?? 0)) > 300 || !in_array($req['step'] ?? '', ['start', 'confirm'], true)) {
            self::raw(400, 'Bad request.');
        }
        if (!self::freshNonce($id, $req['n'])) {
            self::raw(409, 'Replayed request.');
        }
        $reply = static function (array $answer) use ($key, $id, $req): never {
            while (ob_get_level() > 0) {
                ob_end_clean();
            }
            header('Content-Type: text/plain; charset=us-ascii');
            echo self::seal((string) json_encode($answer + ['n' => $req['n']], JSON_UNESCAPED_SLASHES), $key, $id . '|' . $req['n']);
            exit;
        };
        Audit::setActor('sign-in screen ' . $id);
        $audit = Audit::default();
        if (empty($policy['enrol_at_signin'])) {
            $reply(['status' => 'off']);
        }
        $username = mb_strtolower(trim(mb_substr((string) ($req['user'] ?? ''), 0, 128)));
        $username = (string) preg_replace('/^[^\\\\]*\\\\|@.*$/', '', $username); // DOMAIN\user, user@domain
        $users = new Users();
        $user = null === Users::validateName($username) && $users->exists($username) ? $users->get($username) : null;
        $pendingKey = $id . '|' . $username;

        if ('start' === $req['step']) {
            $local = true === ($req['local'] ?? false);
            if ($local) {
                if (empty($policy['enrol_local']) || !self::reportedLocalAccount($endpoint, $username)
                    || (null !== $user && ($user['synchronized'] || null !== (new SelfEnrol())->refusal($user)))) {
                    $reply(['status' => 'not_needed']); // the normal sign-in decides
                }
            } else {
                if (null === $user || !$user['synchronized'] || '' === $user['synced_dn']) {
                    $reply(['status' => 'not_needed']); // local accounts and unknown users: the normal sign-in decides
                }
                if (null !== $user['last_login'] && null === (new SelfEnrol())->resetAt($user['user'])) {
                    $reply(['status' => 'not_needed']); // already signs in with a code: no password check needed
                }
                $engine = MultiotpService::get();
                $engine->SetUser($user['user']);
                if (!$engine->CheckUserLdapPassword($engine->GetUserSynchronizedDn(), (string) ($req['password'] ?? ''))) {
                    $audit->record('self_enrol.sign_in', 'failure', $user['user'], ['reason' => 'wrong directory password', 'via' => 'sign-in screen', 'endpoint' => $id]);
                    // Sign-in 1.0.4 then says "wrong password" (older versions treat it as not_needed)
                    $reply(['status' => 'bad_password']);
                }
                if (null !== ($refusal = (new SelfEnrol())->refusal($user))) {
                    $reply(['status' => 'not_needed']);
                }
            }
            $seed = random_bytes(20);
            $create = null === $user;
            self::pending()->update(static function (array &$data) use ($pendingKey, $seed, $create): void {
                foreach ($data as $k => $p) {
                    if ($p['at'] < time() - self::PENDING_LIFETIME) {
                        unset($data[$k]);
                    }
                }
                $data[$pendingKey] = ['seed' => Crypto::encrypt(bin2hex($seed)), 'at' => time(), 'tries' => 0, 'create' => $create];
            });
            $audit->record('self_enrol.sign_in', 'success', $username, ['via' => 'sign-in screen', 'endpoint' => $id, 'account' => $local ? 'local (password checked by the computer)' : 'directory']);
            $uri = SelfEnrol::otpauthUri($username, $seed);
            $reply(['status' => 'scan', 'secret' => implode(' ', str_split(Totp::base32($seed), 4)), 'qr' => self::matrix($uri), 'minutes' => intdiv(self::PENDING_LIFETIME, 60)]);
        }

        // confirm
        $pending = self::pending()->read()[$pendingKey] ?? null;
        if ((null === $user && empty($pending['create'])) || null === $pending || $pending['at'] < time() - self::PENDING_LIFETIME) {
            $reply(['status' => 'expired', 'message' => 'The set-up expired. Sign in again to get a new QR code.']);
        }
        $seedHex = Crypto::decrypt($pending['seed']);
        $code = (string) preg_replace('/\D/', '', (string) ($req['code'] ?? ''));
        $step = 6 === strlen($code) ? Totp::verify((string) hex2bin($seedHex), $code, -1, time()) : null;
        if (null === $step) {
            $tries = self::pending()->update(static function (array &$data) use ($pendingKey): int {
                if (!isset($data[$pendingKey])) {
                    return self::MAX_CODE_TRIES;
                }
                $data[$pendingKey]['tries']++;
                $tries = $data[$pendingKey]['tries'];
                if ($tries >= self::MAX_CODE_TRIES) {
                    unset($data[$pendingKey]);
                }
                return $tries;
            });
            if ($tries >= self::MAX_CODE_TRIES) {
                $audit->record('self_enrol.confirm', 'failure', $username, ['reason' => 'too many wrong codes', 'via' => 'sign-in screen', 'endpoint' => $id]);
                $reply(['status' => 'expired', 'message' => 'Too many wrong codes. Sign in again to get a new QR code.']);
            }
            $reply(['status' => 'wrong_code', 'message' => 'This code is not correct. Type the code the app shows now.']);
        }
        if (null === $user) {
            // local account (start checked it): its SohobOTP user, created now that the first code is right
            if ($users->exists($username)) {
                self::forget($pendingKey);
                $reply(['status' => 'not_needed']); // created elsewhere meanwhile
            }
            $users->create(['user' => $username, 'display_name' => $username . ' on ' . (string) ($endpoint['inventory']['hostname'] ?? $id), 'token_serial' => '']);
            $audit->record('user.create', 'success', $username, ['via' => 'sign-in screen (local account)', 'endpoint' => $id]);
            $user = $users->get($username);
        }
        if (null !== (new SelfEnrol())->refusal($user)) { // set up elsewhere meanwhile
            self::forget($pendingKey);
            $reply(['status' => 'not_needed']);
        }
        $users->enrollSoftwareToken($user['user'], $seedHex, $step);
        (new SelfEnrol())->markDone($user['user'], 'self', 'sign-in screen ' . $ip);
        (new VipMigration())->set([$user['user']], 'sohobotp', 'self-service', 'authenticator set up at the Windows sign-in');
        self::forget($pendingKey);
        $audit->record('user.token_enrolled', 'success', $user['user'], ['type' => 'software TOTP', 'via' => 'sign-in screen', 'endpoint' => $id]);
        $reply(['status' => 'done']);
    }

    /** The computer reported this local account (agent inventory): only those may be created. */
    private static function reportedLocalAccount(array $endpoint, string $username): bool
    {
        foreach ((array) ($endpoint['inventory']['accounts'] ?? []) as $account) {
            if ('local' === ($account['kind'] ?? '') && mb_strtolower((string) ($account['name'] ?? '')) === $username) {
                return '' !== $username && null === Users::validateName($username);
            }
        }
        return false;
    }

    /** QR code modules as rows of "0"/"1" (dark = 1), drawn by the sign-in screen. */
    public static function matrix(string $text): array
    {
        MultiotpService::get(); // loads the bundled barcode generator
        $encode = new \ReflectionMethod(\barcode_generator::class, 'dispatch_encode');
        $code = $encode->invoke(new \barcode_generator(), 'qr-m', $text, []);
        $rows = [];
        foreach ($code['b'] as $row) {
            $rows[] = implode('', array_map(static fn ($bit): string => $bit ? '1' : '0', $row));
        }
        return $rows;
    }

    private static function pending(): JsonStore
    {
        return new JsonStore(Config::ensureDataDir() . '/cp-enrol-pending.json');
    }

    private static function forget(string $pendingKey): void
    {
        self::pending()->update(static function (array &$data) use ($pendingKey): void {
            unset($data[$pendingKey]);
        });
    }

    private static function freshNonce(string $id, string $nonce): bool
    {
        return (new JsonStore(Config::ensureDataDir() . '/cp-enrol-nonces.json'))->update(static function (array &$data) use ($id, $nonce): bool {
            foreach ($data as $n => $at) {
                if ($at < time() - 600) {
                    unset($data[$n]);
                }
            }
            if (isset($data[$id . $nonce])) {
                return false;
            }
            $data[$id . $nonce] = time();
            return true;
        });
    }

    private static function raw(int $status, string $message): never
    {
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
        http_response_code($status);
        header('Content-Type: text/plain; charset=utf-8');
        echo $message;
        exit;
    }
}
