<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Signed agent releases for self-update (stage 4d).
 *
 * Releases are signed OFFLINE with the release key (sohobotp-agent release sign); the portal
 * only stores and serves them through the signed agent API (a=release). Agents check the
 * signature against the release key built into them, so the portal cannot make them run
 * other code. When the portal knows the public release key (portal-admin.php release-key-set,
 * or MULTIOTP_PORTAL_RELEASE_KEY), it also refuses to store a release whose signature does
 * not verify, and shows which computers run an agent built with another key or none.
 *
 * Storage: <data>/releases/releases.json and <data>/releases/<os>-<arch>-<version>.bin
 */
final class AgentReleases
{
    public const PLATFORMS = ['linux/amd64', 'linux/arm64', 'windows/amd64', 'windows/arm64'];
    private const VERSION = '/^\d{1,4}\.\d{1,4}\.\d{1,4}$/';

    public static function dir(): string
    {
        $dir = Config::ensureDataDir() . '/releases';
        if (!is_dir($dir) && !@mkdir($dir, 0700) && !is_dir($dir)) {
            throw new \RuntimeException('Cannot create the releases folder.');
        }
        return $dir;
    }

    /**
     * The PUBLIC release key (base64) this portal checks uploads against: the environment
     * variable MULTIOTP_PORTAL_RELEASE_KEY, else <data>/releases/release-public.key
     * (portal-admin.php release-key-set). '' when none is set: uploads are stored unchecked
     * (agents check them anyway). The private key is never on the portal.
     */
    public static function releaseKey(): string
    {
        $key = trim((string) (getenv('MULTIOTP_PORTAL_RELEASE_KEY') ?: ''));
        if ('' === $key && is_file($file = Config::dataDir() . '/releases/release-public.key')) {
            $key = trim((string) @file_get_contents($file));
        }
        return $key;
    }

    public static function setReleaseKey(string $key): string
    {
        $key = trim($key);
        $raw = base64_decode($key, true);
        if (false === $raw || SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen($raw)) {
            throw new ValidationException('The release key must be the public key printed by "sohobotp-agent release keygen" (44 characters of base64).');
        }
        $file = self::dir() . '/release-public.key';
        if (false === file_put_contents($file, $key . "\n", LOCK_EX)) {
            throw new \RuntimeException('Cannot store the release key.');
        }
        @chmod($file, 0600);
        self::giveToWebUser();
        return self::fingerprint();
    }

    /** Short name of the release key, as agents report theirs (first 8 bytes of its SHA-256, hex). '' when none. */
    public static function fingerprint(): string
    {
        $raw = base64_decode(self::releaseKey(), true);
        return false !== $raw && SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES === strlen($raw) ? substr(hash('sha256', $raw), 0, 16) : '';
    }

    /**
     * portal-admin.php usually runs as root (docker exec): the releases folder and its files
     * then go to the owner of the data folder (the web server user), which serves them.
     */
    private static function giveToWebUser(): void
    {
        if (!function_exists('posix_geteuid') || 0 !== posix_geteuid() || false === ($owner = @fileowner(Config::dataDir()))) {
            return;
        }
        @chown(self::dir(), $owner);
        foreach (glob(self::dir() . '/*') ?: [] as $file) {
            @chown($file, $owner);
        }
    }

    private static function store(): JsonStore
    {
        return new JsonStore(self::dir() . '/releases.json');
    }

    public static function validVersion(string $version): bool
    {
        return 1 === preg_match(self::VERSION, $version);
    }

    /** Bytes covered by a release signature (same as the agent's release.Manifest.Message). */
    public static function message(array $m): string
    {
        return "sohobotp-release-v1\n{$m['os']}\n{$m['arch']}\n{$m['version']}\n" . strtolower($m['sha256']) . "\n{$m['size']}";
    }

    /** Store a signed binary. @return array the stored manifest */
    public static function add(string $file, array $manifest): array
    {
        $m = [
            'version' => (string) ($manifest['version'] ?? ''), 'os' => (string) ($manifest['os'] ?? ''),
            'arch' => (string) ($manifest['arch'] ?? ''), 'sha256' => strtolower((string) ($manifest['sha256'] ?? '')),
            'size' => (int) ($manifest['size'] ?? 0), 'signature' => (string) ($manifest['signature'] ?? ''),
        ];
        if (!self::validVersion($m['version']) || !in_array($m['os'] . '/' . $m['arch'], self::PLATFORMS, true)) {
            throw new ValidationException('The manifest needs a version x.y.z and a supported platform (' . implode(', ', self::PLATFORMS) . ').');
        }
        if (!is_file($file) || filesize($file) !== $m['size'] || hash_file('sha256', $file) !== $m['sha256']) {
            throw new ValidationException('The file does not match the manifest (size or SHA-256).');
        }
        $signature = base64_decode($m['signature'], true);
        if (false === $signature || SODIUM_CRYPTO_SIGN_BYTES !== strlen($signature)) {
            throw new ValidationException('The manifest has no valid signature.');
        }
        $key = self::releaseKey();
        if ('' !== $key) {
            $pub = base64_decode($key, true);
            if (false === $pub || SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen($pub) || !sodium_crypto_sign_verify_detached($signature, self::message($m), $pub)) {
                throw new ValidationException('The release signature does not verify with the release key of this portal (' . self::fingerprint() . ').');
            }
        }
        $target = self::dir() . "/{$m['os']}-{$m['arch']}-{$m['version']}.bin";
        if (!copy($file, $target)) {
            throw new \RuntimeException('Cannot store the release file.');
        }
        @chmod($target, 0600);
        $m['added_at'] = time();
        self::store()->update(static function (array &$data) use ($m): void {
            $data["{$m['os']}/{$m['arch']}/{$m['version']}"] = $m;
        });
        self::giveToWebUser();
        return $m;
    }

    /** @return list<array> newest version first */
    public static function all(): array
    {
        $list = array_values(self::store()->read());
        usort($list, static fn (array $a, array $b): int => version_compare($b['version'], $a['version']) ?: strcmp($a['os'] . $a['arch'], $b['os'] . $b['arch']));
        return $list;
    }

    /** @return list<string> distinct versions, newest first */
    public static function versions(): array
    {
        return array_values(array_unique(array_column(self::all(), 'version')));
    }

    public static function find(string $version, string $os, string $arch): ?array
    {
        return self::store()->read()["$os/$arch/$version"] ?? null;
    }

    public static function file(array $m): string
    {
        return self::dir() . "/{$m['os']}-{$m['arch']}-{$m['version']}.bin";
    }
}
