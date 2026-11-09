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
 * other code. If MULTIOTP_PORTAL_RELEASE_KEY (base64 public key) is set, the portal also
 * refuses to store a release whose signature does not verify.
 *
 * Storage: <data>/releases/releases.json and <data>/releases/<os>-<arch>-<version>.bin
 */
final class AgentReleases
{
    public const PLATFORMS = ['linux/amd64', 'linux/arm64', 'windows/amd64'];
    private const VERSION = '/^\d{1,4}\.\d{1,4}\.\d{1,4}$/';

    public static function dir(): string
    {
        $dir = Config::ensureDataDir() . '/releases';
        if (!is_dir($dir) && !@mkdir($dir, 0700) && !is_dir($dir)) {
            throw new \RuntimeException('Cannot create the releases folder.');
        }
        return $dir;
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
        $key = getenv('MULTIOTP_PORTAL_RELEASE_KEY') ?: '';
        if ('' !== $key) {
            $pub = base64_decode($key, true);
            if (false === $pub || SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen($pub) || !sodium_crypto_sign_verify_detached($signature, self::message($m), $pub)) {
                throw new ValidationException('The release signature does not verify with MULTIOTP_PORTAL_RELEASE_KEY.');
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
