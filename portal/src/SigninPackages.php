<?php

declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * The installers the agent installs by itself on Windows (computer policy "Install and update
 * SohobOTP Sign-in automatically"): SohobOTP Sign-in for each processor, and the Visual C++ x64
 * runtime its PHP engine needs. An administrator adds them once (portal-admin.php
 * signin-package-add); a newer Sign-in added later updates every such computer at its next
 * check-in, because the policy names each installer by version, size and SHA-256 (the agent
 * checks the download against them; the policy is signed by the portal key).
 *
 * <data>/signin-packages/: signin-amd64.msi, signin-arm64.msi, vc_redist.x64.exe, manifest.json
 */
final class SigninPackages
{
    public const KINDS = [
        'signin/amd64' => ['file' => 'signin-amd64.msi', 'label' => 'SohobOTP Sign-in (Windows Intel/AMD)'],
        'signin/arm64' => ['file' => 'signin-arm64.msi', 'label' => 'SohobOTP Sign-in (Windows on ARM)'],
        'vcredist'     => ['file' => 'vc_redist.x64.exe', 'label' => 'Visual C++ runtime x64'],
    ];
    private const MSI_MAGIC = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";
    private const MAX_SIZE = 200 * 1024 * 1024;

    public static function dir(): string
    {
        return Config::dataDir() . '/signin-packages';
    }

    /** @return array<string, array{version: string, sha256: string, size: int, added_at: int, file: string}> present installers */
    public static function all(): array
    {
        if (!is_file(self::dir() . '/manifest.json')) {
            return []; // none added yet (the folder does not exist)
        }
        $manifest = (new JsonStore(self::dir() . '/manifest.json'))->read();
        $out = [];
        foreach (self::KINDS as $kind => $meta) {
            $entry = $manifest[$kind] ?? null;
            $file = self::dir() . '/' . $meta['file'];
            if (is_array($entry) && is_file($file) && (int) filesize($file) === (int) ($entry['size'] ?? -1)) {
                $out[$kind] = ['version' => (string) $entry['version'], 'sha256' => (string) $entry['sha256'], 'size' => (int) $entry['size'],
                    'added_at' => (int) ($entry['added_at'] ?? 0), 'file' => $file];
            }
        }
        return $out;
    }

    /** The part of the Windows policy that names the installers (empty when none was added). */
    public static function policy(): array
    {
        $all = self::all();
        $signin = [];
        foreach (['amd64', 'arm64'] as $arch) {
            if (isset($all["signin/$arch"])) {
                $signin[$arch] = self::entry($all["signin/$arch"]);
            }
        }
        if ([] === $signin) {
            return [];
        }
        return ['signin_packages' => $signin] + (isset($all['vcredist']) ? ['vcredist' => self::entry($all['vcredist'])] : []);
    }

    /** @param array{version: string, sha256: string, size: int} $p */
    private static function entry(array $p): array
    {
        return ['version' => $p['version'], 'sha256' => $p['sha256'], 'size' => $p['size']];
    }

    /** The file an agent asked for, when it is the one the policy names (same SHA-256). */
    public static function file(string $kind, string $sha256): ?string
    {
        $p = self::all()[$kind] ?? null;
        return null !== $p && hash_equals($p['sha256'], strtolower($sha256)) ? $p['file'] : null;
    }

    /** FileVersion from a Windows program's version resource (vc_redist.x64.exe), or ''. */
    public static function fileVersion(string $file): string
    {
        $data = (string) @file_get_contents($file, false, null, 0, 64 * 1024 * 1024);
        $key = mb_convert_encoding("FileVersion\0", 'UTF-16LE', 'UTF-8');
        $at = strrpos($data, $key);
        if (false === $at) {
            return '';
        }
        $at += strlen($key);
        while ($at + 1 < strlen($data) && "\0\0" === substr($data, $at, 2)) {
            $at += 2; // padding to the value
        }
        $value = '';
        for (; $at + 1 < strlen($data) && "\0\0" !== substr($data, $at, 2) && strlen($value) < 40; $at += 2) {
            $value .= substr($data, $at, 2);
        }
        $version = trim((string) mb_convert_encoding($value, 'UTF-8', 'UTF-16LE'));
        return preg_match('/^\d{1,5}(\.\d{1,5}){1,3}$/', $version) ? $version : '';
    }

    /** @return array{kind: string, version: string, sha256: string, size: int} */
    public static function add(string $file, string $kind, string $version): array
    {
        if ('' === $version && 'vcredist' === $kind) {
            $version = self::fileVersion($file); // Microsoft's installer carries its version
        }
        if (!isset(self::KINDS[$kind])) {
            throw new ValidationException('Kinds: ' . implode(', ', array_keys(self::KINDS)) . '.');
        }
        if (!preg_match('/^\d{1,5}(\.\d{1,5}){1,3}$/', $version)) {
            throw new ValidationException('Version: numbers and dots, like 1.0.2.0.');
        }
        $size = is_file($file) ? (int) filesize($file) : 0;
        if ($size < 100_000 || $size > self::MAX_SIZE) {
            throw new ValidationException('The file is not an installer (100 KB to 200 MB expected).');
        }
        $head = (string) file_get_contents($file, false, null, 0, 8);
        if ('vcredist' === $kind ? !str_starts_with($head, 'MZ') : self::MSI_MAGIC !== $head) {
            throw new ValidationException('vcredist' === $kind ? 'Not a Windows program (vc_redist.x64.exe expected).' : 'Not a Windows Installer package (.msi).');
        }
        $dir = self::dir();
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new \RuntimeException('Cannot create the installers folder.');
        }
        $target = $dir . '/' . self::KINDS[$kind]['file'];
        if (!copy($file, "$target.new") || !rename("$target.new", $target)) {
            throw new \RuntimeException('Cannot store the installer.');
        }
        @chmod($target, 0600);
        $sha = (string) hash_file('sha256', $target);
        $store = new JsonStore($dir . '/manifest.json');
        $store->update(static function (array &$m) use ($kind, $version, $sha, $size): void {
            $m[$kind] = ['version' => $version, 'sha256' => $sha, 'size' => $size, 'added_at' => time()];
        });
        // portal-admin.php runs as root (docker exec): the web server user must read them
        if (function_exists('posix_geteuid') && 0 === posix_geteuid() && false !== ($owner = @fileowner(Config::dataDir()))) {
            foreach ([$dir, $target, "$dir/manifest.json", "$dir/manifest.json.lock"] as $path) {
                if (file_exists($path)) {
                    @chown($path, $owner);
                }
            }
        }
        return ['kind' => $kind, 'version' => $version, 'sha256' => $sha, 'size' => $size];
    }
}
