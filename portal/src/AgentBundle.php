<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * "Download agent": the agent program with its enrolment settings built in (portal address,
 * a new enrolment token, the portal key pin and the portal's CA certificate), so a machine
 * enrols by running the download, without options or a separate certificate file.
 *
 * Nothing is compiled: the settings are appended to the program, which finds them at its own
 * end (agent/internal/bundle):
 *
 *   program | settings (JSON) | SHA-256 of the settings (32) | settings length (4, big endian) | "SOHOBOTP-BUNDLE1"
 *
 * The download contains a usable token: it is built for one request, never stored, and the
 * installed agent does not keep the settings.
 *
 * Agent programs come from the newest signed release (AgentReleases), else from the programs
 * folder: <data>/agent-programs (portal-admin.php agent-program-add), else the folder shipped
 * with the appliance (/usr/local/share/sohobotp/agent-programs).
 */
final class AgentBundle
{
    public const MAGIC = 'SOHOBOTP-BUNDLE1';
    public const MAX_SETTINGS = 262144;
    public const PLATFORMS = [
        'windows/amd64' => 'Windows (64-bit)',
        'linux/amd64'   => 'Linux (Intel/AMD, 64-bit)',
        'linux/arm64'   => 'Linux (ARM 64-bit, Raspberry Pi)',
    ];
    private const SHIPPED = '/usr/local/share/sohobotp/agent-programs';

    public static function programsDir(): string
    {
        return Config::dataDir() . '/agent-programs';
    }

    public static function programName(string $os, string $arch): string
    {
        return "sohobotp-agent-$os-$arch" . ('windows' === $os ? '.exe' : '');
    }

    /**
     * The agent program the portal can give for a platform.
     * @return ?array{file: string, source: string, version: string, size: int}
     */
    public static function program(string $platform): ?array
    {
        if (!isset(self::PLATFORMS[$platform])) {
            return null;
        }
        [$os, $arch] = explode('/', $platform);
        foreach (AgentReleases::all() as $m) { // newest first
            if ($m['os'] === $os && $m['arch'] === $arch && is_file(AgentReleases::file($m))) {
                return ['file' => AgentReleases::file($m), 'source' => 'signed release', 'version' => $m['version'], 'size' => (int) $m['size']];
            }
        }
        $dirs = [self::programsDir() => 'added by an administrator', (getenv('MULTIOTP_PORTAL_AGENT_DIR') ?: self::SHIPPED) => 'shipped with the portal'];
        foreach ($dirs as $dir => $source) {
            $file = $dir . '/' . self::programName($os, $arch);
            if (is_file($file) && is_readable($file) && null === self::programError($file, $os)) {
                return ['file' => $file, 'source' => $source, 'version' => '', 'size' => (int) filesize($file)];
            }
        }
        return null;
    }

    /** Why a file is not an agent program for this system, or null. */
    public static function programError(string $file, string $os): ?string
    {
        $size = @filesize($file);
        if (false === $size || $size < 1_000_000 || $size > 100_000_000) {
            return 'The file is not an agent program (1 to 100 MB expected).';
        }
        $handle = @fopen($file, 'rb');
        if (false === $handle) {
            return 'The file cannot be read.';
        }
        $head = (string) fread($handle, 4);
        fseek($handle, -strlen(self::MAGIC), SEEK_END);
        $tail = (string) fread($handle, strlen(self::MAGIC));
        fclose($handle);
        if ('windows' === $os ? !str_starts_with($head, 'MZ') : "\x7fELF" !== $head) {
            return 'windows' === $os ? 'Not a Windows program (.exe).' : 'Not a Linux program.';
        }
        if (self::MAGIC === $tail) {
            return 'This file is a downloaded agent with settings built in: add the plain agent program.';
        }
        return null;
    }

    /** Store a plain agent program (CLI agent-program-add). @return array{file: string, sha256: string, size: int} */
    public static function addProgram(string $file, string $os, string $arch): array
    {
        if (!isset(self::PLATFORMS["$os/$arch"])) {
            throw new ValidationException('Supported platforms: ' . implode(', ', array_keys(self::PLATFORMS)) . '.');
        }
        if (!is_file($file) || null !== ($error = self::programError($file, $os))) {
            throw new ValidationException($error ?? 'File not found.');
        }
        $dir = self::programsDir();
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new \RuntimeException('Cannot create the agent programs folder.');
        }
        $target = $dir . '/' . self::programName($os, $arch);
        if (!copy($file, "$target.new") || !rename("$target.new", $target)) {
            throw new \RuntimeException('Cannot store the agent program.');
        }
        @chmod($target, 0600);
        return ['file' => $target, 'sha256' => (string) hash_file('sha256', $target), 'size' => (int) filesize($target)];
    }

    /**
     * The CA certificate agents need for this portal, when it is not publicly trusted:
     * <data>/agent-ca.pem if an administrator put one there, else the portal's own
     * certificate when it is self-signed (appliance default). '' otherwise.
     */
    public static function detectCa(): string
    {
        $own = Config::dataDir() . '/agent-ca.pem';
        if (is_file($own)) {
            try {
                return self::validateCa((string) file_get_contents($own));
            } catch (ValidationException) {
                return '';
            }
        }
        $cert = @file_get_contents(Config::etcDir() . '/certificates/multiotp.crt');
        if (false === $cert || !function_exists('openssl_x509_parse')) {
            return '';
        }
        $parsed = @openssl_x509_parse($cert);
        if (!is_array($parsed) || ($parsed['subject'] ?? null) != ($parsed['issuer'] ?? [])) {
            return '';
        }
        try {
            return self::validateCa($cert);
        } catch (ValidationException) {
            return '';
        }
    }

    /** One or more PEM certificates, normalised; '' stays '' (publicly trusted certificate). */
    public static function validateCa(string $pem): string
    {
        $pem = trim(str_replace("\r", '', $pem));
        if ('' === $pem) {
            return '';
        }
        if (strlen($pem) > 65536 || !preg_match_all('/-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+\/=\n]+\n-----END CERTIFICATE-----/', $pem, $blocks)) {
            throw new ValidationException('The CA certificate must be in PEM format (-----BEGIN CERTIFICATE-----).');
        }
        if (trim((string) preg_replace('/-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+\/=\n]+\n-----END CERTIFICATE-----/', '', $pem)) !== '') {
            throw new ValidationException('The CA certificate field must contain certificates only (no private key, no other text).');
        }
        foreach ($blocks[0] as $block) {
            if (function_exists('openssl_x509_read') && false === @openssl_x509_read($block)) {
                throw new ValidationException('A certificate in the CA field cannot be read.');
            }
        }
        return implode("\n", $blocks[0]) . "\n";
    }

    /** https://host[:port], as the machines will reach the portal. */
    public static function validatePortal(string $url): string
    {
        $url = rtrim(trim($url), '/');
        if (!preg_match('/^https:\/\/(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)(:\d{1,5})?$/', $url)) {
            throw new ValidationException('The portal address must look like https://otp.example.com or https://192.168.1.50.');
        }
        return strtolower($url);
    }

    /** The bytes to append to the program. */
    public static function trailer(string $portal, string $token, string $pin, string $caPem): string
    {
        $settings = ['v' => 1, 'portal' => $portal, 'token' => $token, 'pin' => $pin];
        if ('' !== $caPem) {
            $settings['ca_pem'] = $caPem;
        }
        $json = (string) json_encode($settings, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        if (strlen($json) > self::MAX_SETTINGS) {
            throw new ValidationException('The CA certificate is too large.');
        }
        return $json . hash('sha256', $json, true) . pack('N', strlen($json)) . self::MAGIC;
    }
}
