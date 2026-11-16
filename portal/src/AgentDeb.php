<?php

declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * "Add a computer" for Debian and Ubuntu: a .deb package around the downloaded agent (the
 * program with its enrolment settings built in, AgentBundle), so a machine enrols with
 *
 *   sudo apt install ./sohobotp-agent-<token id>_<arch>.deb
 *
 * The package carries the downloaded agent as /var/lib/sohobotp-agent/setup (root only). Its
 * postinst runs "setup install": the agent enrols, installs itself as the plain program
 * (/usr/local/sbin/sohobotp-agent, without the token) and starts its systemd service; then the
 * setup file is deleted, so the token does not stay on the machine. When enrolment fails (portal
 * unreachable, token expired) the package stays unconfigured and "sudo dpkg --configure -a"
 * tries again. Removing the package runs "sohobotp-agent uninstall" (PAM changes, service, state).
 *
 * Built for each download, in memory, never stored: Debian's format is an ar archive with
 * "debian-binary", control.tar.gz and data.tar.gz (deb(5)), written here without dpkg.
 */
final class AgentDeb
{
    public const PACKAGE = 'sohobotp-agent';
    private const SETUP = 'var/lib/sohobotp-agent/setup';
    private const ARCH = ['amd64' => 'amd64', 'arm64' => 'arm64'];

    /** The .deb file name for a download. */
    public static function fileName(string $tokenId, string $arch): string
    {
        return self::PACKAGE . '-' . preg_replace('/[^A-Za-z0-9]/', '', $tokenId) . '_' . self::ARCH[$arch] . '.deb';
    }

    /**
     * @param string $program the plain agent program (file)
     * @param string $trailer the settings block (AgentBundle::trailer)
     * @param string $version agent version when known ('' otherwise)
     */
    public static function build(string $program, string $trailer, string $arch, string $version, int $now): string
    {
        if (!isset(self::ARCH[$arch])) {
            throw new ValidationException('Debian packages: amd64 or arm64.');
        }
        $agent = (string) file_get_contents($program) . $trailer;
        // Debian version: the agent's, else a date (a later download sorts later)
        $debVersion = preg_match('/^\d+\.\d+\.\d+$/', $version) ? $version : '0.0.' . gmdate('YmdHis', $now);
        $control = implode("\n", [
            'Package: ' . self::PACKAGE,
            'Version: ' . $debVersion,
            'Architecture: ' . self::ARCH[$arch],
            'Maintainer: Sohobcom <support@sohobcom.invalid>',
            'Installed-Size: ' . (int) ceil(strlen($agent) / 1024),
            'Depends: systemd',
            'Section: admin',
            'Priority: optional',
            'Description: SohobOTP agent (two-factor sign-in for this computer)',
            ' Enrols this computer with the SohobOTP portal it was downloaded from and keeps',
            ' its sign-in policy (SSH, sudo, console) up to date.',
        ]) . "\n";
        $setup = '/' . self::SETUP;
        $postinst = <<<SH
#!/bin/sh
# SohobOTP agent: enrol with the settings built into the download, then delete it (token)
set -e
if [ "\$1" = configure ] && [ -f $setup ]; then
    if /usr/local/sbin/sohobotp-agent status >/dev/null 2>&1; then
        echo "SohobOTP agent already enrolled: the settings in this package are not used."
    else
        $setup install
    fi
    rm -f $setup
fi
exit 0

SH;
        $prerm = <<<SH
#!/bin/sh
# SohobOTP agent: on removal, undo the PAM changes and remove the service and the agent state
set -e
if [ "\$1" = remove ] && [ -x /usr/local/sbin/sohobotp-agent ]; then
    # a computer with tamper protection needs its uninstall code (portal: Computers, the computer):
    #   sudo SOHOBOTP_UNINSTALL_CODE=XXXX-XXXX-XXXX apt remove sohobotp-agent
    /usr/local/sbin/sohobotp-agent uninstall \${SOHOBOTP_UNINSTALL_CODE:+--code "\$SOHOBOTP_UNINSTALL_CODE"} || echo "sohobotp-agent uninstall failed: the agent is still installed; run 'sohobotp-agent uninstall' by hand (with --code CODE on a computer with tamper protection)" >&2
fi
exit 0

SH;
        $controlTar = self::tar([
            ['./', null, 0755],
            ['./control', $control, 0644],
            ['./postinst', $postinst, 0755],
            ['./prerm', $prerm, 0755],
        ], $now);
        $dataTar = self::tar([
            ['./', null, 0755],
            ['./var/', null, 0755],
            ['./var/lib/', null, 0755],
            ['./var/lib/sohobotp-agent/', null, 0700],
            ['./' . self::SETUP, $agent, 0700],
        ], $now);
        return "!<arch>\n"
            . self::arMember('debian-binary', "2.0\n", $now)
            . self::arMember('control.tar.gz', (string) gzencode($controlTar, 9), $now)
            . self::arMember('data.tar.gz', (string) gzencode($dataTar, 6), $now);
    }

    private static function arMember(string $name, string $data, int $now): string
    {
        $header = str_pad($name, 16) . str_pad((string) $now, 12) . str_pad('0', 6) . str_pad('0', 6)
            . str_pad('100644', 8) . str_pad((string) strlen($data), 10) . "`\n";
        return $header . $data . (1 === strlen($data) % 2 ? "\n" : '');
    }

    /**
     * POSIX ustar archive, owned by root. Entries: [path, content or null for a directory, mode].
     * @param list<array{0: string, 1: ?string, 2: int}> $entries
     */
    private static function tar(array $entries, int $now): string
    {
        $out = '';
        foreach ($entries as [$path, $content, $mode]) {
            if (strlen($path) > 99) {
                throw new \LogicException('tar path too long: ' . $path);
            }
            $isDir = null === $content;
            $size = $isDir ? 0 : strlen((string) $content);
            $header = str_pad($path, 100, "\0")
                . sprintf('%07o', $mode) . "\0"
                . sprintf('%07o', 0) . "\0" . sprintf('%07o', 0) . "\0"
                . sprintf('%011o', $size) . "\0"
                . sprintf('%011o', $now) . "\0"
                . str_repeat(' ', 8)                      // checksum, computed below
                . ($isDir ? '5' : '0')
                . str_repeat("\0", 100)                   // link name
                . "ustar\0" . '00'
                . str_pad('root', 32, "\0") . str_pad('root', 32, "\0")
                . str_repeat("\0", 16)                    // device numbers
                . str_repeat("\0", 155);                  // prefix
            $header = str_pad($header, 512, "\0");
            $sum = array_sum(array_map('ord', str_split($header)));
            $header = substr_replace($header, sprintf('%06o', $sum) . "\0 ", 148, 8);
            $out .= $header;
            if (!$isDir) {
                $out .= $content . str_repeat("\0", (512 - $size % 512) % 512);
            }
        }
        return $out . str_repeat("\0", 1024);
    }
}
