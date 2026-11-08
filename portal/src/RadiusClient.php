<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Minimal RADIUS client (RFC 2865 PAP + RFC 3579 Message-Authenticator) for the
 * diagnostics "test login": it talks to FreeRADIUS exactly like a VPN gateway would.
 */
final class RadiusClient
{
    public const ACCESS_REQUEST = 1;
    public const ACCESS_ACCEPT = 2;
    public const ACCESS_REJECT = 3;
    public const ACCESS_CHALLENGE = 11;

    private const USER_NAME = 1;
    private const USER_PASSWORD = 2;
    private const NAS_IP_ADDRESS = 4;
    private const REPLY_MESSAGE = 18;
    private const STATE = 24;
    private const NAS_IDENTIFIER = 32;
    private const MESSAGE_AUTHENTICATOR = 80;

    /**
     * @return array{result: string, code: int, reply_message: string, state: ?string, error: ?string}
     *   result: accepted | rejected | challenge | timeout | error
     */
    public static function authenticate(string $host, int $port, string $secret, string $user, string $password, string $sourceIp, int $timeout = 10, ?string $state = null): array
    {
        $id = random_int(0, 255);
        $authenticator = random_bytes(16);
        $attributes = self::attribute(self::USER_NAME, $user)
            . self::attribute(self::USER_PASSWORD, self::hidePassword($password, $secret, $authenticator))
            . self::attribute(self::NAS_IP_ADDRESS, (string) inet_pton($sourceIp))
            . self::attribute(self::NAS_IDENTIFIER, 'multiotp-portal-diagnostics');
        if (null !== $state) {
            $attributes .= self::attribute(self::STATE, $state);
        }
        $packet = self::packet(self::ACCESS_REQUEST, $id, $authenticator, $attributes, $secret);

        $context = stream_context_create(['socket' => ['bindto' => $sourceIp . ':0']]);
        $socket = @stream_socket_client("udp://$host:$port", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $context);
        if (false === $socket) {
            return self::outcome('error', 0, '', null, "Cannot open a UDP socket to $host:$port ($errstr).");
        }
        stream_set_timeout($socket, $timeout);
        fwrite($socket, $packet);
        $deadline = microtime(true) + $timeout;
        while (microtime(true) < $deadline) {
            $reply = fread($socket, 4096);
            $meta = stream_get_meta_data($socket);
            if (false === $reply || '' === $reply) {
                if ($meta['timed_out']) {
                    break;
                }
                usleep(50_000); // e.g. ICMP port unreachable: retry until the deadline without spinning
                continue;
            }
            if (strlen($reply) < 20 || ord($reply[1]) !== $id) {
                continue; // not our answer
            }
            fclose($socket);
            return self::parseReply($reply, $authenticator, $secret);
        }
        fclose($socket);
        return self::outcome('timeout', 0, '', null, 'No answer from FreeRADIUS. Is it running, and is the diagnostics client applied?');
    }

    /** RFC 2865 5.2: User-Password hiding. */
    public static function hidePassword(string $password, string $secret, string $authenticator): string
    {
        $padded = str_pad($password, max(16, (int) ceil(strlen($password) / 16) * 16), "\0");
        $result = '';
        $previous = $authenticator;
        foreach (str_split($padded, 16) as $block) {
            $cipher = $block ^ md5($secret . $previous, true);
            $result .= $cipher;
            $previous = $cipher;
        }
        return substr($result, 0, 128);
    }

    /** Build a packet whose Message-Authenticator (HMAC-MD5 over the packet) comes first. */
    private static function packet(int $code, int $id, string $authenticator, string $attributes, string $secret): string
    {
        $withPlaceholder = self::attribute(self::MESSAGE_AUTHENTICATOR, str_repeat("\0", 16)) . $attributes;
        $length = 20 + strlen($withPlaceholder);
        $unsigned = chr($code) . chr($id) . pack('n', $length) . $authenticator . $withPlaceholder;
        $mac = hash_hmac('md5', $unsigned, $secret, true);
        return substr_replace($unsigned, $mac, 22, 16);
    }

    private static function attribute(int $type, string $value): string
    {
        return chr($type) . chr(2 + strlen($value)) . $value;
    }

    private static function parseReply(string $reply, string $requestAuthenticator, string $secret): array
    {
        $code = ord($reply[0]);
        $length = unpack('n', substr($reply, 2, 2))[1];
        if ($length > strlen($reply) || $length < 20) {
            return self::outcome('error', $code, '', null, 'Malformed RADIUS answer.');
        }
        $reply = substr($reply, 0, $length);
        $expected = md5(substr($reply, 0, 4) . $requestAuthenticator . substr($reply, 20) . $secret, true);
        if (!hash_equals($expected, substr($reply, 4, 16))) {
            return self::outcome('error', $code, '', null, 'The answer failed the RADIUS authenticator check (wrong shared secret?).');
        }
        $messages = [];
        $state = null;
        $offset = 20;
        while ($offset + 2 <= $length) {
            $type = ord($reply[$offset]);
            $len = ord($reply[$offset + 1]);
            if ($len < 2) {
                break;
            }
            $value = substr($reply, $offset + 2, $len - 2);
            if (self::REPLY_MESSAGE === $type) {
                $messages[] = $value;
            } elseif (self::STATE === $type) {
                $state = $value;
            }
            $offset += $len;
        }
        $result = match ($code) {
            self::ACCESS_ACCEPT    => 'accepted',
            self::ACCESS_REJECT    => 'rejected',
            self::ACCESS_CHALLENGE => 'challenge',
            default                => 'error',
        };
        return self::outcome($result, $code, implode(' ', $messages), $state, 'error' === $result ? "Unexpected RADIUS code $code." : null);
    }

    private static function outcome(string $result, int $code, string $message, ?string $state, ?string $error): array
    {
        return ['result' => $result, 'code' => $code, 'reply_message' => $message, 'state' => $state, 'error' => $error];
    }
}
