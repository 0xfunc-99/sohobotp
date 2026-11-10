<?php
/**
 * Stand-in for a Symantec VIP Enterprise Gateway validation server, for the appliance test
 * (portal/tests/appliance-vip.php). A minimal RADIUS server (RFC 2865 PAP, RFC 3579
 * Message-Authenticator in every answer):
 *
 *   php fake-vip-radius.php <port> <secret> <counter file>
 *
 *   vip.only / VipPass-123456        Access-Accept, Reply-Message "Symantec VIP accepted"
 *   vip.challenge / VipPass-123456   Access-Challenge "Enter your VIP security code" + State,
 *                                    then the same user with that State and 246810: Accept
 *   anything else                    Access-Reject
 *
 * Every request received increments the counter file (the test checks who was forwarded)
 * and appends the user name to <counter file>.users.
 */
declare(strict_types=1);

[$port, $secret, $counter] = [(int) ($argv[1] ?? 18120), (string) ($argv[2] ?? ''), (string) ($argv[3] ?? '')];
$socket = stream_socket_server("udp://127.0.0.1:$port", $errno, $errstr, STREAM_SERVER_BIND);
if (false === $socket) {
    fwrite(STDERR, "cannot listen: $errstr\n");
    exit(1);
}
file_put_contents($counter, '0');
$states = [];

$attr = static fn (int $type, string $value): string => chr($type) . chr(2 + strlen($value)) . $value;

while (true) {
    $packet = stream_socket_recvfrom($socket, 4096, 0, $peer);
    if (false === $packet || strlen($packet) < 20 || 1 !== ord($packet[0])) {
        continue;
    }
    $id = ord($packet[1]);
    $authenticator = substr($packet, 4, 16);
    $length = min(strlen($packet), unpack('n', substr($packet, 2, 2))[1]);
    $user = $hidden = $state = '';
    for ($o = 20; $o + 2 <= $length;) {
        $t = ord($packet[$o]);
        $l = ord($packet[$o + 1]);
        if ($l < 2) {
            break;
        }
        $v = substr($packet, $o + 2, $l - 2);
        match ($t) { 1 => $user = $v, 2 => $hidden = $v, 24 => $state = $v, default => null };
        $o += $l;
    }
    $password = '';
    $previous = $authenticator;
    foreach (str_split($hidden, 16) as $block) {
        $password .= $block ^ md5($secret . $previous, true);
        $previous = $block;
    }
    $password = rtrim($password, "\0");
    file_put_contents($counter, (string) ((int) file_get_contents($counter) + 1));
    file_put_contents($counter . '.users', $user . "\n", FILE_APPEND);

    $code = 3;
    $attributes = '';
    if ('vip.only' === $user && 'VipPass-123456' === $password) {
        $code = 2;
        $attributes = $attr(18, 'Symantec VIP accepted');
    } elseif ('vip.challenge' === $user && '' === $state && 'VipPass-123456' === $password) {
        $code = 11;
        $token = random_bytes(16);
        $states[$token] = true;
        $attributes = $attr(18, 'Enter your VIP security code') . $attr(24, $token);
    } elseif ('vip.challenge' === $user && isset($states[$state]) && '246810' === $password) {
        unset($states[$state]);
        $code = 2;
        $attributes = $attr(18, 'Symantec VIP accepted after challenge');
    }
    // Message-Authenticator first (HMAC-MD5 with the request authenticator), then the
    // Response Authenticator over the final packet
    $body = $attr(80, str_repeat("\0", 16)) . $attributes;
    $reply = chr($code) . chr($id) . pack('n', 20 + strlen($body)) . $authenticator . $body;
    $reply = substr_replace($reply, hash_hmac('md5', $reply, $secret, true), 22, 16);
    $reply = substr_replace($reply, md5(substr($reply, 0, 4) . $authenticator . substr($reply, 20) . $secret, true), 4, 16);
    stream_socket_sendto($socket, $reply, 0, $peer);
}
