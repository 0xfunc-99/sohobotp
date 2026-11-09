<?php
/**
 * A minimal endpoint agent written from docs/agent-protocol.md (not from the portal code),
 * used by the unit, end-to-end and appliance tests.
 */
declare(strict_types=1);

final class AgentSim
{
    public string $sign;
    public string $box;
    public ?string $id = null;

    public function __construct()
    {
        $this->sign = sodium_crypto_sign_keypair();
        $this->box = sodium_crypto_box_keypair();
    }

    public function enrollRequest(string $token, array $inventory): array
    {
        $signPub = base64_encode(sodium_crypto_sign_publickey($this->sign));
        $boxPub = base64_encode(sodium_crypto_box_publickey($this->box));
        $proof = sodium_crypto_sign_detached("multiotp-agent-enroll-v1\n$token\n$signPub\n$boxPub", sodium_crypto_sign_secretkey($this->sign));
        return ['token' => $token, 'sign_key' => $signPub, 'box_key' => $boxPub, 'proof' => base64_encode($proof), 'inventory' => $inventory];
    }

    /** Signature headers, lower-case names. */
    public function headers(string $method, string $uri, string $body, ?int $time = null, ?string $nonce = null): array
    {
        $time = (string) ($time ?? time());
        $nonce ??= base64_encode(random_bytes(16));
        $message = "multiotp-agent-v1\n$method\n$uri\n$time\n$nonce\n" . hash('sha256', $body);
        return [
            'x-agent-id' => (string) $this->id,
            'x-agent-time' => $time,
            'x-agent-nonce' => $nonce,
            'x-agent-signature' => base64_encode(sodium_crypto_sign_detached($message, sodium_crypto_sign_secretkey($this->sign))),
        ];
    }

    /**
     * Verify and open a configuration envelope like the real agent must.
     * @return array the payload with secrets in clear
     */
    public function openConfig(array $envelope, string $portalPublicKey, int $lastApplied = 0, string $os = ''): array
    {
        $payload = base64_decode((string) ($envelope['payload'] ?? ''), true);
        $signature = base64_decode((string) ($envelope['signature'] ?? ''), true);
        if (false === $payload || false === $signature || 64 !== strlen($signature)
            || !sodium_crypto_sign_verify_detached($signature, "multiotp-config-v1\n" . $payload, $portalPublicKey)) {
            throw new RuntimeException('bad config signature');
        }
        $config = json_decode($payload, true, 512, JSON_THROW_ON_ERROR);
        if ($config['endpoint_id'] !== $this->id) {
            throw new RuntimeException('config for another endpoint');
        }
        if ('' !== $os && $config['os'] !== $os) {
            throw new RuntimeException('config for another OS');
        }
        if ($config['version'] <= $lastApplied) {
            throw new RuntimeException('config version replay or rollback');
        }
        foreach ($config['secrets'] as $name => $sealed) {
            $plain = sodium_crypto_box_seal_open((string) base64_decode($sealed, true), $this->box);
            if (false === $plain) {
                throw new RuntimeException("secret $name does not open");
            }
            $config['secrets'][$name] = $plain;
        }
        return $config;
    }
}
