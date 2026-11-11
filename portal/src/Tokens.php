<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/** Hardware tokens known to multiOTP (imported from PSKC, CSV, Yubico, Authenex... files). */
final class Tokens
{
    private \Multiotp $engine;

    public function __construct()
    {
        $this->engine = MultiotpService::get();
    }

    /** @return list<array{serial: string, manufacturer: string, algorithm: string, digits: int, description: string, users: list<string>}> */
    public function all(): array
    {
        $tokens = [];
        foreach (explode("\t", (string) $this->engine->GetTokensList()) as $serial) {
            if ('' === trim($serial) || !$this->engine->ReadTokenData($serial)) {
                continue;
            }
            $tokens[] = [
                'serial'       => $serial,
                'manufacturer' => (string) $this->engine->GetTokenManufacturer(),
                'algorithm'    => (string) $this->engine->GetTokenAlgorithm(),
                'digits'       => (int) $this->engine->GetTokenNumberOfDigits(),
                'description'  => (string) $this->engine->GetTokenDescription(),
                'users'        => array_values(array_filter(explode(',', (string) $this->engine->GetTokenAttributedUsers()), 'strlen')),
            ];
        }
        return $tokens;
    }

    /**
     * Import a token file using the engine's importers (format detected from the content and name).
     * @return list<string> imported serial numbers
     */
    public function import(string $path, string $originalName, string $password): array
    {
        $before = array_column($this->all(), 'serial');
        $this->engine->ResetLastImportedTokensArray();
        if (!$this->engine->ImportTokensFile($path, $originalName, $password)) {
            throw new ValidationException('The file could not be imported. Check the format and, for encrypted PSKC files, the password.');
        }
        $imported = array_values(array_diff(array_column($this->all(), 'serial'), $before));
        return [] !== $imported ? $imported : array_values(array_map('strval', (array) $this->engine->GetLastImportedTokens()));
    }

    public function delete(string $serial): void
    {
        foreach ($this->all() as $token) {
            if ($token['serial'] === $serial) {
                if ([] !== $token['users']) {
                    throw new ValidationException('This token is assigned to ' . implode(', ', $token['users']) . '. Remove it from the user first.');
                }
                if (!$this->engine->DeleteToken($serial)) {
                    throw new \RuntimeException('SohobOTP could not delete the token.');
                }
                return;
            }
        }
        throw new ValidationException('This token does not exist.');
    }
}
