<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * The multiOTP engine encrypts token seeds, PINs, RADIUS device secrets and passwords in its
 * settings with an "encryption key". Out of the box that key is a constant published in the
 * open-source code ("DefaultCliEncryptionKey"), so a copy of the users folder or of the
 * database was enough to clone every authenticator.
 *
 * protect() gives the engine a private random key: it writes the key file, re-encrypts every
 * user, token, RADIUS device and group (files or MariaDB) and the engine settings, then points
 * the settings at the key file (encryption_key_full_path), where the engine — also the copy run
 * by FreeRADIUS — reads it. Safe to run again: records already using the new key are skipped.
 *
 * The HA secondary adopts the primary's key (pairing code), because it reads the same database.
 */
final class EngineKey
{
    public const PUBLIC_KEYS = ['', 'DefaultCliEncryptionKey', 'MuLtIoTpEnCrYpTiOn'];

    public static function path(): string
    {
        return Config::etcDir() . '/engine.key';
    }

    /** True while the engine still uses a key published in the multiOTP source. */
    public static function isPublic(?\Multiotp $engine = null): bool
    {
        $engine ??= MultiotpService::get();
        return in_array((string) $engine->GetEncryptionKey(), self::PUBLIC_KEYS, true);
    }

    /** The current private key (for the HA pairing code), or null while the public key is in use. */
    public static function current(): ?string
    {
        $engine = MultiotpService::get();
        return self::isPublic($engine) ? null : (string) $engine->GetEncryptionKey();
    }

    /**
     * Switch the engine to a private key ($adopt: use this key, e.g. the HA primary's).
     * @return array{changed: bool, users: int, tokens: int, devices: int, groups: int, failed: list<string>}
     */
    public static function protect(?string $adopt = null): array
    {
        if (null !== $adopt && !preg_match('/^[0-9a-f]{64}$/', $adopt)) {
            throw new ValidationException('The engine key must be 64 hexadecimal characters.');
        }
        $summary = ['changed' => false, 'users' => 0, 'tokens' => 0, 'devices' => 0, 'groups' => 0, 'failed' => []];
        $lock = fopen(Config::etcDir() . '/engine.key.lock', 'c');
        if (false === $lock || !flock($lock, LOCK_EX)) {
            throw new \RuntimeException('Cannot lock the engine key.');
        }
        try {
            $engine = MultiotpService::create(false);
            $old = (string) $engine->GetEncryptionKey();
            if (!self::isPublic($engine) && (null === $adopt || hash_equals($old, $adopt))) {
                return $summary; // already private
            }
            $new = $adopt ?? bin2hex(random_bytes(32));

            // 1. the key file first: if anything below stops, running again finishes the job
            $file = self::path();
            $tmp = $file . '.' . bin2hex(random_bytes(4)) . '.tmp';
            if (false === file_put_contents($tmp, $new . "\n") || !@chmod($tmp, 0644) || !rename($tmp, $file)) {
                @unlink($tmp);
                throw new \RuntimeException('Cannot write the engine key file ' . $file . '.');
            }

            // 2. every record: read with the old key, write with the new one
            $kinds = [
                'users'   => ['GetUsersList', static fn (\Multiotp $e, string $id): bool => (bool) $e->ReadUserData($id, false, true), static fn (\Multiotp $e): bool => (bool) $e->WriteUserData(false, false)],
                'tokens'  => ['GetTokensList', static fn (\Multiotp $e, string $id): bool => (bool) $e->ReadTokenData($id), static fn (\Multiotp $e): bool => (bool) $e->WriteTokenData()],
                'devices' => ['GetDevicesList', static fn (\Multiotp $e, string $id): bool => (bool) $e->ReadDeviceData($id), static fn (\Multiotp $e): bool => (bool) $e->WriteDeviceData(['with_radius_update' => false])],
                'groups'  => ['GetGroupsList', static fn (\Multiotp $e, string $id): bool => (bool) $e->ReadGroupData($id), static fn (\Multiotp $e): bool => (bool) $e->WriteGroupData()],
            ];
            foreach ($kinds as $kind => [$list, $read, $write]) {
                $engine->SetEncryptionKey($old, false);
                foreach (array_filter(explode("\t", trim((string) $engine->$list())), 'strlen') as $id) {
                    $engine->SetEncryptionKey($old, false);
                    if ($read($engine, $id)) {
                        $engine->SetEncryptionKey($new, false);
                        if ($write($engine)) {
                            $summary[$kind]++;
                            continue;
                        }
                    } else {
                        $engine->SetEncryptionKey($new, false);
                        if ($read($engine, $id)) {
                            continue; // already re-encrypted by an earlier run
                        }
                    }
                    $summary['failed'][] = $kind . ':' . $id;
                }
            }

            // 3. the settings, with the key file location (read before anything else by every engine)
            $engine->SetEncryptionKey($new, false);
            $engine->SetEncryptionKeyFullPath($file);
            if (!$engine->WriteConfigData()) {
                throw new \RuntimeException('The engine settings could not be written with the new key.');
            }
            MultiotpService::reset();
            $summary['changed'] = true;
            return $summary;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }
}
