<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Second factor for administrators. Two modes:
 *  - "portal":   a TOTP secret enrolled in the portal itself. It is not a
 *                multiOTP user, so it can never be used to log in over RADIUS.
 *  - "multiotp": an existing multiOTP user's token (e.g. the administrator's own
 *                directory account), checked with the normal multiOTP engine,
 *                including its PIN, lockout and replay rules.
 */
final class Mfa
{
    private const LINKABLE_ALGORITHMS = ['totp', 'hotp', 'motp', 'yubicootp'];

    public function __construct(private AdminRepository $admins)
    {
    }

    public function verify(array $admin, string $code): bool
    {
        $code = trim($code);
        if ('' === $code || mb_strlen($code) > 128) {
            return false;
        }
        return match ($admin['mfa_mode']) {
            'portal'   => $this->verifyPortal($admin, $code),
            'multiotp' => $this->verifyMultiotp((string) $admin['mfa_user'], $code),
            default    => false,
        };
    }

    /** Store a freshly confirmed portal TOTP secret. Returns false when the code does not match. */
    public function enroll(string $adminId, string $secret, string $code): bool
    {
        $step = Totp::verify($secret, $code);
        if (null === $step) {
            return false;
        }
        $this->admins->update($adminId, static function (array &$admin) use ($secret, $step): void {
            $admin['mfa_mode'] = 'portal';
            $admin['mfa_secret'] = Crypto::encrypt($secret);
            $admin['mfa_last_step'] = $step;
            $admin['mfa_user'] = null;
        });
        return true;
    }

    /** Returns an error message, or null if the multiOTP user can serve as an administrator's second factor. */
    public static function checkLinkableUser(string $user): ?string
    {
        if ('' === $user) {
            return 'Choose a SohobOTP user.';
        }
        $multiotp = MultiotpService::get();
        if (!$multiotp->CheckUserExists($user)) {
            return 'This SohobOTP user does not exist.';
        }
        $multiotp->SetUser($user);
        if (!in_array($multiotp->GetUserAlgorithm(), self::LINKABLE_ALGORITHMS, true)) {
            return 'This SohobOTP user has no usable token (without2FA and empty tokens are refused).';
        }
        if (1 !== (int) $multiotp->GetUserActivated()) {
            return 'This SohobOTP user is deactivated.';
        }
        return null;
    }

    private function verifyPortal(array $admin, string $code): bool
    {
        if (empty($admin['mfa_secret'])) {
            return false;
        }
        $step = Totp::verify(Crypto::decrypt($admin['mfa_secret']), $code, (int) $admin['mfa_last_step']);
        if (null === $step) {
            return false;
        }
        // Remember the step under the lock; a concurrent login with the same code loses
        $accepted = false;
        $this->admins->update($admin['id'], static function (array &$record) use ($step, &$accepted): void {
            if ($step > (int) $record['mfa_last_step']) {
                $record['mfa_last_step'] = $step;
                $accepted = true;
            }
        });
        return $accepted;
    }

    private function verifyMultiotp(string $user, string $code): bool
    {
        if (null !== self::checkLinkableUser($user)) {
            return false;
        }
        $multiotp = MultiotpService::get();
        $multiotp->SetUser($user);
        return 0 === (int) $multiotp->CheckToken($code);
    }
}
