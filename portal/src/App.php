<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Front controller: security headers, session, authentication stages,
 * CSRF, permissions and the Stage 1 pages.
 */
final class App
{
    private const SIGN_IN_FAILED = 'Sign-in failed. Check your details, or wait a few minutes if there have been several failed attempts.';

    private AdminRepository $admins;
    private Audit $audit;
    private Throttle $throttle;
    private Mfa $mfa;
    private View $view;
    private ?array $admin = null;
    private string $ip = '';

    public function __construct()
    {
        $this->admins = new AdminRepository();
        $this->audit = Audit::default();
        $this->throttle = new Throttle();
        $this->mfa = new Mfa($this->admins);
        $this->view = new View();
    }

    public function run(): void
    {
        $this->sendSecurityHeaders();
        $https = self::isHttps();
        if (!$https && !Config::allowHttp()) {
            http_response_code(403);
            $this->view->render('error', ['title' => 'HTTPS required', 'message' => 'The management portal is only available over HTTPS.'], 'auth');
            return;
        }
        $this->ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        Audit::setIp($this->ip);
        try {
            Session::start($https);
            $this->loadAdmin();
            $this->dispatch((string) ($_GET['r'] ?? ''));
        } catch (\Throwable $error) {
            error_log('multiOTP portal: ' . $error);
            if (!headers_sent()) {
                http_response_code(500);
            }
            $this->view->render('error', [
                'title'   => 'Something went wrong',
                'message' => 'The request could not be completed. Details were written to the server error log.',
            ], 'auth');
        }
    }

    // ------------------------------------------------------------------
    // Routing
    // ------------------------------------------------------------------

    private function dispatch(string $route): void
    {
        if ('POST' === ($_SERVER['REQUEST_METHOD'] ?? 'GET') && !Csrf::valid($_POST[Csrf::FIELD] ?? null)) {
            $this->audit->record('security.csrf_rejected', 'denied', $route);
            http_response_code(400);
            $this->view->render('error', [
                'title'   => 'Request expired',
                'message' => 'The form was out of date or came from another site. Go back, reload the page and try again.',
            ], 'auth');
            return;
        }

        if ('licences' === $route) {
            // public: open-source notices, no data
            $this->view->render('licences', ['title' => 'Licences'], null === $this->admin ? 'auth' : 'app');
            return;
        }

        switch (Session::stage()) {
            case null:
                $this->login();
                return;
            case 'mfa':
                'logout' === $route ? $this->logout() : $this->secondFactor();
                return;
            case 'enroll':
                'logout' === $route ? $this->logout() : $this->enroll();
                return;
        }

        // Fully signed in
        if (!empty($this->admin['must_change_password']) && !in_array($route, ['password', 'logout'], true)) {
            $this->redirect('password');
        }
        $users = new UsersController($this->admin, $this->audit, $this->view);
        $tokens = new TokensController($this->admin, $this->audit, $this->view);
        $directory = new DirectoryController($this->admin, $this->audit, $this->view);
        $radius = new RadiusController($this->admin, $this->audit, $this->view);
        $endpoints = new EndpointsController($this->admin, $this->audit, $this->view);
        $apiKeys = new ApiKeysController($this->admin, $this->audit, $this->view);
        $database = new DatabaseController($this->admin, $this->audit, $this->view);
        $ha = new HaController($this->admin, $this->audit, $this->view);
        match ($route) {
            'ha'                   => $ha->index(),
            'database'             => $database->index(),
            'api-keys'             => $apiKeys->index(),
            'radius'               => $radius->index(),
            'radius-group'         => $radius->group(),
            'radius-group-delete'  => $radius->groupDelete(),
            'radius-client'        => $radius->client(),
            'radius-client-action' => $radius->clientAction(),
            'radius-apply'         => $radius->apply(),
            'radius-diagnostics'   => $radius->diagnostics(),
            'radius-vip'           => $radius->vip(),
            'endpoints'             => $endpoints->index(),
            'endpoint'              => $endpoints->endpoint(),
            'endpoint-groups'       => $endpoints->groups(),
            'endpoint-group'        => $endpoints->group(),
            'endpoint-group-delete' => $endpoints->groupDelete(),
            'endpoint-rules'        => $endpoints->rules(),
            'endpoint-enrol'        => $endpoints->enrol(),
            'agent-download'        => $endpoints->agentDownload(),
            'users'          => $users->index(),
            'self-service'   => $users->selfService(),
            'user-new'       => $users->create(),
            'user'           => $users->show(),
            'user-action'    => $users->action(),
            'user-bulk'      => $users->bulk(),
            'tokens'         => $tokens->index(),
            'token-import'   => $tokens->import(),
            'token-action'   => $tokens->action(),
            'directory'      => $directory->index(),
            'directory-save' => $directory->save(),
            'directory-test' => $directory->test(),
            'directory-run'  => $directory->run(),
            'jobs'           => $directory->jobs(),
            'job'            => $directory->job(),
            'job-status'     => $directory->jobStatus(),
            'job-cancel'     => $directory->cancel(),
            'logout'       => $this->logout(),
            'password'     => $this->changePassword(),
            'account'      => $this->account(),
            'admins'       => $this->adminList(),
            'admin-new'    => $this->adminNew(),
            'admin-edit'   => $this->adminEdit(),
            'admin-action' => $this->adminAction(),
            'audit'        => $this->auditLog(),
            default        => $this->dashboard(),
        };
    }

    /** Load the signed-in administrator and drop sessions that are no longer valid. */
    private function loadAdmin(): void
    {
        $id = Session::adminId();
        if (null === $id) {
            return;
        }
        $admin = $this->admins->find($id);
        $reason = null;
        if (null === $admin || 'active' !== $admin['status']) {
            $reason = 'Your account is not available. Please contact a super administrator.';
        } elseif ('full' === Session::stage() && ($_SESSION['session_version'] ?? null) !== $admin['session_version']) {
            $reason = 'You were signed out because your account or sessions were changed.';
        }
        if (null !== $reason) {
            Session::reset();
            Session::flash('info', $reason);
            return;
        }
        $this->admin = $admin;
        Audit::setActor($admin['username'], 'full' === Session::stage() ? $admin['role'] : '');
        $this->view->setAdmin('full' === Session::stage() ? $admin : null);
    }

    private function requirePermission(string $permission): void
    {
        if (!Roles::can($this->admin['role'], $permission)) {
            $this->audit->record('access.denied', 'denied', $permission);
            http_response_code(403);
            $this->view->render('error', ['title' => 'Not allowed', 'message' => 'Your role does not allow this action.']);
            exit;
        }
    }

    // ------------------------------------------------------------------
    // Sign-in
    // ------------------------------------------------------------------

    private function login(): void
    {
        if (!$this->isPost()) {
            $this->view->render('login', ['title' => 'Sign in', 'username' => ''], 'auth');
            return;
        }
        $username = AdminRepository::normalise(mb_substr((string) ($_POST['username'] ?? ''), 0, 64));
        $password = mb_substr((string) ($_POST['password'] ?? ''), 0, 256);
        $error = self::SIGN_IN_FAILED;

        $admin = '' === $username ? null : $this->admins->findByUsername($username);
        $passwordOk = Passwords::verify($password, $admin['password_hash'] ?? null);

        if ($this->throttle->isBlocked($this->ip)) {
            $this->audit->record('auth.login', 'denied', $username, ['reason' => 'too many failures from this address']);
        } elseif (null === $admin) {
            $this->throttle->fail($this->ip);
            $this->audit->record('auth.login', 'failure', $username, ['reason' => 'unknown administrator']);
        } elseif (AdminRepository::isLocked($admin)) {
            $this->throttle->fail($this->ip);
            $this->audit->record('auth.login', 'denied', $username, ['reason' => 'account locked']);
        } elseif (!$passwordOk) {
            $this->throttle->fail($this->ip);
            $updated = $this->admins->registerFailure($admin['id']);
            $this->audit->record('auth.login', 'failure', $username, [
                'reason' => 'wrong password',
                'locked' => AdminRepository::isLocked($updated),
            ]);
        } elseif ('active' !== $admin['status']) {
            $this->audit->record('auth.login', 'denied', $username, ['reason' => 'account disabled']);
        } elseif (null !== $admin['password_expires_at'] && $admin['password_expires_at'] < time()) {
            $this->audit->record('auth.login', 'denied', $username, ['reason' => 'temporary password expired']);
            $error = 'Your temporary password has expired. Ask a super administrator to reset it.';
        } else {
            if (Passwords::needsRehash($admin['password_hash'])) {
                $this->admins->update($admin['id'], static function (array &$a) use ($password): void {
                    $a['password_hash'] = Passwords::hash($password);
                });
            }
            $stage = null === $admin['mfa_mode'] ? 'enroll' : 'mfa';
            Session::beginSecondFactor($admin, $stage);
            $this->audit->record('auth.password', 'success', $username, ['next' => $stage]);
            $this->redirect($stage);
        }
        http_response_code(401);
        $this->view->render('login', ['title' => 'Sign in', 'username' => $username, 'error' => $error], 'auth');
    }

    private function secondFactor(): void
    {
        $this->expireSecondFactorStage(Config::mfaStepTimeout());
        $error = null;
        if ($this->isPost()) {
            $code = (string) ($_POST['code'] ?? '');
            if (!$this->throttle->isBlocked($this->ip) && !AdminRepository::isLocked($this->admin) && $this->mfa->verify($this->admin, $code)) {
                $this->finishLogin('mfa');
            }
            $this->throttle->fail($this->ip);
            $updated = $this->admins->registerFailure($this->admin['id']);
            $this->audit->record('auth.mfa', 'failure', $this->admin['username'], ['locked' => AdminRepository::isLocked($updated)]);
            $error = $this->countSecondFactorAttempt(AdminRepository::isLocked($updated));
        }
        $this->view->render('mfa', [
            'title' => 'Verification code',
            'mode'  => $this->admin['mfa_mode'],
            'error' => $error,
        ], 'auth');
    }

    private function enroll(): void
    {
        // Scanning a QR code takes longer than typing a code
        $this->expireSecondFactorStage(2 * Config::mfaStepTimeout());
        if (empty($_SESSION['enroll_secret'])) {
            $_SESSION['enroll_secret'] = base64_encode(Totp::newSecret());
        }
        $secret = base64_decode($_SESSION['enroll_secret'], true);
        $error = null;
        if ($this->isPost()) {
            if ($this->mfa->enroll($this->admin['id'], $secret, (string) ($_POST['code'] ?? ''))) {
                $this->audit->record('auth.mfa_enrolled', 'success', $this->admin['username'], ['mode' => 'portal']);
                unset($_SESSION['enroll_secret']);
                $this->admin = $this->admins->find($this->admin['id']);
                $this->finishLogin('enrolment');
            }
            $this->audit->record('auth.mfa_enrolled', 'failure', $this->admin['username']);
            $error = $this->countSecondFactorAttempt(false);
        }
        $uri = Totp::uri(Config::issuer(), $this->admin['username'], $secret);
        $this->view->render('enroll', [
            'title'  => 'Set up two-factor authentication',
            'qr'     => self::qrDataUri($uri),
            'secret' => trim(chunk_split(Totp::base32($secret), 4, ' ')),
            'error'  => $error,
        ], 'auth');
    }

    private function finishLogin(string $via): never
    {
        $ip = $this->ip;
        $admin = $this->admins->update($this->admin['id'], static function (array &$a) use ($ip): void {
            $a['failed_attempts'] = 0;
            $a['locked_until'] = null;
            $a['last_login_at'] = time();
            $a['last_login_ip'] = $ip;
        });
        Session::completeLogin($admin);
        $this->throttle->clear($this->ip);
        Audit::setActor($admin['username'], $admin['role']);
        $this->audit->record('auth.login', 'success', $admin['username'], ['via' => $via]);
        $this->redirect($admin['must_change_password'] ? 'password' : 'dashboard');
    }

    private function expireSecondFactorStage(int $timeout): void
    {
        if (time() - (int) ($_SESSION['stage_since'] ?? 0) > $timeout) {
            Session::reset();
            Session::flash('info', 'The sign-in took too long. Please start again.');
            $this->redirect('login');
        }
    }

    /** Returns the error to show, or ends the attempt after too many wrong codes. */
    private function countSecondFactorAttempt(bool $locked): string
    {
        $_SESSION['mfa_attempts'] = ($_SESSION['mfa_attempts'] ?? 0) + 1;
        if ($locked || $_SESSION['mfa_attempts'] >= Config::maxMfaAttempts()) {
            Session::reset();
            Session::flash('error', self::SIGN_IN_FAILED);
            $this->redirect('login');
        }
        http_response_code(401);
        return 'That code was not accepted. Check the time on your device and try the next code.';
    }

    private function logout(): void
    {
        if ($this->isPost()) {
            if (null !== $this->admin) {
                $this->audit->record('auth.logout', 'success', $this->admin['username']);
            }
            Session::reset();
            Session::flash('info', 'You are signed out.');
        }
        $this->redirect('login');
    }

    // ------------------------------------------------------------------
    // Own account
    // ------------------------------------------------------------------

    private function changePassword(): void
    {
        $error = null;
        if ($this->isPost()) {
            $current = (string) ($_POST['current_password'] ?? '');
            $new = (string) ($_POST['new_password'] ?? '');
            if (!Passwords::verify($current, $this->admin['password_hash'])) {
                $updated = $this->admins->registerFailure($this->admin['id']);
                $this->audit->record('account.password_change', 'failure', $this->admin['username'], ['reason' => 'wrong current password']);
                if (AdminRepository::isLocked($updated)) {
                    Session::reset();
                    Session::flash('error', 'Too many wrong passwords. Your account is locked for a few minutes.');
                    $this->redirect('login');
                }
                $error = 'Your current password is not correct.';
            } elseif ($new !== (string) ($_POST['confirm_password'] ?? '')) {
                $error = 'The new passwords do not match.';
            } elseif ($new === $current) {
                $error = 'Choose a password different from the current one.';
            } elseif (null === ($error = Passwords::validate($new, $this->admin['username']))) {
                $admin = $this->admins->update($this->admin['id'], static function (array &$a) use ($new): void {
                    $a['password_hash'] = Passwords::hash($new);
                    $a['must_change_password'] = false;
                    $a['password_expires_at'] = null;
                    $a['password_changed_at'] = time();
                    $a['failed_attempts'] = 0;
                    $a['session_version']++; // signs out every other session
                });
                Session::regenerate();
                $_SESSION['session_version'] = $admin['session_version'];
                $this->audit->record('account.password_change', 'success', $admin['username']);
                Session::flash('success', 'Your password was changed. Other sessions were signed out.');
                $this->redirect('dashboard');
            }
        }
        $this->view->render('password', [
            'title'  => 'Change password',
            'forced' => !empty($this->admin['must_change_password']),
            'error'  => $error,
            'min'    => Config::minPasswordLength(),
        ]);
    }

    private function account(): void
    {
        if ($this->isPost() && 'revoke-sessions' === ($_POST['op'] ?? '')) {
            $this->admins->update($this->admin['id'], static function (array &$a): void {
                $a['session_version']++;
            });
            $this->audit->record('account.sessions_revoked', 'success', $this->admin['username']);
            Session::reset();
            Session::flash('info', 'All your sessions were signed out, including this one.');
            $this->redirect('login');
        }
        $this->view->render('account', ['title' => 'My account', 'me' => $this->admin]);
    }

    // ------------------------------------------------------------------
    // Dashboard
    // ------------------------------------------------------------------

    private function dashboard(): void
    {
        $this->requirePermission('dashboard.view');
        $stats = ['users' => null, 'active' => null, 'locked' => null, 'tokens' => null, 'error' => null];
        try {
            $multiotp = MultiotpService::get();
            $stats['users'] = (int) $multiotp->GetUsersCount();
            $stats['active'] = (int) $multiotp->GetActiveUsersCount();
            $stats['locked'] = (int) $multiotp->GetLockedUsersCount();
            $stats['tokens'] = (int) $multiotp->GetTokensCount();
        } catch (\Throwable $error) {
            error_log('multiOTP portal dashboard: ' . $error);
            $stats['error'] = 'The SohobOTP engine could not be read.';
        }
        $admins = $this->admins->all();
        $recent = Roles::can($this->admin['role'], 'audit.view') ? $this->audit->search([], 1, 8)['entries'] : [];
        $directoryState = (new Directory())->state();
        $directorySettings = null;
        try {
            $directorySettings = (new Directory())->settings();
        } catch (\Throwable $error) {
            error_log('multiOTP portal dashboard directory: ' . $error);
        }
        $this->view->render('dashboard', [
            'title'       => 'Dashboard',
            'stats'       => $stats,
            'adminCount'  => count(array_filter($admins, static fn (array $a): bool => 'active' === $a['status'])),
            'lockedAdmins'=> count(array_filter($admins, [AdminRepository::class, 'isLocked'])),
            'recent'      => $recent,
            'directory'   => [
                'enabled'  => (bool) ($directorySettings['enabled'] ?? false),
                'schedule' => $directoryState['schedule'] ?? null,
                'last'     => $directoryState['last_sync'] ?? null,
                'active'   => Jobs::latest('directory.sync'),
            ],
        ]);
    }

    // ------------------------------------------------------------------
    // Administrator accounts (super administrators only)
    // ------------------------------------------------------------------

    private function adminList(): void
    {
        $this->requirePermission('admins.manage');
        $this->view->render('admins', ['title' => 'Administrators', 'admins' => $this->admins->all()]);
    }

    private function adminNew(): void
    {
        $this->requirePermission('admins.manage');
        $input = ['username' => '', 'display_name' => '', 'email' => '', 'role' => 'helpdesk', 'mfa' => 'enroll', 'mfa_user' => ''];
        $error = null;
        if ($this->isPost()) {
            foreach (array_keys($input) as $field) {
                $input[$field] = trim(mb_substr((string) ($_POST[$field] ?? ''), 0, 255));
            }
            try {
                if ('multiotp' === $input['mfa']) {
                    if (null !== ($linkError = Mfa::checkLinkableUser($input['mfa_user']))) {
                        throw new ValidationException($linkError);
                    }
                } else {
                    $input['mfa_user'] = '';
                }
                $temporary = Passwords::temporary();
                $created = $this->admins->create($input, $temporary, true, $this->admin['username']);
                $this->audit->record('admin.create', 'success', $created['username'], [
                    'role' => $created['role'],
                    'mfa'  => $created['mfa_mode'] ?? 'enrol at first sign-in',
                    'mfa_user' => $created['mfa_user'],
                ]);
                $this->view->render('admin-secret', [
                    'title'    => 'Administrator created',
                    'subject'  => $created,
                    'password' => $temporary,
                    'hours'    => intdiv(Config::tempPasswordLifetime(), 3600),
                ]);
                return;
            } catch (ValidationException $invalid) {
                $error = $invalid->getMessage();
            }
        }
        $this->view->render('admin-form', ['title' => 'New administrator', 'input' => $input, 'error' => $error, 'subject' => null]);
    }

    private function adminEdit(): void
    {
        $this->requirePermission('admins.manage');
        $subject = $this->subjectOr404((string) ($_GET['id'] ?? ''));
        $input = [
            'display_name' => $subject['display_name'],
            'email'        => $subject['email'],
            'role'         => $subject['role'],
            'mfa_user'     => (string) $subject['mfa_user'],
        ];
        $error = null;
        if ($this->isPost()) {
            foreach (array_keys($input) as $field) {
                $input[$field] = trim(mb_substr((string) ($_POST[$field] ?? ''), 0, 255));
            }
            try {
                if (!Roles::exists($input['role'])) {
                    throw new ValidationException('Unknown role.');
                }
                if ('' !== $input['email'] && false === filter_var($input['email'], FILTER_VALIDATE_EMAIL)) {
                    throw new ValidationException('The email address is not valid.');
                }
                $linkChanged = '' !== $input['mfa_user'] && $input['mfa_user'] !== (string) $subject['mfa_user'];
                if ($linkChanged && null !== ($linkError = Mfa::checkLinkableUser($input['mfa_user']))) {
                    throw new ValidationException($linkError);
                }
                $changes = [];
                $this->admins->update($subject['id'], static function (array &$a, array &$all) use ($input, $linkChanged, &$changes): void {
                    if ('superadmin' === $a['role'] && 'superadmin' !== $input['role'] && 0 === AdminRepository::activeSuperadmins($all, $a['id'])) {
                        throw new ValidationException('This is the last active super administrator; its role cannot be changed.');
                    }
                    foreach (['display_name', 'email', 'role'] as $field) {
                        if ($a[$field] !== $input[$field]) {
                            $changes[$field] = ['from' => $a[$field], 'to' => $input[$field]];
                            $a[$field] = $input[$field];
                        }
                    }
                    if ($linkChanged) {
                        $changes['mfa'] = ['from' => $a['mfa_mode'] ?? 'not enrolled', 'to' => 'multiotp:' . $input['mfa_user']];
                        $a['mfa_mode'] = 'multiotp';
                        $a['mfa_user'] = $input['mfa_user'];
                        $a['mfa_secret'] = null;
                        $a['mfa_last_step'] = -1;
                        $a['session_version']++;
                    }
                });
                $this->audit->record('admin.update', 'success', $subject['username'], ['changes' => $changes]);
                Session::flash('success', [] === $changes ? 'Nothing changed.' : 'Administrator updated.');
                $this->redirect('admins');
            } catch (ValidationException $invalid) {
                $error = $invalid->getMessage();
            }
        }
        $this->view->render('admin-form', ['title' => 'Edit ' . $subject['username'], 'input' => $input, 'error' => $error, 'subject' => $subject]);
    }

    private function adminAction(): void
    {
        $this->requirePermission('admins.manage');
        if (!$this->isPost()) {
            $this->redirect('admins');
        }
        $subject = $this->subjectOr404((string) ($_POST['id'] ?? ''));
        $op = (string) ($_POST['op'] ?? '');
        $self = $subject['id'] === $this->admin['id'];
        $myId = $this->admin['id'];
        $temporary = null;

        try {
            $updated = $this->admins->update($subject['id'], static function (array &$a, array &$all) use ($op, $self, &$temporary): void {
                switch ($op) {
                    case 'reset-password':
                        $temporary = Passwords::temporary();
                        $a['password_hash'] = Passwords::hash($temporary);
                        $a['must_change_password'] = true;
                        $a['password_expires_at'] = time() + Config::tempPasswordLifetime();
                        $a['failed_attempts'] = 0;
                        $a['locked_until'] = null;
                        $a['session_version']++;
                        break;
                    case 'unlock':
                        $a['failed_attempts'] = 0;
                        $a['locked_until'] = null;
                        break;
                    case 'revoke-sessions':
                        $a['session_version']++;
                        break;
                    case 'reset-mfa':
                        if ($self) {
                            throw new ValidationException('Another super administrator must reset your own second factor.');
                        }
                        $a['mfa_mode'] = null;
                        $a['mfa_secret'] = null;
                        $a['mfa_last_step'] = -1;
                        $a['mfa_user'] = null;
                        $a['session_version']++;
                        break;
                    case 'disable':
                        if ($self) {
                            throw new ValidationException('You cannot disable your own account.');
                        }
                        if ('superadmin' === $a['role'] && 0 === AdminRepository::activeSuperadmins($all, $a['id'])) {
                            throw new ValidationException('The last active super administrator cannot be disabled.');
                        }
                        $a['status'] = 'disabled';
                        $a['session_version']++;
                        break;
                    case 'enable':
                        $a['status'] = 'active';
                        break;
                    default:
                        throw new ValidationException('Unknown action.');
                }
            });
        } catch (ValidationException $invalid) {
            $this->audit->record('admin.' . preg_replace('/[^a-z-]/', '', $op), 'denied', $subject['username'], ['reason' => $invalid->getMessage()]);
            Session::flash('error', $invalid->getMessage());
            $this->redirect('admins');
        }

        $this->audit->record('admin.' . $op, 'success', $subject['username']);
        if ($self && in_array($op, ['reset-password', 'revoke-sessions'], true)) {
            Session::reset();
            Session::flash('info', 'Your own sessions were signed out.' . (null !== $temporary ? ' Sign in with the new temporary password.' : ''));
            if (null === $temporary) {
                $this->redirect('login');
            }
        }
        if (null !== $temporary) {
            if ($self) {
                $this->view->setAdmin(null);
            }
            $this->view->render('admin-secret', [
                'title'    => 'Temporary password',
                'subject'  => $updated,
                'password' => $temporary,
                'hours'    => intdiv(Config::tempPasswordLifetime(), 3600),
            ], $self ? 'auth' : 'app');
            return;
        }
        $messages = [
            'unlock'          => 'Account unlocked.',
            'revoke-sessions' => 'All sessions of this administrator were signed out.',
            'reset-mfa'       => 'Second factor removed. The administrator sets up a new one at next sign-in.',
            'disable'         => 'Account disabled and signed out.',
            'enable'          => 'Account enabled.',
        ];
        Session::flash('success', $messages[$op] ?? 'Done.');
        $this->redirect('admins');
    }

    private function subjectOr404(string $id): array
    {
        $subject = '' === $id ? null : $this->admins->find($id);
        if (null === $subject) {
            http_response_code(404);
            $this->view->render('error', ['title' => 'Not found', 'message' => 'This administrator does not exist.']);
            exit;
        }
        return $subject;
    }

    // ------------------------------------------------------------------
    // Audit trail
    // ------------------------------------------------------------------

    private function auditLog(): void
    {
        $this->requirePermission('audit.view');
        $filters = [];
        foreach (['actor', 'action', 'result', 'target', 'from', 'to', 'q'] as $key) {
            $filters[$key] = trim(mb_substr((string) ($_GET[$key] ?? ''), 0, 128));
        }
        foreach (['from', 'to'] as $key) {
            if ('' !== $filters[$key] && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $filters[$key])) {
                $filters[$key] = '';
            }
        }
        $page = max(1, (int) ($_GET['page'] ?? 1));
        $perPage = 50;
        $result = $this->audit->search($filters, $page, $perPage);
        $this->view->render('audit', [
            'title'   => 'Audit trail',
            'filters' => $filters,
            'entries' => $result['entries'],
            'total'   => $result['total'],
            'page'    => $page,
            'pages'   => max(1, (int) ceil($result['total'] / $perPage)),
            'chain'   => $this->audit->verify(),
        ]);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private function isPost(): bool
    {
        return 'POST' === ($_SERVER['REQUEST_METHOD'] ?? 'GET');
    }

    private function redirect(string $route, array $params = []): never
    {
        header('Location: ' . route($route, $params), true, 303);
        exit;
    }

    public static function isHttps(): bool
    {
        // Proxy headers such as X-Forwarded-Proto are deliberately not trusted
        return (!empty($_SERVER['HTTPS']) && 'off' !== strtolower((string) $_SERVER['HTTPS']))
            || '443' === (string) ($_SERVER['SERVER_PORT'] ?? '');
    }

    public static function sendSecurityHeaders(): void
    {
        header("Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: same-origin');
        header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
        header('Cache-Control: no-store');
        header('Pragma: no-cache');
        if (self::isHttps()) {
            header('Strict-Transport-Security: max-age=31536000');
        }
    }

    public static function qrDataUri(string $text): ?string
    {
        try {
            MultiotpService::get(); // loads the bundled barcode generator
            if (!class_exists('barcode_generator', false)) {
                return null;
            }
            $svg = (new \barcode_generator())->render_svg('qr-m', $text, ['sf' => 6, 'p' => 4]);
            return is_string($svg) && '' !== $svg ? 'data:image/svg+xml;base64,' . base64_encode($svg) : null;
        } catch (\Throwable $error) {
            error_log('multiOTP portal QR code: ' . $error);
            return null;
        }
    }
}
