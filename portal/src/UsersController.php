<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/** Users: list, search, create, edit, unlock, enable/disable, delete, token enrolment, resync, recovery codes, bulk actions. */
final class UsersController extends Controller
{
    private const PER_PAGE = 50;
    private const BULK = ['unlock' => 'users.unlock', 'enable' => 'users.manage', 'disable' => 'users.manage', 'delete' => 'users.manage',
        'to-sohobotp' => 'users.manage', 'to-vip' => 'users.manage'];
    public const BULK_LABELS = ['unlock' => 'Unlock', 'enable' => 'Enable', 'disable' => 'Disable', 'delete' => 'Delete',
        'to-sohobotp' => 'Move to SohobOTP (Symantec VIP migration)', 'to-vip' => 'Send back to Symantec VIP'];

    public function index(): void
    {
        $this->requirePermission('users.view');
        $q = $this->query('q', 128);
        $status = $this->query('status', 16);
        if (!isset(Users::STATUSES[$status])) {
            $status = '';
        }
        $page = max(1, (int) ($_GET['page'] ?? 1));
        $result = (new Users())->search($q, $status, $page, self::PER_PAGE);
        $bulk = array_keys(array_filter(self::BULK, fn (string $p): bool => $this->can($p)));
        $this->view->render('users', [
            'title' => 'Users',
            'users' => $result['users'],
            'total' => $result['total'],
            'q'     => $q,
            'status'=> $status,
            'page'  => $page,
            'pages' => max(1, (int) ceil($result['total'] / self::PER_PAGE)),
            'bulk'  => $bulk,
            'canCreate' => $this->can('users.manage'),
        ]);
    }

    public function create(): void
    {
        $this->requirePermission('users.manage');
        $users = new Users();
        $input = ['user' => '', 'display_name' => '', 'email' => '', 'sms' => '', 'description' => '', 'group' => '', 'token_serial' => ''];
        $error = null;
        if ($this->isPost()) {
            foreach (array_keys($input) as $field) {
                $input[$field] = $this->post($field);
            }
            try {
                $created = $users->create($input);
                $this->audit->record('user.create', 'success', $created['user'], ['token' => '' === $input['token_serial'] ? 'software' : 'hardware ' . $input['token_serial']]);
                if (null !== $created['otpauth']) {
                    $this->showEnrolment($created['user'], $created['otpauth'], 'User created');
                }
                \Portal\Session::flash('success', 'User created with hardware token ' . $input['token_serial'] . '.');
                $this->redirect('user', ['u' => $created['user']]);
            } catch (ValidationException $invalid) {
                $error = $invalid->getMessage();
            }
        }
        $this->view->render('user-form', ['title' => 'New user', 'input' => $input, 'error' => $error, 'freeTokens' => $users->freeTokens()]);
    }

    public function show(): void
    {
        $this->requirePermission('users.view');
        $users = new Users();
        $user = $users->get($this->query('u', 128)) ?? $this->notFound('This user does not exist.');
        $this->view->render('user', [
            'title'      => $user['user'],
            'user'       => $user,
            'freeTokens' => $this->can('tokens.manage') ? $users->freeTokens() : [],
            'vipRoute'   => (new VipMigration())->stateOf($user['user']),
            'vipGroups'  => (new Radius())->forwardingGroups(),
            'perm'       => [
                'manage' => $this->can('users.manage'),
                'unlock' => $this->can('users.unlock'),
                'enroll' => $this->can('tokens.enroll'),
                'resync' => $this->can('tokens.resync'),
                'tokens' => $this->can('tokens.manage'),
            ],
        ]);
    }

    public function action(): void
    {
        if (!$this->isPost()) {
            $this->redirect('users');
        }
        $users = new Users();
        $name = $this->post('u', 128);
        if (!$users->exists($name)) {
            $this->notFound('This user does not exist.');
        }
        $op = $this->post('op', 32);
        $permission = match ($op) {
            'unlock'                        => 'users.unlock',
            'enable', 'disable', 'delete', 'save', 'login-format', 'vip-route' => 'users.manage',
            'enroll', 'recovery-codes'      => 'tokens.enroll',
            'resync'                        => 'tokens.resync',
            'assign-token', 'remove-token'  => 'tokens.manage',
            default                         => $this->notFound('Unknown action.'),
        };
        $this->requirePermission($permission);

        try {
            switch ($op) {
                case 'unlock':
                    $users->unlock($name);
                    $this->done('user.unlock', $name, 'User unlocked.');
                case 'enable':
                case 'disable':
                    $users->setEnabled($name, 'enable' === $op);
                    $this->done('user.' . $op, $name, 'enable' === $op ? 'User enabled.' : 'User disabled. RADIUS logins are refused until it is enabled again.');
                case 'delete':
                    $users->delete($name);
                    (new VipMigration())->forget($name);
                    $this->audit->record('user.delete', 'success', $name);
                    Session::flash('success', "User $name deleted.");
                    $this->redirect('users');
                case 'save':
                    $fields = [];
                    foreach (['display_name', 'description', 'email', 'sms', 'group'] as $field) {
                        $fields[$field] = $this->post($field);
                    }
                    $changes = $users->update($name, $fields);
                    $this->done('user.update', $name, [] === $changes ? 'Nothing changed.' : 'User updated.', ['changes' => $changes]);
                case 'login-format':
                    $format = $this->post('format', 16);
                    $pin = $users->setLoginFormat($name, $format);
                    $this->audit->record('user.login_format', 'success', $name, ['format' => $format]);
                    if (null !== $pin) {
                        $this->view->render('user-pin', ['title' => 'PIN for ' . $name, 'name' => $name, 'pin' => $pin]);
                        exit;
                    }
                    Session::flash('success', 'Login format changed to: ' . Users::LOGIN_FORMATS[$format] . '.');
                    $this->redirect('user', ['u' => $name]);
                case 'vip-route':
                    $route = 'vip' === $this->post('route', 16) ? 'vip' : 'sohobotp';
                    (new VipMigration())->set([$name], $route, $this->admin['username'], 'by an administrator');
                    $this->done('user.vip_route', $name, 'vip' === $route
                        ? 'Sent back to Symantec VIP: on server groups with forwarding on, this user signs in with Symantec again.'
                        : 'Moved to SohobOTP: this user now signs in with SohobOTP everywhere.', ['route' => $route]);
                case 'enroll':
                    $uri = $users->enrollSoftwareToken($name);
                    (new VipMigration())->set([$name], 'sohobotp', $this->admin['username'], 'authenticator enrolled');
                    $this->audit->record('user.token_enrolled', 'success', $name, ['type' => 'software TOTP']);
                    $this->showEnrolment($name, $uri, 'New authenticator enrolment');
                case 'recovery-codes':
                    $codes = $users->newRecoveryCodes($name);
                    $this->audit->record('user.recovery_codes', 'success', $name, ['count' => count($codes)]);
                    $this->view->render('user-codes', ['title' => 'Recovery codes for ' . $name, 'name' => $name, 'codes' => $codes]);
                    exit;
                case 'resync':
                    $ok = $users->resync($name, $this->post('code1', 32), $this->post('code2', 32));
                    $this->audit->record('user.token_resync', $ok ? 'success' : 'failure', $name);
                    Session::flash($ok ? 'success' : 'error', $ok ? 'Token resynchronised.' : 'Resynchronisation failed. Use two consecutive codes, generated one after the other.');
                    $this->redirect('user', ['u' => $name]);
                case 'assign-token':
                    $serial = $this->post('serial', 128);
                    $users->assignToken($name, $serial);
                    (new VipMigration())->set([$name], 'sohobotp', $this->admin['username'], 'hardware token assigned');
                    $this->done('user.token_assigned', $name, "Hardware token $serial assigned.", ['serial' => $serial]);
                case 'remove-token':
                    $serial = $users->removeToken($name);
                    $this->done('user.token_removed', $name, "Hardware token $serial removed. Enrol a new authenticator for this user.", ['serial' => $serial]);
            }
        } catch (ValidationException $invalid) {
            $this->audit->record('user.' . $op, 'denied', $name, ['reason' => $invalid->getMessage()]);
            Session::flash('error', $invalid->getMessage());
            $this->redirect('user', ['u' => $name]);
        }
    }

    public function bulk(): void
    {
        if (!$this->isPost()) {
            $this->redirect('users');
        }
        $op = $this->post('op', 16);
        if (!isset(self::BULK[$op])) {
            Session::flash('error', 'Choose an action for the selected users.');
            $this->redirect('users');
        }
        $this->requirePermission(self::BULK[$op]);
        $names = array_slice(array_filter(array_map('strval', (array) ($_POST['users'] ?? [])), 'strlen'), 0, 500);
        if ([] === $names) {
            Session::flash('error', 'No users selected.');
            $this->redirect('users');
        }
        $users = new Users();
        $done = $failed = [];
        if ('to-sohobotp' === $op || 'to-vip' === $op) {
            $route = 'to-vip' === $op ? 'vip' : 'sohobotp';
            $known = array_values(array_filter($names, [$users, 'exists']));
            (new VipMigration())->set($known, $route, $this->admin['username'], 'by an administrator');
            foreach ($known as $name) {
                $this->audit->record('user.vip_route', 'success', $name, ['route' => $route, 'bulk' => true]);
            }
            $missing = array_diff($names, $known);
            Session::flash([] === $missing ? 'success' : 'error', self::BULK_LABELS[$op] . ': ' . count($known) . ' done' . ([] === $missing ? '.' : ', unknown: ' . implode(', ', array_slice($missing, 0, 20)) . '.'));
            $this->redirect('users', array_filter(['q' => $this->post('q', 128), 'status' => $this->post('status', 16)]));
        }
        foreach ($names as $name) {
            try {
                if (!$users->exists($name)) {
                    throw new ValidationException('missing');
                }
                match ($op) {
                    'unlock'  => $users->unlock($name),
                    'enable'  => $users->setEnabled($name, true),
                    'disable' => $users->setEnabled($name, false),
                    'delete'  => $users->delete($name),
                };
                if ('delete' === $op) {
                    (new VipMigration())->forget($name);
                }
                $this->audit->record('user.' . $op, 'success', $name, ['bulk' => true]);
                $done[] = $name;
            } catch (\Throwable $error) {
                $this->audit->record('user.' . $op, 'failure', $name, ['bulk' => true]);
                $failed[] = $name;
            }
        }
        Session::flash([] === $failed ? 'success' : 'error', ucfirst($op) . ': ' . count($done) . ' done' . ([] === $failed ? '.' : ', failed for ' . implode(', ', array_slice($failed, 0, 20)) . '.'));
        $this->redirect('users', array_filter(['q' => $this->post('q', 128), 'status' => $this->post('status', 16)]));
    }

    private function done(string $action, string $name, string $message, array $details = []): never
    {
        $this->audit->record($action, 'success', $name, $details);
        Session::flash('success', $message);
        $this->redirect('user', ['u' => $name]);
    }

    /** Shows the provisioning QR code exactly once (it contains the seed). */
    private function showEnrolment(string $name, string $uri, string $title): never
    {
        parse_str((string) parse_url($uri, PHP_URL_QUERY), $query);
        $this->view->render('user-enroll', [
            'title'  => $title,
            'name'   => $name,
            'qr'     => Qr::dataUri($uri),
            'secret' => trim(chunk_split((string) ($query['secret'] ?? ''), 4, ' ')),
        ]);
        exit;
    }
}
