<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/** RADIUS: server groups, servers (FreeRADIUS clients), apply, diagnostics. */
final class RadiusController extends Controller
{
    public function index(): void
    {
        $this->requirePermission('radius.view');
        $radius = new Radius();
        $groups = $radius->groups();
        $this->view->render('radius', [
            'title'    => 'VPNs and devices',
            'groups'   => $groups,
            'names'    => array_column($groups, 'name', 'id'),
            'clients'  => $radius->clients(),
            'state'    => $radius->state(),
            'active'   => self::activeApply(),
            'canManage'=> $this->can('radius.manage'),
            'vip'      => $radius->vipSettings(),
            'vipActive'=> $radius->vipActive(),
            'vipGroups'=> $radius->forwardingGroups(),
            'vipCounts'=> (new VipMigration())->counts(),
        ]);
    }

    /** Symantec VIP migration: the VIP Enterprise Gateway servers, test, users already on SohobOTP. */
    public function vip(): void
    {
        $this->requirePermission('radius.manage');
        $radius = new Radius();
        $migration = new VipMigration();
        $error = null;
        $test = null;
        $input = null;
        if ($this->isPost()) {
            $op = $this->post('op', 16);
            try {
                switch ($op) {
                    case 'save':
                        $input = $_POST;
                        $details = $radius->saveVip($_POST);
                        $this->audit->record('radius.vip_save', 'success', '', $details);
                        Session::flash('success', 'Symantec VIP servers saved. Apply the configuration to activate them on FreeRADIUS.');
                        $this->redirect('radius-vip');
                    case 'test':
                        $server = '2' === $this->post('server', 1) ? 2 : 1;
                        $user = $this->post('user', 128);
                        $test = $radius->testVip($server, $user, mb_substr((string) ($_POST['password'] ?? ''), 0, 256));
                        $test['user'] = $user;
                        $test['server'] = $server;
                        $this->audit->record('radius.vip_test', 'accepted' === $test['result'] ? 'success' : 'failure', $user, ['server' => $server, 'result' => $test['result']]);
                        break;
                    case 'seed':
                        $job = Jobs::enqueue('radius.vip_seed', [], $this->admin['username']);
                        if (empty($job['already_active'])) {
                            $this->audit->record('radius.vip_seed_requested', 'success', '', ['job' => $job['id']]);
                        }
                        $this->redirect('job', ['id' => $job['id']]);
                    default:
                        $this->notFound('Unknown action.');
                }
            } catch (ValidationException $invalid) {
                $error = $invalid->getMessage();
            }
        }
        $vip = $radius->vipSettings();
        if (null !== $input) { // keep what was typed (never the secrets)
            foreach ([1, 2] as $n) {
                $vip['form']["address_$n"] = mb_substr((string) ($input["address_$n"] ?? ''), 0, 64);
                $vip['form']["port_$n"] = mb_substr((string) ($input["port_$n"] ?? ''), 0, 8);
            }
            $vip['form']['response_window'] = mb_substr((string) ($input['response_window'] ?? ''), 0, 4);
        }
        $this->view->render('radius-vip', [
            'title'   => 'Symantec VIP migration',
            'vip'     => $vip,
            'active'  => $radius->vipActive(),
            'state'   => $radius->state(),
            'groups'  => $radius->forwardingGroups(),
            'counts'  => $migration->counts(),
            'error'   => $error,
            'test'    => $test,
        ]);
    }

    public function group(): void
    {
        $this->requirePermission('radius.manage');
        $radius = new Radius();
        $id = $this->query('id', 32);
        $group = '' === $id ? null : ($radius->group($id) ?? $this->notFound('This server group does not exist.'));
        $input = $group ?? ['name' => '', 'description' => '', 'policy' => Radius::DEFAULT_POLICY];
        $error = null;
        if ($this->isPost()) {
            try {
                $saved = $radius->saveGroup($group['id'] ?? null, $_POST + ['name' => '', 'description' => '']);
                $this->audit->record(null === $group ? 'radius.group_create' : 'radius.group_update', 'success', $saved['name'], ['policy' => $saved['policy']]);
                if ($saved['policy']['vip_forward'] && !(new VipMigration())->isSeeded()) {
                    // first time forwarding is switched on: users already on SohobOTP stay on it
                    $job = Jobs::enqueue('radius.vip_seed', [], $this->admin['username']);
                    $this->audit->record('radius.vip_seed_requested', 'success', '', ['job' => $job['id'], 'reason' => 'forwarding switched on']);
                }
                Session::flash('success', 'Server group saved. Apply the configuration to activate it on FreeRADIUS.');
                $this->redirect('radius');
            } catch (ValidationException $invalid) {
                $error = $invalid->getMessage();
                $input = ['name' => $this->post('name', 64), 'description' => $this->post('description'), 'policy' => array_merge(Radius::DEFAULT_POLICY, array_intersect_key($_POST, Radius::DEFAULT_POLICY))];
            }
        }
        $known = [];
        foreach (MultiotpService::get()->ApiGetUsersArray(['page' => 1, 'itemsPerPage' => 1000000])['users'] ?? [] as $row) {
            foreach (explode(',', (string) ($row['group'] ?? '')) as $g) {
                if ('' !== trim($g)) {
                    $known[mb_strtolower(trim($g))] = trim($g);
                }
            }
        }
        ksort($known);
        $this->view->render('radius-group', ['title' => null === $group ? 'New server group' : 'Edit ' . $group['name'], 'group' => $group, 'input' => $input, 'error' => $error, 'knownGroups' => array_slice(array_values($known), 0, 40)]);
    }

    public function groupDelete(): void
    {
        $this->requirePermission('radius.manage');
        try {
            $group = (new Radius())->deleteGroup($this->post('id', 32));
            $this->audit->record('radius.group_delete', 'success', $group['name']);
            Session::flash('success', 'Server group deleted.');
        } catch (ValidationException $invalid) {
            Session::flash('error', $invalid->getMessage());
        }
        $this->redirect('radius');
    }

    public function client(): void
    {
        $this->requirePermission('radius.manage');
        $radius = new Radius();
        $groups = $radius->groups();
        if ([] === $groups) {
            Session::flash('info', 'Create a server group first: every server belongs to one.');
            $this->redirect('radius-group');
        }
        $id = $this->query('id', 32);
        $client = '' === $id ? null : ($radius->client($id) ?? $this->notFound('This server does not exist.'));
        $input = $client ?? ['name' => '', 'description' => '', 'address' => '', 'group_id' => $this->query('group', 32) ?: $groups[0]['id'], 'nas_type' => 'other', 'require_message_authenticator' => true];
        $error = null;
        if ($this->isPost()) {
            $input = [
                'name'        => $this->post('name', 40),
                'description' => $this->post('description'),
                'address'     => $this->post('address', 64),
                'group_id'    => $this->post('group_id', 32),
                'nas_type'    => $this->post('nas_type', 16),
                'require_message_authenticator' => !empty($_POST['require_message_authenticator']),
                'secret'      => (string) ($_POST['secret'] ?? ''),
            ];
            try {
                if (null === $client) {
                    [$created, $secret] = $radius->createClient($input);
                    $this->audit->record('radius.client_create', 'success', $created['name'], ['address' => $created['address'], 'group' => $created['group_id'], 'custom_secret' => '' !== trim($input['secret'])]);
                    $this->showSecret($created, $secret, 'Server added');
                }
                $updated = $radius->updateClient($client['id'], $input);
                $this->audit->record('radius.client_update', 'success', $updated['name'], ['address' => $updated['address'], 'group' => $updated['group_id']]);
                Session::flash('success', 'Server saved. Apply the configuration to activate the change.');
                $this->redirect('radius');
            } catch (ValidationException $invalid) {
                $error = $invalid->getMessage();
                unset($input['secret']);
            }
        }
        $this->view->render('radius-client', ['title' => null === $client ? 'Add server' : 'Edit ' . $client['name'], 'client' => $client, 'input' => $input, 'groups' => $groups, 'error' => $error]);
    }

    public function clientAction(): void
    {
        $this->requirePermission('radius.manage');
        if (!$this->isPost()) {
            $this->redirect('radius');
        }
        $radius = new Radius();
        $client = $radius->client($this->post('id', 32)) ?? $this->notFound('This server does not exist.');
        try {
            switch ($this->post('op', 16)) {
                case 'rotate-secret':
                    $secret = $radius->rotateSecret($client['id'], (string) ($_POST['secret'] ?? ''));
                    $this->audit->record('radius.secret_rotate', 'success', $client['name']);
                    $this->showSecret($client, $secret, 'New shared secret');
                case 'delete':
                    $radius->deleteClient($client['id']);
                    $this->audit->record('radius.client_delete', 'success', $client['name']);
                    Session::flash('success', 'Server deleted. Apply the configuration to remove it from FreeRADIUS.');
                    $this->redirect('radius');
            }
        } catch (ValidationException $invalid) {
            Session::flash('error', $invalid->getMessage());
        }
        $this->redirect('radius');
    }

    public function apply(): void
    {
        $this->requirePermission('radius.manage');
        if (!$this->isPost()) {
            $this->redirect('radius');
        }
        $job = Jobs::enqueue('radius.apply', [], $this->admin['username']);
        if (empty($job['already_active'])) {
            $this->audit->record('radius.apply_requested', 'success', '', ['job' => $job['id']]);
        }
        $this->redirect('job', ['id' => $job['id']]);
    }

    public function diagnostics(): void
    {
        $this->requirePermission('radius.view');
        $radius = new Radius();
        $test = null;
        if ($this->isPost()) {
            $this->requirePermission('radius.manage');
            $op = $this->post('op', 32);
            if ('test-login' === $op) {
                $user = $this->post('user', 128);
                $test = $radius->testLogin($user, mb_substr((string) ($_POST['password'] ?? ''), 0, 256));
                $this->audit->record('radius.test_login', 'accepted' === $test['result'] ? 'success' : 'failure', $user, ['result' => $test['result']]);
                $test['user'] = $user;
            } elseif ('disable-default-client' === $op) {
                $result = Radius::disableDefaultClient();
                $this->audit->record('radius.default_client_disable', $result['ok'] ? 'success' : 'failure', '', ['output' => mb_substr($result['output'], 0, 500)]);
                Session::flash($result['ok'] ? 'success' : 'error', $result['ok'] ? 'The install-time catch-all client was disabled.' : 'Could not disable it: ' . $result['output']);
                $this->redirect('radius-diagnostics');
            }
        }
        $filterUser = $this->query('user', 128);
        $filterResult = in_array($this->query('result', 16), ['accepted', 'rejected'], true) ? $this->query('result', 16) : '';
        $this->view->render('radius-diagnostics', [
            'title'     => 'RADIUS diagnostics',
            'status'    => Radius::status(),
            'state'     => $radius->state(),
            'logins'    => Radius::recentLogins($filterUser, $filterResult),
            'forwarded' => VipMigration::recentForwarded($filterUser),
            'filterUser'=> $filterUser,
            'filterResult' => $filterResult,
            'test'      => $test,
            'canManage' => $this->can('radius.manage'),
        ]);
    }

    private static function activeApply(): ?array
    {
        $job = Jobs::latest('radius.apply');
        return null !== $job && in_array($job['status'], Jobs::ACTIVE, true) ? $job : null;
    }

    private function showSecret(array $client, string $secret, string $title): never
    {
        $this->view->render('radius-secret', ['title' => $title, 'client' => $client, 'secret' => $secret]);
        exit;
    }
}
