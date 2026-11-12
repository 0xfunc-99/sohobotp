<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/** Endpoints (agents), endpoint groups and enrolment tokens. */
final class EndpointsController extends Controller
{
    public function index(): void
    {
        $this->requirePermission('endpoints.view');
        $endpoints = new Endpoints();
        $groups = $endpoints->groups();
        $list = $endpoints->endpoints();
        $groupFilter = $this->query('group', 32);
        $healthFilter = $this->query('health', 16);
        $rows = [];
        $counts = ['online' => 0, 'offline' => 0, 'never' => 0, 'pending' => 0, 'disabled' => 0, 'attention' => 0];
        foreach ($list as $endpoint) {
            $endpoint['health'] = $endpoints->health($endpoint);
            $endpoint['attention'] = self::attention($endpoint);
            $counts[$endpoint['health']]++;
            $counts['attention'] += null !== $endpoint['attention'] ? 1 : 0;
            if ('' !== $groupFilter && $endpoint['group_id'] !== $groupFilter) {
                continue;
            }
            if ('' !== $healthFilter && $endpoint['health'] !== $healthFilter && !('attention' === $healthFilter && null !== $endpoint['attention'])) {
                continue;
            }
            $rows[] = $endpoint;
        }
        $this->view->render('endpoints', [
            'title' => 'Endpoints',
            'rows' => $rows,
            'total' => count($list),
            'counts' => $counts,
            'groups' => $groups,
            'names' => array_column($groups, 'name', 'id'),
            'groupFilter' => $groupFilter,
            'healthFilter' => $healthFilter,
            'coverage' => $endpoints->coverage(),
            'adReady' => (static function (): bool { $d = (new Directory())->settings(); return $d['enabled'] && 1 === $d['server_type']; })(),
            'canManage' => $this->can('endpoints.manage'),
        ]);
    }

    public function endpoint(): void
    {
        $this->requirePermission('endpoints.view');
        $endpoints = new Endpoints();
        $endpoint = $endpoints->endpoint($this->query('id', 20)) ?? $this->notFound('This endpoint does not exist.');
        if ($this->isPost()) {
            $this->requirePermission('endpoints.manage');
            $name = $endpoint['inventory']['hostname'] ?: $endpoint['id'];
            try {
                switch ($this->post('op', 16)) {
                    case 'approve':
                        $endpoints->approve($endpoint['id']);
                        $this->audit->record('endpoint.approve', 'success', $name, ['endpoint' => $endpoint['id'], 'by' => 'admin']);
                        Session::flash('success', 'Endpoint approved. It receives its configuration at its next check-in.');
                        break;
                    case 'reject':
                        if ('pending' !== $endpoint['status']) {
                            throw new ValidationException('Only machines waiting for approval can be rejected.');
                        }
                        $endpoints->deleteEndpoint($endpoint['id']);
                        $this->audit->record('endpoint.reject', 'success', $name, ['endpoint' => $endpoint['id'], 'ip' => $endpoint['enrolled_ip']]);
                        Session::flash('success', 'Enrolment rejected and removed.');
                        $this->redirect('endpoints');
                    case 'unlock-group':
                        $endpoints->unlockGroup($endpoint['id']);
                        Jobs::enqueue('endpoints.directory', [], $this->admin['username']);
                        $this->audit->record('endpoint.group_unlock', 'success', $name, ['endpoint' => $endpoint['id']]);
                        Session::flash('success', 'The Active Directory rules choose this machine\'s group again (checked in the background).');
                        break;
                    case 'move':
                        $moved = $endpoints->moveEndpoint($endpoint['id'], $this->post('group_id', 32));
                        $this->audit->record('endpoint.move', 'success', $name, ['endpoint' => $endpoint['id'], 'from' => $endpoint['group_id'], 'to' => $moved['group_id']]);
                        Session::flash('success', 'Endpoint moved. It receives the new policy at its next check-in.');
                        break;
                    case 'disable':
                        $endpoints->setStatus($endpoint['id'], false);
                        $this->audit->record('endpoint.disable', 'success', $name, ['endpoint' => $endpoint['id']]);
                        Session::flash('success', 'Endpoint disabled: its agent is refused and its secrets were revoked.');
                        break;
                    case 'enable':
                        $endpoints->setStatus($endpoint['id'], true);
                        $this->audit->record('endpoint.enable', 'success', $name, ['endpoint' => $endpoint['id']]);
                        Session::flash('success', 'Endpoint enabled. It receives new secrets at its next check-in.');
                        break;
                    case 'delete':
                        $endpoints->deleteEndpoint($endpoint['id']);
                        $this->audit->record('endpoint.delete', 'success', $name, ['endpoint' => $endpoint['id']]);
                        Session::flash('success', 'Endpoint deleted. To manage the machine again, re-install the agent with a new enrolment token.');
                        $this->redirect('endpoints');
                }
            } catch (ValidationException $invalid) {
                Session::flash('error', $invalid->getMessage());
            }
            $this->redirect('endpoint', ['id' => $endpoint['id']]);
        }
        $endpoint['health'] = $endpoints->health($endpoint);
        $endpoint['attention'] = self::attention($endpoint);
        $groups = $endpoints->groups();
        $radiusClient = '' !== ($endpoint['radius_client_id'] ?? '') ? (new Radius())->client($endpoint['radius_client_id']) : null;
        $this->view->render('endpoint', [
            'title' => $endpoint['inventory']['hostname'] ?: $endpoint['id'],
            'endpoint' => $endpoint,
            'group' => $endpoints->group($endpoint['group_id']),
            'groups' => $groups,
            'radiusClient' => $radiusClient,
            'canManage' => $this->can('endpoints.manage'),
        ]);
    }

    public function groups(): void
    {
        $this->requirePermission('endpoints.view');
        $endpoints = new Endpoints();
        $groups = $endpoints->groups();
        $settings = (new Directory())->settings();
        $this->view->render('endpoint-groups', [
            'title' => 'Endpoint groups',
            'groups' => $groups,
            'names' => array_column($groups, 'name', 'id'),
            'rules' => $endpoints->rules(),
            'adReady' => $settings['enabled'] && 1 === $settings['server_type'],
            'lastCheck' => Jobs::latest('endpoints.directory'),
            'radiusNames' => array_column((new Radius())->groups(), 'name', 'id'),
            'canManage' => $this->can('endpoints.manage'),
        ]);
    }

    public function group(): void
    {
        $this->requirePermission('endpoints.manage');
        $endpoints = new Endpoints();
        $id = $this->query('id', 32);
        $group = '' === $id ? null : ($endpoints->group($id) ?? $this->notFound('This endpoint group does not exist.'));
        $template = null === $group ? $this->query('template', 16) : '';
        $template = isset(Endpoints::TEMPLATES[$template]) ? $template : '';
        $input = ['name' => $group['name'] ?? '', 'description' => $group['description'] ?? '']
            + (null === $group ? Endpoints::templateInput($template) : Endpoints::policyToInput($group['policy']));
        $error = null;
        if ($this->isPost()) {
            try {
                $saved = $endpoints->saveGroup($group['id'] ?? null, $_POST);
                $this->audit->record(null === $group ? 'endpoint.group_create' : 'endpoint.group_update', 'success', $saved['name'], ['policy' => $saved['policy']]);
                Session::flash('success', 'Endpoint group saved. Its endpoints receive the policy at their next check-in.');
                $this->redirect('endpoint-groups');
            } catch (ValidationException $invalid) {
                $error = $invalid->getMessage();
                $input = array_merge($input, array_map(static fn ($v) => is_array($v) ? $v : (string) $v, $_POST));
                foreach (['linux_enabled', 'linux_ssh_keys_need_code', 'linux_require_message_authenticator', 'win_cache_enabled', 'win_upn_format', 'win_without2fa', 'win_two_step_hide_otp', 'win_two_step_send_password'] as $flag) {
                    $input[$flag] = !empty($_POST[$flag]);
                }
                $input['linux_services'] = (array) ($_POST['linux_services'] ?? []);
            }
        }
        $this->view->render('endpoint-group', [
            'title' => null === $group ? 'New endpoint group' : 'Edit ' . $group['name'],
            'group' => $group,
            'input' => $input,
            'radiusGroups' => (new Radius())->groups(),
            'template' => $template,
            'error' => $error,
        ]);
    }

    /** Active Directory assignment rules (POST only). */
    public function rules(): void
    {
        $this->requirePermission('endpoints.manage');
        if (!$this->isPost()) {
            $this->redirect('endpoint-groups');
        }
        $endpoints = new Endpoints();
        try {
            switch ($this->post('op', 16)) {
                case 'add':
                    $rule = $endpoints->addRule($this->post('type', 8), $this->post('value', 512), $this->post('group_id', 32));
                    $this->audit->record('endpoint.rule_add', 'success', $rule['value'], ['rule' => $rule]);
                    Jobs::enqueue('endpoints.directory', [], $this->admin['username']);
                    Session::flash('success', 'Rule added. Machines are re-checked in the background.');
                    break;
                case 'delete':
                    $rule = $endpoints->deleteRule($this->post('id', 12));
                    $this->audit->record('endpoint.rule_delete', 'success', $rule['value'], ['rule' => $rule]);
                    Session::flash('success', 'Rule deleted. Machines stay in their current group.');
                    break;
                case 'up':
                case 'down':
                    $endpoints->moveRule($this->post('id', 12), 'up' === $this->post('op', 16) ? -1 : 1);
                    $this->audit->record('endpoint.rule_order', 'success', $this->post('id', 12), ['direction' => $this->post('op', 16)]);
                    Jobs::enqueue('endpoints.directory', [], $this->admin['username']);
                    break;
                case 'coverage':
                    $coverage = $endpoints->checkCoverage();
                    $this->audit->record('endpoint.coverage_check', 'success', '', array_diff_key($coverage, ['unprotected' => true, 'checked_at' => true]));
                    Session::flash('success', 0 === count($coverage['unprotected'])
                        ? 'Every enabled computer in Active Directory has the SohobOTP agent.'
                        : count($coverage['unprotected']) . ' enabled computer(s) in Active Directory have no SohobOTP agent.');
                    $this->redirect('endpoints');
                    // no break: redirect() ends the request
                case 'check':
                    $job = Jobs::enqueue('endpoints.directory', [], $this->admin['username']);
                    $this->audit->record('endpoint.directory_check', 'success', '', ['job' => $job['id']]);
                    $this->redirect('job', ['id' => $job['id']]);
            }
        } catch (ValidationException $invalid) {
            Session::flash('error', $invalid->getMessage());
        }
        $this->redirect('coverage' === $this->post('op', 16) ? 'endpoints' : 'endpoint-groups');
    }

    public function groupDelete(): void
    {
        $this->requirePermission('endpoints.manage');
        try {
            $group = (new Endpoints())->deleteGroup($this->post('id', 32));
            $this->audit->record('endpoint.group_delete', 'success', $group['name']);
            Session::flash('success', 'Endpoint group deleted.');
        } catch (ValidationException $invalid) {
            Session::flash('error', $invalid->getMessage());
        }
        $this->redirect('endpoint-groups');
    }

    public function enrol(): void
    {
        $this->requirePermission('endpoints.manage');
        $endpoints = new Endpoints();
        $groups = $endpoints->groups();
        $error = null;
        if ($this->isPost()) {
            try {
                switch ($this->post('op', 16)) {
                    case 'create':
                        [$token, $plain] = $endpoints->createToken(
                            $this->post('group_id', 32),
                            $this->post('label', 100),
                            (int) $this->post('hours', 4),
                            (int) $this->post('max_uses', 6),
                            $this->admin['username'],
                            $this->post('approval', 16) ?: 'none'
                        );
                        $this->audit->record('endpoint.token_create', 'success', $token['label'], [
                            'token' => $token['id'], 'group' => $token['group_id'], 'expires_at' => $token['expires_at'], 'max_uses' => $token['max_uses'], 'approval' => $token['approval'],
                        ]);
                        $this->view->render('endpoint-token', [
                            'title' => 'Enrolment token created',
                            'token' => $token,
                            'plain' => $plain,
                            'group' => $endpoints->group($token['group_id']),
                            'pin' => $endpoints->pin(),
                            'portal' => 'https://' . self::host(),
                        ]);
                        return;
                    case 'revoke':
                        $token = $endpoints->revokeToken($this->post('id', 12));
                        $this->audit->record('endpoint.token_revoke', 'success', $token['label'], ['token' => $token['id']]);
                        Session::flash('success', 'Enrolment token revoked.');
                        $this->redirect('endpoint-enrol');
                }
            } catch (ValidationException $invalid) {
                $error = $invalid->getMessage();
            }
        }
        if ([] === $groups) {
            Session::flash('info', 'Create an endpoint group first: every endpoint joins one when it enrols.');
            $this->redirect('endpoint-group');
        }
        $this->view->render('endpoint-enrol', [
            'title' => 'Enrol endpoints',
            'tokens' => $endpoints->tokens(),
            'groups' => $groups,
            'names' => array_column($groups, 'name', 'id'),
            'pin' => $endpoints->pin(),
            'error' => $error,
        ]);
    }

    /** Reason an endpoint needs the administrator's attention, or null. */
    private static function attention(array $endpoint): ?string
    {
        if ('disabled' === $endpoint['status']) {
            return null;
        }
        if ('pending' === $endpoint['status']) {
            return 'Waiting for approval' . ('' !== ($endpoint['approval_note'] ?? '') ? ': ' . $endpoint['approval_note'] : '.');
        }
        $adName = (string) ($endpoint['ad_name'] ?? '');
        if ('' !== $adName && '' !== $endpoint['inventory']['hostname'] && 0 !== strcasecmp(explode('.', $adName)[0], explode('.', $endpoint['inventory']['hostname'])[0])) {
            return 'The machine now reports the host name "' . $endpoint['inventory']['hostname'] . '" but is bound to the computer account ' . strtoupper($adName) . '. If it was renamed, delete it and enrol it again.';
        }
        if ('' !== ($endpoint['radius_error'] ?? '')) {
            return $endpoint['radius_error'];
        }
        if ('' !== ($endpoint['config']['error'] ?? '')) {
            return $endpoint['config']['error'];
        }
        if ('failed' === $endpoint['applied']['status']) {
            return 'Last configuration failed on the machine: ' . ($endpoint['applied']['error'] ?: 'no details');
        }
        return null;
    }

    private static function host(): string
    {
        $host = (string) ($_SERVER['HTTP_HOST'] ?? 'localhost');
        return preg_match('/^(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]{1,253})(:\d{1,5})?$/', $host) ? strtolower($host) : 'localhost';
    }
}
