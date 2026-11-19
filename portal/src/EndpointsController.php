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
            $endpoint['tamper'] = $endpoints->tamperState($endpoint);
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
            'title' => 'Computers',
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
        $shownCode = null; // the uninstall code, shown once in the answer to "Show the uninstall code"
        if ($this->isPost()) {
            $this->requirePermission('endpoints.manage');
            $name = $endpoint['inventory']['hostname'] ?: $endpoint['id'];
            try {
                switch ($this->post('op', 24)) {
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
                    case 'accounts':
                        $exempt = $endpoints->setCodeExempt($endpoint['id'], array_map('strval', (array) ($_POST['needs_code'] ?? [])), array_map('strval', (array) ($_POST['needs_code_admin'] ?? [])));
                        $this->audit->record('endpoint.code_exempt', 'success', $name, ['endpoint' => $endpoint['id'],
                            'no_code_at_signin' => implode(', ', $exempt['signin']), 'no_code_for_admin' => implode(', ', $exempt['admin'])]);
                        Session::flash('success', 'Saved. The computer applies it at its next check-in (within a minute or two).');
                        break;
                    case 'uninstall-code':
                    case 'uninstall-code-new':
                        // the code itself never goes to the audit trail, only who looked at it
                        $new = 'uninstall-code-new' === $this->post('op', 24);
                        $shownCode = $endpoints->uninstallCode($endpoint['id'], $new);
                        $this->audit->record($new ? 'endpoint.uninstall_code_new' : 'endpoint.uninstall_code_view', 'success', $name, ['endpoint' => $endpoint['id']]);
                        break;
                    case 'alerts-seen':
                        $count = $endpoints->markAlertsSeen($endpoint['id']);
                        $this->audit->record('endpoint.alerts_seen', 'success', $name, ['endpoint' => $endpoint['id'], 'alerts' => $count]);
                        Session::flash('success', 'Alerts marked as seen.');
                        break;
                    case 'create-user':
                        $this->requirePermission('users.manage');
                        $account = $this->post('account', 120);
                        $username = mb_strtolower((string) preg_replace('/^[^\\\\]*\\\\/', '', $account));
                        $users = new Users();
                        if (null !== ($invalid = Users::validateName($username))) {
                            throw new ValidationException($invalid);
                        }
                        if (!$users->exists($username)) {
                            $users->create(['user' => $username, 'display_name' => $username . ' on ' . $name, 'token_serial' => '']);
                            $this->audit->record('user.create', 'success', $username, ['via' => 'computer account', 'endpoint' => $endpoint['id']]);
                        }
                        Session::flash('success', 'SohobOTP user ' . $username . ' created. Scan its QR code now (Enrol new authenticator), then tick it on the computer.');
                        $this->redirect('user', ['u' => $username]);
                    case 'delete':
                        $endpoints->deleteEndpoint($endpoint['id']);
                        $this->audit->record('endpoint.delete', 'success', $name, ['endpoint' => $endpoint['id']]);
                        Session::flash('success', 'Endpoint deleted. To manage the machine again, re-install the agent with a new enrolment token.');
                        $this->redirect('endpoints');
                }
            } catch (ValidationException $invalid) {
                Session::flash('error', $invalid->getMessage());
            }
            if (null === $shownCode) {
                $this->redirect('endpoint', ['id' => $endpoint['id']]);
            }
            header('Cache-Control: no-store');
            $endpoint = $endpoints->endpoint($endpoint['id']) ?? $endpoint;
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
            'accounts' => $endpoints->accountsView($endpoint),
            'promptsOn' => '3' !== substr((string) (Endpoints::effectivePolicy($endpoints->group($endpoint['group_id'])['policy'] ?? [])['windows']['cpus_credui'] ?? '3e'), 0, 1),
            // accounts without a SohobOTP user that set up their code with the QR at the Windows sign-in screen
            'qrSetup' => (static function (array $w, bool $windows): array {
                $on = $windows && !empty($w['enrol_at_signin']);
                return ['domain' => $on, 'local' => $on && !empty($w['enrol_local'])];
            })(Endpoints::effectivePolicy($endpoints->group($endpoint['group_id'])['policy'] ?? [])['windows'], 'windows' === $endpoint['os']),
            'canManage' => $this->can('endpoints.manage'),
            'canCreateUsers' => $this->can('users.manage'),
            'tamper' => $endpoints->tamperState($endpoint),
            'alerts' => Endpoints::alerts($endpoint),
            'shownCode' => $shownCode,
            'portalReleaseKey' => AgentReleases::fingerprint(),
        ]);
    }

    public function groups(): void
    {
        $this->requirePermission('endpoints.view');
        $endpoints = new Endpoints();
        $groups = $endpoints->groups();
        $settings = (new Directory())->settings();
        $this->view->render('endpoint-groups', [
            'title' => 'Computer policies',
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
                foreach (['tamper_protection', 'linux_enabled', 'linux_ssh_keys_need_code', 'linux_require_message_authenticator', 'win_cache_enabled', 'win_enrol_at_signin', 'win_enrol_local', 'win_signin_auto', 'win_upn_format', 'win_without2fa', 'win_two_step_hide_otp', 'win_two_step_send_password'] as $flag) {
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
            'signinPackages' => SigninPackages::all(),
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
            'title' => 'Enrolment tokens',
            'tokens' => $endpoints->tokens(),
            'groups' => $groups,
            'names' => array_column($groups, 'name', 'id'),
            'pin' => $endpoints->pin(),
            'error' => $error,
        ]);
    }

    /**
     * Download agent: a new enrolment token built into the agent program, with the portal
     * address, the pin and the CA certificate (AgentBundle). The token exists only in the
     * download; the audit trail records who downloaded what, never the token.
     */
    public function agentDownload(): void
    {
        $this->requirePermission('endpoints.manage');
        $endpoints = new Endpoints();
        $groups = $endpoints->groups();
        if ([] === $groups) {
            Session::flash('info', 'Create an endpoint group first: every endpoint joins one when it enrols.');
            $this->redirect('endpoint-group');
        }
        $programs = [];
        foreach (AgentBundle::PLATFORMS as $platform => $label) {
            $programs[$platform] = AgentBundle::program($platform);
        }
        $values = [
            'platform' => '', 'group_id' => $groups[0]['id'], 'label' => '', 'hours' => '24', 'max_uses' => '1', 'approval' => 'directory',
            'portal' => 'https://' . self::host(), 'ca_pem' => AgentBundle::detectCa(),
        ];
        $error = null;
        $link = null; // an install link just made: shown once on the page
        if ($this->isPost()) {
            foreach (['platform' => 32, 'group_id' => 32, 'label' => 100, 'hours' => 4, 'max_uses' => 6, 'approval' => 16, 'portal' => 300] as $key => $max) {
                $values[$key] = $this->post($key, $max);
            }
            // "Install link" buttons send the platform as "link": the file is kept behind a one-time address
            $asLink = '' !== $this->post('link', 32);
            if ($asLink) {
                $values['platform'] = $this->post('link', 32);
            }
            $values['ca_pem'] = mb_substr((string) ($_POST['ca_pem'] ?? ''), 0, 70000);
            try {
                [$platform, $format, $downloadLabel] = AgentBundle::DOWNLOADS[$values['platform']] ?? ['', '', ''];
                if ($asLink && !str_starts_with($platform, 'linux/')) {
                    throw new ValidationException('Install links are for Linux machines. On Windows, download the agent and double-click it.');
                }
                $program = $programs[$platform] ?? null;
                if (null === $program) {
                    throw new ValidationException('Choose Windows or Linux. A greyed-out choice means the portal has no agent program for it yet.');
                }
                $portal = AgentBundle::validatePortal($values['portal']);
                $caPem = AgentBundle::validateCa($values['ca_pem']);
                [$token, $plain] = $endpoints->createToken(
                    $values['group_id'],
                    '' !== $values['label'] ? $values['label'] : 'Downloaded agent, ' . $downloadLabel,
                    (int) $values['hours'],
                    (int) $values['max_uses'],
                    $this->admin['username'],
                    $values['approval'] ?: 'none'
                );
                $trailer = AgentBundle::trailer($portal, $plain, $endpoints->pin(), $caPem);
                if ($asLink) {
                    [$os, $arch] = explode('/', $platform);
                    $deb = 'deb' === $format ? AgentDeb::build($program['file'], $trailer, $arch, $program['version'], time()) : null;
                    $made = AgentLinks::create(
                        $deb ?? ((string) file_get_contents($program['file']) . $trailer),
                        null !== $deb ? AgentDeb::fileName($token['id'], $arch) : 'sohobotp-agent-' . $token['id'] . ('arm64' === $arch ? '-arm64' : ''),
                        null !== $deb ? 'application/vnd.debian.binary-package' : 'application/octet-stream',
                        $token['expires_at'],
                        ['label' => $token['label'], 'token_id' => $token['id'], 'platform' => $platform, 'format' => $format, 'created_by' => $this->admin['username']],
                        time()
                    );
                    $this->audit->record('endpoint.agent_link_create', 'success', $token['label'], [
                        'token' => $token['id'], 'group' => $token['group_id'], 'platform' => $platform, 'format' => $format, 'portal' => $portal,
                        'agent' => $program['source'] . ('' !== $program['version'] ? ' ' . $program['version'] : ''), 'with_ca' => '' !== $caPem,
                        'sha256' => $made['sha256'], 'expires_at' => $made['expires_at'], 'max_uses' => $token['max_uses'], 'approval' => $token['approval'],
                    ]);
                    $url = $portal . '/portal/get.php?k=' . $made['key'];
                    $link = $made + ['url' => $url, 'format' => $format, 'label' => $downloadLabel, 'group' => $endpoints->group($token['group_id'])['name'] ?? '',
                        'commands' => AgentLinks::commands($url, $made['sha256'], $format, '' !== $caPem), 'approval' => $token['approval']];
                    header('Cache-Control: no-store');
                } else {
                    $this->audit->record('endpoint.agent_download', 'success', $token['label'], [
                        'token' => $token['id'], 'group' => $token['group_id'], 'platform' => $platform, 'format' => $format, 'portal' => $portal,
                        'agent' => $program['source'] . ('' !== $program['version'] ? ' ' . $program['version'] : ''), 'with_ca' => '' !== $caPem,
                        'expires_at' => $token['expires_at'], 'max_uses' => $token['max_uses'], 'approval' => $token['approval'],
                    ]);
                    [$os, $arch] = explode('/', $platform);
                    $deb = 'deb' === $format ? AgentDeb::build($program['file'], $trailer, $arch, $program['version'], time()) : null;
                    $name = null !== $deb ? AgentDeb::fileName($token['id'], $arch)
                        : 'sohobotp-agent-' . $token['id'] . ('windows' === $os ? ('arm64' === $arch ? '-arm64' : '') . '.exe' : ('arm64' === $arch ? '-arm64' : ''));
                    while (ob_get_level() > 0) {
                        ob_end_clean();
                    }
                    header('Content-Type: ' . (null !== $deb ? 'application/vnd.debian.binary-package' : 'application/octet-stream'));
                    header('Content-Disposition: attachment; filename="' . $name . '"');
                    header('Content-Length: ' . (null !== $deb ? strlen($deb) : $program['size'] + strlen($trailer)));
                    header('Cache-Control: no-store');
                    header('X-Content-Type-Options: nosniff');
                    if (null !== $deb) {
                        echo $deb;
                    } else {
                        readfile($program['file']);
                        echo $trailer;
                    }
                    exit;
                }
            } catch (ValidationException $invalid) {
                $error = $invalid->getMessage();
                http_response_code(400);
            }
        }
        $this->view->render('agent-download', [
            'title' => 'Add a computer',
            'groups' => $groups,
            'programs' => $programs,
            'values' => $values,
            'pin' => $endpoints->pin(),
            'error' => $error,
            'link' => $link,
            'openLinks' => AgentLinks::open(time()),
        ]);
    }

    /**
     * Group Policy kit (GpoKit): a zip with a computer startup script, the plain Windows agent
     * programs and a new enrolment token, for rolling the agent out to an OU. POST only, from
     * the "Add a computer" page; like a downloaded agent, the token exists only in the download.
     */
    public function gpoKit(): void
    {
        $this->requirePermission('endpoints.manage');
        if (!$this->isPost()) {
            $this->redirect('agent-download');
        }
        $endpoints = new Endpoints();
        try {
            $portal = AgentBundle::validatePortal($this->post('portal', 300));
            $caPem = AgentBundle::validateCa(mb_substr((string) ($_POST['ca_pem'] ?? ''), 0, 70000));
            $programs = [];
            foreach (['amd64', 'arm64'] as $arch) {
                $program = AgentBundle::program("windows/$arch");
                if (null !== $program) {
                    $programs[$arch] = $program;
                }
            }
            if ([] === $programs) {
                throw new ValidationException('The portal has no Windows agent program yet: add one first (see the list above).');
            }
            $group = $endpoints->group($this->post('group_id', 32)) ?? throw new ValidationException('Choose a computer policy.');
            $days = (int) $this->post('days', 4);
            [$token, $plain] = $endpoints->createToken(
                $group['id'],
                '' !== $this->post('label', 100) ? $this->post('label', 100) : 'Group Policy kit',
                24 * $days,
                (int) $this->post('max_uses', 6),
                $this->admin['username'],
                $this->post('approval', 16) ?: 'directory',
                24 * 365
            );
            $policy = Endpoints::effectivePolicy($group['policy']);
            $now = time();
            $zip = GpoKit::build($portal, $plain, $endpoints->pin(), $caPem, array_map(static fn (array $p): string => $p['file'], $programs), [
                'group' => $group['name'], 'expires_at' => $token['expires_at'], 'max_uses' => $token['max_uses'], 'approval' => $token['approval'],
                'tamper' => $policy['tamper_protection'], 'signin_auto' => !empty($policy['windows']['signin_auto']),
            ], $now);
            $this->audit->record('endpoint.gpo_kit', 'success', $token['label'], [
                'token' => $token['id'], 'group' => $token['group_id'], 'portal' => $portal, 'with_ca' => '' !== $caPem,
                'agents' => implode(', ', array_map(static fn (string $a, array $p): string => "$a " . ('' !== $p['version'] ? $p['version'] : $p['source']), array_keys($programs), $programs)),
                'expires_at' => $token['expires_at'], 'max_uses' => $token['max_uses'], 'approval' => $token['approval'],
            ]);
            while (ob_get_level() > 0) {
                ob_end_clean();
            }
            header('Content-Type: application/zip');
            header('Content-Disposition: attachment; filename="SohobOTP-GroupPolicy-' . $token['id'] . '.zip"');
            header('Content-Length: ' . strlen($zip));
            header('Cache-Control: no-store');
            header('X-Content-Type-Options: nosniff');
            echo $zip;
            exit;
        } catch (ValidationException $invalid) {
            Session::flash('error', 'Group Policy kit: ' . $invalid->getMessage());
            $this->redirect('agent-download');
        }
    }

    /**
     * "Windows sign-in installers": what the agent installs by itself (computer policy "Install
     * and update SohobOTP Sign-in automatically"), which computers have which Sign-in version,
     * and an upload form (the same checks as portal-admin.php signin-package-add).
     */
    public function signinPackages(): void
    {
        $this->requirePermission('endpoints.manage');
        $error = null;
        if ($this->isPost()) {
            $kind = $this->post('kind', 32);
            $version = $this->post('version', 32);
            $file = $_FILES['installer'] ?? null;
            try {
                if (!is_array($file) || UPLOAD_ERR_OK !== ($file['error'] ?? UPLOAD_ERR_NO_FILE) || !is_uploaded_file((string) $file['tmp_name'])) {
                    throw new ValidationException(is_array($file) && in_array($file['error'] ?? 0, [UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE], true)
                        ? 'The file is too large for this server.' : 'Choose the installer file.');
                }
                $added = SigninPackages::add((string) $file['tmp_name'], $kind, $version);
                $this->audit->record('signin.package_add', 'success', $added['kind'], ['version' => $added['version'], 'sha256' => $added['sha256'], 'size' => $added['size'], 'via' => 'portal']);
                Session::flash('success', SigninPackages::KINDS[$added['kind']]['label'] . ' ' . $added['version'] . ' added. Computers whose policy installs Sign-in automatically get it at their next check-in.');
                $this->redirect('signin-packages');
            } catch (ValidationException $invalid) {
                $error = $invalid->getMessage();
                http_response_code(400);
            }
        }
        $endpoints = new Endpoints();
        $versions = [];
        foreach ($endpoints->endpoints() as $e) {
            if ('windows' === $e['os'] && null !== $e['last_seen']) {
                $v = (string) ($e['inventory']['component']['version'] ?? '');
                $versions['' === $v ? 'not installed' : $v] = ($versions['' === $v ? 'not installed' : $v] ?? 0) + 1;
            }
        }
        uksort($versions, static fn (string $a, string $b): int => strnatcmp($b, $a));
        $autoGroups = array_values(array_filter($endpoints->groups(), static fn (array $g): bool => !empty(Endpoints::effectivePolicy($g['policy'])['windows']['signin_auto'])));
        $this->view->render('signin-packages', [
            'title' => 'Windows sign-in installers',
            'packages' => SigninPackages::all(),
            'versions' => $versions,
            'autoGroups' => $autoGroups,
            'groups' => $endpoints->groups(),
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
        $unseen = array_values(array_filter(Endpoints::alerts($endpoint), static fn (array $a): bool => empty($a['seen'])));
        if ([] !== $unseen) {
            return 'Tamper alert' . (count($unseen) > 1 ? ' (' . count($unseen) . ' new)' : '') . ': ' . (Endpoints::EVENT_KINDS[$unseen[0]['kind']] ?? $unseen[0]['kind']) . ' (' . format_time($unseen[0]['at']) . ').';
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
