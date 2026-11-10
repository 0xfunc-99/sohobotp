<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/** AD/LDAP settings, connection test, preview, sync now, schedule, job history and progress. */
final class DirectoryController extends Controller
{
    public function index(?array $test = null, ?string $error = null, ?array $input = null): void
    {
        $this->requirePermission('settings.view', 'sync.view', 'directory.manage');
        $directory = new Directory();
        $state = $directory->state();
        $this->view->render('directory', [
            'title'     => 'Directory (AD/LDAP)',
            'settings'  => $input ?? $directory->settings(),
            'hasPassword' => $directory->settings()['has_password'],
            'lastSync'  => $state['last_sync'] ?? null,
            'nextRun'   => !empty($state['schedule']['enabled']) ? ($state['last_scheduled_at'] ?? 0) + 60 * (int) $state['schedule']['minutes'] : null,
            'jobs'      => array_slice(Jobs::all(), 0, 5),
            'active'    => array_values(array_filter(Jobs::all(), static fn (array $j): bool => in_array($j['status'], Jobs::ACTIVE, true))),
            'test'      => $test,
            'error'     => $error,
            'perm'      => [
                'manage' => $this->can('directory.manage'),
                'sync'   => $this->can('sync.run'),
                'jobs'   => $this->can('sync.view') || $this->can('directory.manage'),
            ],
        ]);
    }

    public function save(): void
    {
        $this->requirePermission('directory.manage');
        if (!$this->isPost()) {
            $this->redirect('directory');
        }
        $input = [];
        foreach (['server_type', 'domain_controllers', 'port', 'base_dn', 'users_dn', 'bind_dn', 'account_suffix', 'in_groups', 'without2fa_groups',
                  'cn_identifier', 'group_attribute', 'group_cn_identifier', 'synced_user_attribute', 'language_attribute', 'default_algorithm',
                  'delete_retention_days', 'network_timeout', 'tls_reqcert', 'schedule_minutes'] as $field) {
            $input[$field] = $this->post($field, 1024);
        }
        $input['ldap_filter'] = $this->post('ldap_filter', 4096);
        foreach (['enabled', 'ssl', 'recursive_groups', 'opt_in_2fa', 'request_ldap_password', 'dont_auto_disable', 'dont_auto_enable', 'schedule_enabled'] as $flag) {
            $input[$flag] = !empty($_POST[$flag]);
        }
        $password = (string) ($_POST['bind_password'] ?? '');
        try {
            $changes = (new Directory())->save($input, '' === $password ? null : mb_substr($password, 0, 512));
            $this->audit->record('directory.settings_update', 'success', '', ['changes' => $changes]);
            Session::flash('success', [] === $changes ? 'Nothing changed.' : 'Directory settings saved.');
            $this->redirect('directory');
        } catch (ValidationException $invalid) {
            $this->index(null, $invalid->getMessage(), $input + ['has_password' => false]);
        }
    }

    public function test(): void
    {
        $this->requirePermission('directory.manage');
        if (!$this->isPost()) {
            $this->redirect('directory');
        }
        try {
            $result = (new Directory())->testConnection();
        } catch (ValidationException $invalid) {
            $result = ['ok' => false, 'message' => $invalid->getMessage(), 'log' => []];
        }
        $this->audit->record('directory.test', $result['ok'] ? 'success' : 'failure');
        $this->index($result);
    }

    public function run(): void
    {
        $op = $this->post('op', 16);
        $this->requirePermission('preview' === $op ? 'directory.manage' : 'sync.run');
        if (!$this->isPost() || !in_array($op, ['sync', 'preview'], true)) {
            $this->redirect('directory');
        }
        $job = Jobs::enqueue('directory.' . $op, [], $this->admin['username']);
        if (empty($job['already_active'])) {
            $this->audit->record('directory.' . $op . '_requested', 'success', '', ['job' => $job['id']]);
        } else {
            Session::flash('info', 'This job was already queued or running; showing it.');
        }
        $this->redirect('job', ['id' => $job['id']]);
    }

    public function jobs(): void
    {
        $this->requirePermission('sync.view', 'directory.manage');
        $this->view->render('jobs', ['title' => 'Background jobs', 'jobs' => Jobs::all()]);
    }

    public function job(): void
    {
        $this->requirePermission('sync.view', 'directory.manage');
        $job = Jobs::find($this->query('id', 64)) ?? $this->notFound('This job does not exist (old jobs are removed after 200 newer ones).');
        $this->view->render('job', [
            'title'     => self::label($job['type']),
            'job'       => $job,
            'engine'    => 'running' === $job['status'] ? (new Directory())->engineProgress() : '',
            'canCancel' => $this->can('sync.run') && in_array($job['status'], Jobs::ACTIVE, true),
        ]);
    }

    /** JSON used by the job page to refresh progress. */
    public function jobStatus(): void
    {
        $this->requirePermission('sync.view', 'directory.manage');
        $job = Jobs::find($this->query('id', 64));
        if (null === $job) {
            http_response_code(404);
            $this->json(['error' => 'not found']);
        }
        $this->json([
            'status'   => $job['status'],
            'progress' => $job['progress'],
            'engine'   => 'running' === $job['status'] ? (new Directory())->engineProgress() : '',
        ]);
    }

    public function cancel(): void
    {
        $this->requirePermission('sync.run');
        $job = Jobs::find($this->post('id', 64)) ?? $this->notFound('This job does not exist.');
        $updated = Jobs::cancel($job['id']);
        if ('running' === $job['status'] && 'directory.sync' === $job['type']) {
            (new Directory())->requestStop();
        }
        $this->audit->record('job.cancel', 'success', $job['id'], ['type' => $job['type'], 'status' => $updated['status'] ?? '']);
        Session::flash('info', 'running' === $job['status'] ? 'Stop requested. The sync stops after the current entry.' : 'Job cancelled.');
        $this->redirect('job', ['id' => $job['id']]);
    }

    public static function label(string $type): string
    {
        return match ($type) {
            'directory.sync'    => 'Directory sync',
            'directory.preview' => 'Sync preview',
            'radius.apply'      => 'RADIUS configuration',
            'radius.vip_seed'   => 'Symantec VIP migration: users already on SohobOTP',
            'endpoints.directory' => 'Endpoint check in Active Directory',
            default             => $type,
        };
    }
}
