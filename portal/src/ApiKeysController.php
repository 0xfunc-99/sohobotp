<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/** API keys for the REST API (super administrators: permission api.manage). */
final class ApiKeysController extends Controller
{
    public function index(): void
    {
        $this->requirePermission('api.manage');
        $keys = new ApiKeys();
        $error = null;
        $input = ['name' => '', 'scopes' => [], 'networks' => '', 'expires_days' => '365', 'rate' => '120'];
        if ($this->isPost()) {
            $op = $this->post('op', 16);
            try {
                if ('create' === $op) {
                    $input = ['name' => $this->post('name', 64), 'scopes' => array_map('strval', (array) ($_POST['scopes'] ?? [])),
                        'networks' => $this->post('networks', 2000), 'expires_days' => $this->post('expires_days', 8), 'rate' => $this->post('rate', 8)];
                    [$record, $secret] = $keys->create($input, $this->admin['username']);
                    $this->audit->record('api_key.create', 'success', $record['name'], ['scopes' => $record['scopes'], 'networks' => $record['networks'], 'expires_at' => $record['expires_at'], 'rate' => $record['rate']]);
                    $this->view->render('api-key-secret', ['title' => 'API key created', 'key' => $record, 'secret' => $secret]);
                    exit;
                }
                if ('revoke' === $op) {
                    $revoked = $keys->revoke($this->post('id', 32));
                    $this->audit->record('api_key.revoke', 'success', $revoked['name']);
                    Session::flash('success', 'API key ' . $revoked['name'] . ' revoked: it stops working at once.');
                    $this->redirect('api-keys');
                }
                $this->notFound('Unknown action.');
            } catch (ValidationException $invalid) {
                $error = $invalid->getMessage();
            }
        }
        $this->view->render('api-keys', ['title' => 'API keys', 'keys' => $keys->all(), 'input' => $input, 'error' => $error]);
    }
}
