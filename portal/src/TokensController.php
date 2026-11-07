<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/** Hardware tokens: inventory, import from token files, delete unassigned tokens. */
final class TokensController extends Controller
{
    private const MAX_UPLOAD = 5 * 1024 * 1024;

    public function index(): void
    {
        $this->requirePermission('tokens.view');
        $this->view->render('tokens', [
            'title'     => 'Hardware tokens',
            'tokens'    => (new Tokens())->all(),
            'canManage' => $this->can('tokens.manage'),
        ]);
    }

    public function import(): void
    {
        $this->requirePermission('tokens.manage');
        $file = $_FILES['token_file'] ?? null;
        if (!$this->isPost() || !is_array($file) || UPLOAD_ERR_OK !== ($file['error'] ?? UPLOAD_ERR_NO_FILE) || !is_uploaded_file($file['tmp_name'])) {
            Session::flash('error', 'Choose a token file to import.');
            $this->redirect('tokens');
        }
        if ($file['size'] > self::MAX_UPLOAD) {
            Session::flash('error', 'The file is larger than 5 MB.');
            $this->redirect('tokens');
        }
        $name = basename((string) $file['name']);
        try {
            $imported = (new Tokens())->import($file['tmp_name'], $name, (string) ($_POST['password'] ?? ''));
            $this->audit->record('token.import', 'success', $name, ['count' => count($imported), 'serials' => array_slice($imported, 0, 50)]);
            Session::flash('success', count($imported) . ' token(s) imported from ' . $name . '.');
        } catch (ValidationException $invalid) {
            $this->audit->record('token.import', 'failure', $name, ['reason' => $invalid->getMessage()]);
            Session::flash('error', $invalid->getMessage());
        } finally {
            @unlink($file['tmp_name']);
        }
        $this->redirect('tokens');
    }

    public function action(): void
    {
        $this->requirePermission('tokens.manage');
        if (!$this->isPost() || 'delete' !== $this->post('op', 16)) {
            $this->redirect('tokens');
        }
        $serial = $this->post('serial', 128);
        try {
            (new Tokens())->delete($serial);
            $this->audit->record('token.delete', 'success', $serial);
            Session::flash('success', "Token $serial deleted.");
        } catch (ValidationException $invalid) {
            $this->audit->record('token.delete', 'denied', $serial, ['reason' => $invalid->getMessage()]);
            Session::flash('error', $invalid->getMessage());
        }
        $this->redirect('tokens');
    }
}
