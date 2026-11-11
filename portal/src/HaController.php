<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/** High availability page (permission database.manage). */
final class HaController extends Controller
{
    public function index(): void
    {
        $this->requirePermission('database.manage');
        $ha = new Ha();
        $error = null;
        $code = null;
        if ($this->isPost()) {
            $op = $this->post('op', 16);
            try {
                switch ($op) {
                    case 'pair':
                        $secondary = $this->post('secondary_ip', 15);
                        $code = $ha->pair($this->post('primary_ip', 15), $secondary, $this->post('portal_url', 255));
                        $this->audit->record('ha.pair', 'success', $secondary, ['primary' => $this->post('primary_ip', 15)]);
                        $this->view->render('ha-code', ['title' => 'Pairing code', 'code' => $code, 'secondary' => $secondary]);
                        exit;
                    case 'join':
                        $ha->join((string) ($_POST['code'] ?? ''));
                        $this->audit->record('ha.join', 'success', (string) ($ha->state()['primary_ip'] ?? ''));
                        Session::flash('success', 'This appliance is now the secondary: it replicates the primary and copies its RADIUS configuration every minute.');
                        $this->redirect('ha');
                    case 'promote':
                        $ha->promote($this->admin['username']);
                        $this->audit->record('ha.promote', 'success', (string) ($ha->state()['primary_ip'] ?? ''), ['by' => $this->admin['username']]);
                        Session::flash('success', 'This appliance is now a primary: it answers RADIUS logins with its own database.');
                        $this->redirect('ha');
                    case 'auto':
                        $minutes = (int) $this->post('minutes', 4);
                        $ha->setAutoPromote($minutes);
                        $this->audit->record('ha.auto_promote', 'success', '', ['minutes' => $minutes]);
                        Session::flash('success', 0 === $minutes ? 'Automatic promotion off.' : "Automatic promotion after $minutes minute(s) without the primary.");
                        $this->redirect('ha');
                    case 'sync':
                        $ha->sync(true);
                        $this->redirect('ha');
                    default:
                        $this->notFound('Unknown action.');
                }
            } catch (ValidationException $invalid) {
                $error = $invalid->getMessage();
                $this->audit->record('ha.' . $op, 'failure', '', ['reason' => $error]);
            }
        }
        $state = $ha->state();
        $this->view->render('ha', [
            'title'    => 'High availability',
            'state'    => $state,
            'db'       => Database::current(),
            'helper'   => Database::helper('ha-status'),
            'host'     => (string) ($_SERVER['HTTP_HOST'] ?? ''),
            'error'    => $error,
        ]);
    }
}
