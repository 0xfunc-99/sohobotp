<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/** Database: files or MariaDB / MySQL (super administrators: permission database.manage). */
final class DatabaseController extends Controller
{
    public function index(): void
    {
        $this->requirePermission('database.manage');
        $current = Database::current();
        $error = null;
        $test = null;
        $input = ['host' => '', 'port' => '3306', 'database' => 'sohobotp', 'user' => 'sohobotp', 'tls' => false];
        if ($this->isPost()) {
            $op = $this->post('op', 16);
            try {
                if ('engine-key' === $op) {
                    if ('secondary' === ((new Ha())->state()['role'] ?? 'none')) {
                        throw new ValidationException('This appliance is an HA secondary: it takes the key from its primary.');
                    }
                    $summary = EngineKey::protect();
                    if ($summary['changed']) {
                        $this->audit->record('engine.key_protected', [] === $summary['failed'] ? 'success' : 'failure', '', $summary);
                    }
                    Session::flash([] === $summary['failed'] ? 'success' : 'error', [] === $summary['failed']
                        ? 'Token secrets are now encrypted with a private key. Back up ' . EngineKey::path() . ' with your data.'
                        : 'Some records could not be re-encrypted: ' . implode(', ', array_slice($summary['failed'], 0, 20)));
                    $this->redirect('database');
                }
                if ('files' !== $current['backend']) {
                    throw new ValidationException('The data is already in a database.');
                }
                if ('local' === $op) {
                    $connection = Database::prepareLocal();
                    $this->startMigration($connection, 'MariaDB on this appliance');
                }
                if ('test' === $op || 'external' === $op) {
                    $input = ['host' => $this->post('host', 253), 'port' => $this->post('port', 5), 'database' => $this->post('database', 64),
                        'user' => $this->post('user', 80), 'tls' => !empty($_POST['tls'])];
                    $connection = Database::validate($input + ['password' => (string) ($_POST['password'] ?? '')]);
                    $test = Database::test($connection);
                    $this->audit->record('database.test', $test['ok'] ? 'success' : 'failure', $connection['host'], ['database' => $connection['database'], 'user' => $connection['user']]);
                    if ('external' === $op && $test['ok']) {
                        $this->startMigration($connection, $connection['host']);
                    }
                }
            } catch (ValidationException $invalid) {
                $error = $invalid->getMessage();
            }
        }
        $this->view->render('database', [
            'title'   => 'Database',
            'dbNow'   => $current,
            'counts'  => Database::counts(),
            'helper'  => Database::helper('status'),
            'enginePublic' => EngineKey::isPublic(),
            'engineKeyPath' => EngineKey::path(),
            'active'  => self::activeJob(),
            'input'   => $input,
            'test'    => $test,
            'error'   => $error,
        ]);
    }

    private function startMigration(array $connection, string $target): never
    {
        $job = Jobs::enqueue('database.migrate', ['connection' => Crypto::encrypt(json_encode($connection))], $this->admin['username']);
        $this->audit->record('database.migrate_requested', 'success', $target, ['job' => $job['id'], 'database' => $connection['database']]);
        $this->redirect('job', ['id' => $job['id']]);
    }

    private static function activeJob(): ?array
    {
        $job = Jobs::latest('database.migrate');
        return null !== $job && in_array($job['status'], Jobs::ACTIVE, true) ? $job : null;
    }
}
