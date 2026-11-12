<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * portal/enrol.php: "Set up my code" for users (not administrators). Three steps, the state in
 * its own session (cookie __Host-sohobotp_enrol, never the administrators' session):
 *   1. directory user name and password  2. scan the QR code  3. type the first code.
 * The new seed is written to SohobOTP only after a correct first code (step 3).
 */
final class SelfEnrolPage
{
    private const STEP_TIMEOUT = 600;    // 10 minutes to scan and confirm
    private const MAX_CODE_TRIES = 5;
    private const BAD_LOGIN = 'The user name or password is not correct, or this account cannot use self-service set-up.';

    private SelfEnrol $enrol;
    private Throttle $throttle;
    private Audit $audit;
    private View $view;
    private string $ip;

    public function __construct()
    {
        $this->enrol = new SelfEnrol();
        $this->throttle = new Throttle(new JsonStore(Config::ensureDataDir() . '/self-enrol-throttle.json'));
        $this->audit = Audit::default();
        $this->view = new View();
        $this->ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    }

    public function run(): void
    {
        App::sendSecurityHeaders();
        $https = App::isHttps();
        if (!$https && !Config::allowHttp()) {
            http_response_code(403);
            $this->render('error', ['title' => 'HTTPS required', 'message' => 'This page is only available over HTTPS.']);
            return;
        }
        Audit::setIp($this->ip);
        Audit::setActor('self-service');
        try {
            Session::start($https, 'sohobotp_enrol');
            $this->dispatch();
        } catch (\Throwable $error) {
            error_log('SohobOTP self-service set-up: ' . $error);
            if (!headers_sent()) {
                http_response_code(500);
            }
            $this->render('error', ['title' => 'Something went wrong', 'message' => 'Please try again later, or ask your IT team.']);
        }
    }

    private function dispatch(): void
    {
        $post = 'POST' === ($_SERVER['REQUEST_METHOD'] ?? 'GET');
        if ($post && !Csrf::valid($_POST[Csrf::FIELD] ?? null)) {
            http_response_code(400);
            $this->render('error', ['title' => 'Request expired', 'message' => 'The page was out of date. Open it again and start over.']);
            return;
        }
        if (null !== ($closed = $this->enrol->closedReason($this->ip))) {
            unset($_SESSION['enrol']);
            $this->render('self-enrol', ['title' => 'Set up your sign-in code', 'step' => 'closed', 'message' => $closed]);
            return;
        }
        $pending = $_SESSION['enrol'] ?? null;
        if (null !== $pending && $pending['started'] < time() - self::STEP_TIMEOUT) {
            unset($_SESSION['enrol']);
            $pending = null;
            $this->flash('info', 'The set-up took more than 10 minutes. Please sign in again.');
        }
        $step = $post ? (string) ($_POST['step'] ?? '') : '';
        if ('cancel' === $step) {
            unset($_SESSION['enrol']);
            $this->redirect();
        }
        if (null === $pending) {
            'login' === $step ? $this->login() : $this->render('self-enrol', ['title' => 'Set up your sign-in code', 'step' => 'login', 'username' => '']);
            return;
        }
        'confirm' === $step ? $this->confirm($pending) : $this->showCode($pending, null);
    }

    private function login(): void
    {
        $username = mb_strtolower(trim(mb_substr((string) ($_POST['username'] ?? ''), 0, 64)));
        $password = mb_substr((string) ($_POST['password'] ?? ''), 0, 256);
        if ($this->throttle->isBlocked($this->ip)) {
            $this->audit->record('self_enrol.sign_in', 'denied', $username, ['reason' => 'too many failures from this address']);
            $this->loginForm($username, 'Too many attempts. Wait a few minutes and try again.');
            return;
        }
        // account name only (a domain prefix or suffix is accepted and removed)
        $username = (string) preg_replace('/^[^\\\\]*\\\\|@.*$/', '', $username);
        $users = new Users();
        $user = null === Users::validateName($username) && $users->exists($username) ? $users->get($username) : null;
        $ok = false;
        if (null !== $user && $user['synchronized'] && '' !== $user['synced_dn'] && '' !== $password) {
            $engine = MultiotpService::get();
            $engine->SetUser($user['user']);
            $ok = (bool) $engine->CheckUserLdapPassword($engine->GetUserSynchronizedDn(), $password);
        }
        if (!$ok) {
            $this->throttle->fail($this->ip);
            $this->audit->record('self_enrol.sign_in', 'failure', $username, ['reason' => null === $user ? 'unknown or not from the directory' : 'wrong directory password']);
            $this->loginForm($username, self::BAD_LOGIN);
            return;
        }
        if (null !== ($refusal = $this->enrol->refusal($user))) {
            $this->audit->record('self_enrol.sign_in', 'denied', $user['user'], ['reason' => $refusal]);
            $this->render('self-enrol', ['title' => 'Set up your sign-in code', 'step' => 'refused', 'message' => $refusal]);
            return;
        }
        $this->throttle->clear($this->ip);
        Session::regenerate();
        $_SESSION['enrol'] = ['user' => $user['user'], 'seed' => bin2hex(random_bytes(20)), 'started' => time(), 'tries' => 0];
        $this->audit->record('self_enrol.sign_in', 'success', $user['user']);
        $this->redirect();
    }

    private function confirm(array $pending): void
    {
        $code = (string) preg_replace('/\D/', '', mb_substr((string) ($_POST['code'] ?? ''), 0, 20));
        $step = 6 === strlen($code) ? Totp::verify((string) hex2bin($pending['seed']), $code, -1, time()) : null;
        if (null === $step) {
            $_SESSION['enrol']['tries'] = ++$pending['tries'];
            $this->throttle->fail($this->ip);
            if ($pending['tries'] >= self::MAX_CODE_TRIES) {
                unset($_SESSION['enrol']);
                $this->audit->record('self_enrol.confirm', 'failure', $pending['user'], ['reason' => 'too many wrong codes']);
                $this->flash('error', 'Too many wrong codes. Sign in again and scan the new QR code.');
                $this->redirect();
            }
            $this->showCode($pending, 'This code is not correct. Check that the phone shows the time correctly, and type the code currently shown for ' . Config::brandName() . '.');
            return;
        }
        // the user may have been set up by an administrator meanwhile: check again
        $users = new Users();
        $user = $users->get($pending['user']);
        if (null === $user || null !== ($refusal = $this->enrol->refusal($user))) {
            unset($_SESSION['enrol']);
            $this->render('self-enrol', ['title' => 'Set up your sign-in code', 'step' => 'refused', 'message' => $refusal ?? self::BAD_LOGIN]);
            return;
        }
        $users->enrollSoftwareToken($user['user'], $pending['seed'], $step);
        $this->enrol->markDone($user['user'], 'self', $this->ip);
        (new VipMigration())->set([$user['user']], 'sohobotp', 'self-service', 'authenticator set up by the user');
        $this->audit->record('user.token_enrolled', 'success', $user['user'], ['type' => 'software TOTP', 'via' => 'self-service']);
        unset($_SESSION['enrol']);
        Session::regenerate();
        $this->render('self-enrol', ['title' => 'Your code is set up', 'step' => 'done', 'name' => $user['display_name'] ?: $user['user']]);
    }

    private function showCode(array $pending, ?string $error): void
    {
        $seed = (string) hex2bin($pending['seed']);
        $uri = SelfEnrol::otpauthUri($pending['user'], $seed);
        if (null !== $error) {
            http_response_code(400);
        }
        $this->render('self-enrol', [
            'title' => 'Scan your QR code', 'step' => 'scan', 'user' => $pending['user'], 'error' => $error,
            'qr' => App::qrDataUri($uri), 'secret' => implode(' ', str_split(Totp::base32($seed), 4)),
            'minutes' => max(1, (int) ceil(($pending['started'] + self::STEP_TIMEOUT - time()) / 60)),
        ]);
    }

    private function loginForm(string $username, string $error): void
    {
        http_response_code(400);
        $this->render('self-enrol', ['title' => 'Set up your sign-in code', 'step' => 'login', 'username' => $username, 'error' => $error]);
    }

    private function render(string $template, array $data): void
    {
        $this->view->render($template, $data + ['selfService' => true], 'auth');
    }

    private function flash(string $type, string $message): void
    {
        Session::flash($type, $message);
    }

    private function redirect(): never
    {
        header('Location: enrol.php', true, 303);
        exit;
    }
}
