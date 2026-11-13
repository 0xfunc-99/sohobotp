<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/** Shared helpers for page controllers (the administrator is signed in and has passed CSRF checks). */
abstract class Controller
{
    public function __construct(protected array $admin, protected Audit $audit, protected View $view)
    {
    }

    protected function can(string $permission): bool
    {
        return Roles::can($this->admin['role'], $permission);
    }

    protected function requirePermission(string ...$anyOf): void
    {
        foreach ($anyOf as $permission) {
            if ($this->can($permission)) {
                return;
            }
        }
        $this->audit->record('access.denied', 'denied', implode('|', $anyOf));
        http_response_code(403);
        $this->view->render('error', ['title' => 'Not allowed', 'message' => 'Your role does not allow this action.']);
        exit;
    }

    protected function isPost(): bool
    {
        return 'POST' === ($_SERVER['REQUEST_METHOD'] ?? 'GET');
    }

    protected function post(string $key, int $max = 255): string
    {
        return trim(mb_substr((string) ($_POST[$key] ?? ''), 0, $max));
    }

    protected function query(string $key, int $max = 255): string
    {
        return trim(mb_substr((string) ($_GET[$key] ?? ''), 0, $max));
    }

    protected function redirect(string $route, array $params = []): never
    {
        while (ob_get_level() > 0) {
            ob_end_clean(); // engine warnings printed before a redirect must not block it
        }
        header('Location: ' . route($route, $params), true, 303);
        exit;
    }

    protected function notFound(string $message): never
    {
        http_response_code(404);
        $this->view->render('error', ['title' => 'Not found', 'message' => $message]);
        exit;
    }

    protected function json(array $data): never
    {
        header('Content-Type: application/json');
        echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        exit;
    }
}
