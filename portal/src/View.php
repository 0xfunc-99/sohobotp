<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/** Renders a template from portal/templates inside the "app" or "auth" layout. */
final class View
{
    private ?array $admin = null;

    public function setAdmin(?array $admin): void
    {
        $this->admin = $admin;
    }

    public function render(string $template, array $vars = [], string $layout = 'app'): void
    {
        if ('app' === $layout && null === $this->admin) {
            $layout = 'auth';
        }
        $vars['flashes'] = PHP_SESSION_ACTIVE === session_status() ? Session::takeFlashes() : [];
        $vars['me'] ??= $this->admin;
        $vars['nav'] = null === $this->admin ? [] : self::navigation($this->admin['role']);
        $vars['current'] = (string) ($_GET['r'] ?? 'dashboard');
        $vars['content'] = self::capture(PORTAL_ROOT . '/templates/' . $template . '.php', $vars);
        header('Content-Type: text/html; charset=utf-8');
        echo self::capture(PORTAL_ROOT . '/templates/layout-' . $layout . '.php', $vars);
    }

    /** Sidebar entries the role can use. Later stages add users, tokens, sync, RADIUS and endpoints. */
    private static function navigation(string $role): array
    {
        $items = [
            ['route' => 'dashboard', 'label' => 'Dashboard', 'permission' => ['dashboard.view']],
            ['route' => 'users', 'label' => 'Users', 'permission' => ['users.view']],
            ['route' => 'tokens', 'label' => 'Hardware tokens', 'permission' => ['tokens.view']],
            ['route' => 'directory', 'label' => 'Directory (AD/LDAP)', 'permission' => ['settings.view', 'sync.view', 'directory.manage']],
            ['route' => 'radius', 'label' => 'RADIUS servers', 'permission' => ['radius.view']],
            ['route' => 'endpoints', 'label' => 'Endpoints', 'permission' => ['endpoints.view']],
            ['route' => 'admins', 'label' => 'Administrators', 'permission' => ['admins.manage']],
            ['route' => 'api-keys', 'label' => 'API keys', 'permission' => ['api.manage']],
            ['route' => 'audit', 'label' => 'Audit trail', 'permission' => ['audit.view']],
            ['route' => 'account', 'label' => 'My account', 'permission' => []],
        ];
        return array_values(array_filter($items, static function (array $item) use ($role): bool {
            if ([] === $item['permission']) {
                return true;
            }
            foreach ($item['permission'] as $permission) {
                if (Roles::can($role, $permission)) {
                    return true;
                }
            }
            return false;
        }));
    }

    private static function capture(string $__file, array $__vars): string
    {
        extract($__vars, EXTR_SKIP);
        ob_start();
        try {
            require $__file;
            return (string) ob_get_clean();
        } catch (\Throwable $error) {
            ob_end_clean();
            throw $error;
        }
    }
}
