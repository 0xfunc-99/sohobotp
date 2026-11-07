<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Administrator roles. Permissions for later stages (users, tokens, sync,
 * RADIUS, endpoints) are declared now so the role model stays stable.
 */
final class Roles
{
    public const ROLES = [
        'superadmin' => [
            'label'       => 'Super administrator',
            'description' => 'Full access, including administrator accounts.',
            'permissions' => ['*'],
        ],
        'admin' => [
            'label'       => 'Administrator',
            'description' => 'Manages users, tokens, directory sync, RADIUS and endpoints. Cannot manage administrators.',
            'permissions' => [
                'dashboard.view', 'users.view', 'users.manage', 'tokens.view', 'tokens.manage',
                'sync.view', 'sync.run', 'directory.manage', 'radius.view', 'radius.manage',
                'endpoints.view', 'endpoints.manage', 'audit.view', 'settings.view',
            ],
        ],
        'helpdesk' => [
            'label'       => 'Helpdesk',
            'description' => 'Looks up users, unlocks accounts, resynchronises and enrols tokens.',
            'permissions' => ['dashboard.view', 'users.view', 'users.unlock', 'tokens.view', 'tokens.resync', 'tokens.enroll'],
        ],
        'auditor' => [
            'label'       => 'Auditor',
            'description' => 'Read-only access, including the audit trail.',
            'permissions' => [
                'dashboard.view', 'users.view', 'tokens.view', 'sync.view', 'radius.view',
                'endpoints.view', 'audit.view', 'settings.view',
            ],
        ],
    ];

    public static function exists(string $role): bool
    {
        return isset(self::ROLES[$role]);
    }

    public static function can(string $role, string $permission): bool
    {
        $granted = self::ROLES[$role]['permissions'] ?? [];
        return in_array('*', $granted, true) || in_array($permission, $granted, true);
    }

    public static function label(string $role): string
    {
        return self::ROLES[$role]['label'] ?? $role;
    }
}
