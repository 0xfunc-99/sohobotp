<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * "Get started" checklist on the dashboard: the few steps that make SohobOTP useful, each
 * ticked by itself from what is already configured, with one button to the page that does it.
 * Shown until the setup is complete; buttons only for what the administrator's role allows.
 */
final class GettingStarted
{
    /**
     * @return array{steps: list<array{key: string, title: string, text: string, done: bool, actions: list<array{label: string, route: string}>}>, done: int, complete: bool}
     */
    public static function steps(string $role, ?int $users, bool $directoryEnabled, int $successfulLogins): array
    {
        $can = static fn (string $permission): bool => Roles::can($role, $permission);
        $endpoints = [];
        $devices = 0;
        try {
            $endpoints = (new Endpoints())->endpoints();
            $managed = array_flip(array_filter(array_column($endpoints, 'radius_client_id')));
            foreach ((new Radius())->clients() as $client) {
                $devices += isset($managed[$client['id']]) ? 0 : 1; // RADIUS clients made for Linux computers are not VPNs
            }
        } catch (\Throwable $error) {
            error_log('multiOTP portal getting started: ' . $error);
        }
        $action = static fn (string $label, string $route, string $permission): ?array => $can($permission) ? ['label' => $label, 'route' => $route] : null;
        $steps = [
            [
                'key' => 'users', 'title' => 'Add the people who sign in',
                'text' => 'Add users one by one, or connect Active Directory so they are added and disabled automatically.',
                'done' => ($users ?? 0) > 0 || $directoryEnabled,
                'actions' => array_values(array_filter([$action('Connect Active Directory', 'directory', 'directory.manage'), $action('Add a user', 'user-new', 'users.manage')])),
            ],
            [
                'key' => 'devices', 'title' => 'Protect a VPN, firewall or Wi-Fi',
                'text' => 'Add the device: SohobOTP gives you the settings to enter on it, and it then asks for a code at every sign-in.',
                'done' => $devices > 0,
                'actions' => array_values(array_filter([$action('Add a VPN or device', 'radius-client', 'radius.manage')])),
            ],
            [
                'key' => 'computers', 'title' => 'Protect Windows and Linux computers',
                'text' => 'Download the agent with everything built in and run it on the computer: it joins SohobOTP by itself.',
                'done' => [] !== $endpoints,
                'actions' => array_values(array_filter([$action('Add a computer', 'agent-download', 'endpoints.manage')])),
            ],
            [
                'key' => 'test', 'title' => 'Check that a sign-in works',
                'text' => 'Sign in once with a code on a protected VPN or computer, or send a test login from the portal.',
                'done' => $successfulLogins > 0,
                'actions' => array_values(array_filter([$action('Test a sign-in', 'radius-diagnostics', 'radius.view')])),
            ],
        ];
        $done = count(array_filter(array_column($steps, 'done')));
        return ['steps' => $steps, 'done' => $done, 'complete' => 4 === $done];
    }
}
