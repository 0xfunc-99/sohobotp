<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/**
 * Read-only figures for the dashboard charts: logins per day, portal activity per day,
 * endpoint health and RADIUS state. Every method fails soft (empty data) so the dashboard
 * always renders; the template checks the viewer's permissions before calling them.
 */
final class DashboardInsights
{
    /** @return list<array{date: string, label: string}> the last $days days, oldest first (UTC) */
    public static function days(int $days): array
    {
        $out = [];
        for ($i = $days - 1; $i >= 0; $i--) {
            $t = time() - $i * 86400;
            $out[] = ['date' => gmdate('Y-m-d', $t), 'label' => gmdate('j M', $t)];
        }
        return $out;
    }

    /**
     * Logins checked by the engine (RADIUS, agents, Windows sign-in) per day.
     * @return array{available: bool, days: list<array{date: string, label: string, ok: int, failed: int}>, ok: int, failed: int}
     */
    public static function logins(int $days = 14): array
    {
        $series = [];
        foreach (self::days($days) as $day) {
            $series[$day['date']] = $day + ['ok' => 0, 'failed' => 0];
        }
        $available = true;
        try {
            foreach (Radius::recentLogins('', '', 50000) as $event) {
                $date = self::date((string) $event['time']);
                if (null !== $date && isset($series[$date])) {
                    $series[$date][$event['ok'] ? 'ok' : 'failed']++;
                }
            }
        } catch (\Throwable $error) {
            error_log('SohobOTP portal dashboard logins: ' . $error);
            $available = false;
        }
        $list = array_values($series);
        return [
            'available' => $available,
            'days'      => $list,
            'ok'        => array_sum(array_column($list, 'ok')),
            'failed'    => array_sum(array_column($list, 'failed')),
        ];
    }

    /**
     * Portal audit entries per day: successes and failures/denials.
     * @return array{days: list<array{date: string, label: string, ok: int, failed: int}>, ok: int, failed: int}
     */
    public static function activity(Audit $audit, int $days = 14): array
    {
        $range = self::days($days);
        $series = [];
        foreach ($range as $day) {
            $series[$day['date']] = $day + ['ok' => 0, 'failed' => 0];
        }
        try {
            foreach ($audit->search(['from' => $range[0]['date']], 1, 1_000_000)['entries'] as $entry) {
                $date = substr((string) $entry['time'], 0, 10);
                if (isset($series[$date])) {
                    $series[$date]['success' === $entry['result'] ? 'ok' : 'failed']++;
                }
            }
        } catch (\Throwable $error) {
            error_log('SohobOTP portal dashboard activity: ' . $error);
        }
        $list = array_values($series);
        return ['days' => $list, 'ok' => array_sum(array_column($list, 'ok')), 'failed' => array_sum(array_column($list, 'failed'))];
    }

    /** @return array{total: int, online: int, offline: int, never: int, pending: int, disabled: int} */
    public static function endpoints(): array
    {
        $counts = ['total' => 0, 'online' => 0, 'offline' => 0, 'never' => 0, 'pending' => 0, 'disabled' => 0];
        try {
            $endpoints = new Endpoints();
            foreach ($endpoints->endpoints() as $endpoint) {
                $health = $endpoints->health($endpoint);
                $counts['total']++;
                if (isset($counts[$health])) {
                    $counts[$health]++;
                }
            }
        } catch (\Throwable $error) {
            error_log('SohobOTP portal dashboard endpoints: ' . $error);
        }
        return $counts;
    }

    /** @return array{groups: int, servers: int, pending: bool, last_apply: ?array, service: ?bool, catch_all: bool} */
    public static function radius(): array
    {
        $out = ['groups' => 0, 'servers' => 0, 'pending' => false, 'last_apply' => null, 'service' => null, 'catch_all' => false];
        try {
            $radius = new Radius();
            $state = $radius->state();
            $status = Radius::status();
            $out = [
                'groups'     => count($radius->groups()),
                'servers'    => count($radius->clients()),
                'pending'    => $state['pending'],
                'last_apply' => $state['last_apply'],
                'service'    => $status['available'] ? (bool) $status['running'] : null,
                'catch_all'  => (bool) ($status['default_client'] ?? false),
            ];
        } catch (\Throwable $error) {
            error_log('SohobOTP portal dashboard radius: ' . $error);
        }
        return $out;
    }

    /** "2026-11-11 14:44:00", "2026-11-11T14:44:00Z" or similar → "2026-11-11" */
    private static function date(string $time): ?string
    {
        if (preg_match('/^(\d{4})-(\d{2})-(\d{2})/', $time, $m)) {
            return "$m[1]-$m[2]-$m[3]";
        }
        $epoch = strtotime($time);
        return false === $epoch ? null : gmdate('Y-m-d', $epoch);
    }
}
