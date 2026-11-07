<?php
declare(strict_types=1);

defined('PORTAL_ROOT') || exit;

/** HTML-escape for templates. */
function e(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** URL of a portal route. */
function route(string $name, array $params = []): string
{
    return 'index.php?' . http_build_query(['r' => $name] + $params);
}

function format_time(?int $epoch): string
{
    return null === $epoch ? '—' : gmdate('Y-m-d H:i', $epoch) . ' UTC';
}

/** Hidden CSRF field for forms. */
function csrf_field(): string
{
    return '<input type="hidden" name="' . Portal\Csrf::FIELD . '" value="' . e(Portal\Csrf::token()) . '">';
}
