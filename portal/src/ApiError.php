<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/** An error answer of the REST API: {"error": code, "message": text} with an HTTP status. */
final class ApiError extends \RuntimeException
{
    public function __construct(public readonly string $errorCode, public readonly int $status, string $message)
    {
        parent::__construct($message);
    }
}
