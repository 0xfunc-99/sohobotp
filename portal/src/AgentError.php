<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/** An agent API error: protocol error code (docs/agent-protocol.md) and HTTP status. */
final class AgentError extends \RuntimeException
{
    public function __construct(public readonly string $errorCode, public readonly int $status, string $message)
    {
        parent::__construct($message);
    }
}
