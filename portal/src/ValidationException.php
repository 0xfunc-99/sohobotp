<?php
declare(strict_types=1);

namespace Portal;

defined('PORTAL_ROOT') || exit;

/** An error whose message is safe to show to the administrator. */
final class ValidationException extends \RuntimeException
{
}
