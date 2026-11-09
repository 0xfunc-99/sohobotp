<?php
/**
 * multiOTP management portal - endpoint agent API (see docs/agent-protocol.md).
 *
 * @license GNU Lesser General Public License (same as multiOTP)
 */
declare(strict_types=1);

define('PORTAL_ROOT', __DIR__);
require PORTAL_ROOT . '/src/bootstrap.php';

Portal\AgentApi::run();
