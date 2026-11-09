<?php
/**
 * multiOTP management portal - front controller (with agent.php, the only PHP files served).
 *
 * @license GNU Lesser General Public License (same as multiOTP)
 */
declare(strict_types=1);

define('PORTAL_ROOT', __DIR__);
require PORTAL_ROOT . '/src/bootstrap.php';

(new Portal\App())->run();
