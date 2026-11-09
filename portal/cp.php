<?php
/**
 * SohobOTP portal - Credential Provider gateway for managed Windows endpoints
 * (multiOTPServers = https://<portal>/portal/cp.php?e=<endpoint id>). See src/CpGateway.php.
 *
 * @license GNU Lesser General Public License (same as multiOTP)
 */
declare(strict_types=1);

define('PORTAL_ROOT', __DIR__);
require PORTAL_ROOT . '/src/bootstrap.php';

Portal\CpGateway::run();
