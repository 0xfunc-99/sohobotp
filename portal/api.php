<?php
/**
 * SohobOTP portal - REST API (version 1, see src/Api.php). JSON, API keys (API keys page).
 *
 * @license GNU Lesser General Public License (same as multiOTP)
 */
declare(strict_types=1);

define('PORTAL_ROOT', __DIR__);
require PORTAL_ROOT . '/src/bootstrap.php';

Portal\Api::run();
