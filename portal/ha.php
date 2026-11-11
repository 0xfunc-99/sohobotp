<?php
/**
 * SohobOTP portal - high availability: the primary's RADIUS configuration for its paired
 * secondary (encrypted and authenticated with the pairing key, see src/Ha.php).
 *
 * @license GNU Lesser General Public License (same as multiOTP)
 */
declare(strict_types=1);

define('PORTAL_ROOT', __DIR__);
require PORTAL_ROOT . '/src/bootstrap.php';

Portal\Ha::serve();
