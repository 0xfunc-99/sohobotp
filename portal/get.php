<?php
/**
 * SohobOTP: one-time install links for the agent (Portal\AgentLinks), made on "Add a computer".
 * A Linux machine fetches its agent here with wget; each link gives out its file once.
 */
declare(strict_types=1);

define('PORTAL_ROOT', __DIR__);
require PORTAL_ROOT . '/src/bootstrap.php';

Portal\AgentLinks::serve();
