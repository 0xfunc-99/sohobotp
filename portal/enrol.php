<?php
/**
 * SohobOTP: "Set up my code", the self-service page for users (Portal\SelfEnrolPage).
 * Open only while an administrator allows it (Users → Self-service set-up).
 */
declare(strict_types=1);

define('PORTAL_ROOT', __DIR__);
require PORTAL_ROOT . '/src/bootstrap.php';

(new Portal\SelfEnrolPage())->run();
