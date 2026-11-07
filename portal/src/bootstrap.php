<?php
/**
 * multiOTP management portal - bootstrap
 *
 * Loaded by the front controller (portal/index.php) and the CLI tool
 * (portal/bin/portal-admin.php). Files under portal/src/ are never served
 * directly: each one refuses to run unless PORTAL_ROOT is defined.
 *
 * @license GNU Lesser General Public License (same as multiOTP)
 */
declare(strict_types=1);

defined('PORTAL_ROOT') || exit;

if (PHP_VERSION_ID < 80100) {
    http_response_code(500);
    exit("The multiOTP portal requires PHP 8.1 or later.\n");
}

spl_autoload_register(static function (string $class): void {
    if (str_starts_with($class, 'Portal\\')) {
        $file = PORTAL_ROOT . '/src/' . str_replace('\\', '/', substr($class, 7)) . '.php';
        if (is_file($file)) {
            require $file;
        }
    }
});

require PORTAL_ROOT . '/src/helpers.php';
