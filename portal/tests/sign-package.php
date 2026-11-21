<?php
// Test helper: the signature file "sohobotp-agent release sign-package" makes, with a TEST
// release key. Usage: php sign-package.php FILE KIND ARCH VERSION [--public]
declare(strict_types=1);

$keypair = sodium_crypto_sign_seed_keypair(hash('sha256', 'SohobOTP portal tests: release key', true));
if (in_array('--public', $argv, true)) {
    echo base64_encode(sodium_crypto_sign_publickey($keypair)), "\n";
    exit(0);
}
[, $file, $kind, $arch, $version] = $argv + [null, '', '', '', ''];
$m = ['kind' => $kind, 'arch' => $arch, 'version' => $version, 'sha256' => hash_file('sha256', $file), 'size' => filesize($file)];
$message = "sohobotp-package-v1\n{$m['kind']}\n{$m['arch']}\n{$m['version']}\n{$m['sha256']}\n{$m['size']}";
$m['signature'] = base64_encode(sodium_crypto_sign_detached($message, sodium_crypto_sign_secretkey($keypair)));
echo json_encode($m, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
