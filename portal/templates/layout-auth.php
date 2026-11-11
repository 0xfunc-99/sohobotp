<?php defined('PORTAL_ROOT') || exit; ?>
<?php
  $icon = require PORTAL_ROOT . '/templates/partials/icons.php';
  $asset = static fn (string $file): string => 'assets/' . $file . '?v=' . (int) @filemtime(PORTAL_ROOT . '/assets/' . $file);
  $credit = '© ' . e(Portal\Config::companyName()) . ' · <a href="' . e(route('licences')) . '">Licences</a>';
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title><?= e($title ?? 'Sign in') ?> · <?= e(Portal\Config::brandName()) ?></title>
  <link rel="icon" type="image/png" href="assets/brand-icon.png">
  <link rel="stylesheet" href="<?= e($asset('portal.css')) ?>">
  <script src="<?= e($asset('portal.js')) ?>"></script>
</head>
<body class="auth">
  <aside class="auth-aside">
    <p class="auth-brand">
      <img src="assets/brand-icon.png" alt="" width="48" height="48">
      <span><span class="auth-brand-name"><?= e(Portal\Config::brandName()) ?></span><span class="auth-brand-by">by <?= e(Portal\Config::companyName()) ?></span></span>
    </p>
    <div class="auth-pitch">
      <p class="auth-headline">Secure sign-in, managed in one place</p>
      <p>Two-factor authentication for VPNs, Wi-Fi, servers and Windows sign-in.</p>
      <ul class="auth-points">
        <li><?= $icon('users') ?><span>Users and authenticators, synchronised from Active Directory or LDAP</span></li>
        <li><?= $icon('radius') ?><span>RADIUS for VPNs, firewalls and network devices</span></li>
        <li><?= $icon('endpoints') ?><span>Agents for Windows and Linux machines</span></li>
        <li><?= $icon('audit') ?><span>Every change recorded in a tamper-evident audit trail</span></li>
      </ul>
    </div>
    <p class="powered"><?= $credit ?></p>
  </aside>
  <main class="auth-main">
    <div class="auth-card">
      <p class="card-brand"><img src="assets/brand-icon.png" alt="" width="36" height="36"><span><?= e(Portal\Config::brandName()) ?></span></p>
      <h1><?= e($title ?? '') ?></h1>
      <p class="auth-product"><?= e(Portal\Config::brandName()) ?> management portal</p>
      <?php require PORTAL_ROOT . '/templates/partials/flashes.php'; ?>
      <?= $content ?>
    </div>
    <p class="powered"><?= $credit ?></p>
  </main>
</body>
</html>
