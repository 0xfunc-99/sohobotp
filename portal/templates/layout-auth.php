<?php defined('PORTAL_ROOT') || exit; ?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?= e($title ?? 'Sign in') ?> · <?= e(Portal\Config::brandName()) ?></title>
  <link rel="icon" type="image/png" href="assets/brand-icon.png">
  <link rel="stylesheet" href="assets/portal.css">
  <script src="assets/portal.js" defer></script>
</head>
<body class="auth">
  <main class="auth-card">
    <p class="brand"><img class="brand-logo" src="assets/brand-logo.png" alt="<?= e(Portal\Config::companyName()) ?>" width="180" height="50"><span class="brand-product"><?= e(Portal\Config::brandName()) ?> management portal</span></p>
    <h1><?= e($title ?? '') ?></h1>
    <?php require PORTAL_ROOT . '/templates/partials/flashes.php'; ?>
    <?= $content ?>
    <p class="powered">© Sohobcom · <a href="<?= e(route('licences')) ?>">Licences</a></p>
  </main>
</body>
</html>
