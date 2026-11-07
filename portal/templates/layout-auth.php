<?php defined('PORTAL_ROOT') || exit; ?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?= e($title ?? 'Sign in') ?> · multiOTP</title>
  <link rel="stylesheet" href="assets/portal.css">
  <script src="assets/portal.js" defer></script>
</head>
<body class="auth">
  <main class="auth-card">
    <p class="brand">multiOTP management portal</p>
    <h1><?= e($title ?? '') ?></h1>
    <?php require PORTAL_ROOT . '/templates/partials/flashes.php'; ?>
    <?= $content ?>
  </main>
</body>
</html>
