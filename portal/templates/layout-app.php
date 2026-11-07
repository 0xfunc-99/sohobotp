<?php defined('PORTAL_ROOT') || exit; ?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?= e($title ?? 'Portal') ?> · multiOTP</title>
  <link rel="stylesheet" href="assets/portal.css">
  <script src="assets/portal.js" defer></script>
</head>
<body class="app">
  <input type="checkbox" id="nav-toggle" class="nav-toggle" aria-label="Show navigation">
  <header class="topbar">
    <label for="nav-toggle" class="nav-button" aria-hidden="true">☰</label>
    <span class="brand">multiOTP</span>
    <span class="topbar-user">
      <?= e($me['display_name'] !== '' ? $me['display_name'] : $me['username']) ?>
      <span class="badge"><?= e(Portal\Roles::label($me['role'])) ?></span>
    </span>
    <form method="post" action="<?= e(route('logout')) ?>" class="inline">
      <?= csrf_field() ?>
      <button type="submit" class="button-link">Sign out</button>
    </form>
  </header>
  <nav class="sidebar" aria-label="Main">
    <ul>
      <?php foreach ($nav as $item): ?>
        <li><a href="<?= e(route($item['route'])) ?>"<?= $current === $item['route'] ? ' aria-current="page"' : '' ?>><?= e($item['label']) ?></a></li>
      <?php endforeach; ?>
    </ul>
  </nav>
  <main class="content">
    <h1><?= e($title ?? '') ?></h1>
    <?php require PORTAL_ROOT . '/templates/partials/flashes.php'; ?>
    <?= $content ?>
  </main>
</body>
</html>
