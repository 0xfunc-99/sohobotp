<?php defined('PORTAL_ROOT') || exit; ?>
<?php
  $icon = require PORTAL_ROOT . '/templates/partials/icons.php';
  $asset = static fn (string $file): string => 'assets/' . $file . '?v=' . (int) @filemtime(PORTAL_ROOT . '/assets/' . $file);

  // Sidebar sections. Entries the role cannot use are already left out of $nav; unknown entries go to "More".
  $sectionOf = [
      'dashboard' => '', 'users' => 'Identity', 'tokens' => 'Identity', 'directory' => 'Identity',
      'radius' => 'Access', 'endpoints' => 'Access', 'api-keys' => 'Access',
      'admins' => 'System', 'database' => 'System', 'ha' => 'System', 'audit' => 'System',
      'account' => 'You',
  ];
  $sections = ['' => [], 'Identity' => [], 'Access' => [], 'System' => [], 'More' => []];
  $accountItem = null;
  foreach ($nav as $navItem) {
      if ('account' === $navItem['route']) {
          $accountItem = $navItem;
          continue;
      }
      $sections[$sectionOf[$navItem['route']] ?? 'More'][] = $navItem;
  }

  // Which sidebar entry the current page belongs to (detail and form pages highlight their list).
  $navRoute = ['password' => 'account', 'jobs' => 'directory'][$current] ?? null;
  if ('job' === $current) {
      $jobType = (string) ($job['type'] ?? '');
      $navRoute = match (true) {
          str_starts_with($jobType, 'endpoints.') => 'endpoints',
          str_starts_with($jobType, 'radius.') => 'radius',
          str_starts_with($jobType, 'database.') => 'database',
          default => 'directory',
      };
  }
  if (null === $navRoute) {
      $best = 0;
      foreach ($nav as $navItem) {
          $stem = rtrim($navItem['route'], 's');
          if (($current === $navItem['route'] || str_starts_with($current, $stem)) && strlen($stem) > $best) {
              $best = strlen($stem);
              $navRoute = $navItem['route'];
          }
      }
  }
  $activeItem = null;
  foreach ($nav as $navItem) {
      if ($navItem['route'] === $navRoute) {
          $activeItem = $navItem;
      }
  }

  $intros = [
      'users' => 'People who sign in with a SohobOTP code: search, enrol authenticators, unlock and manage accounts.',
      'tokens' => 'Hardware tokens imported into SohobOTP and the users they are assigned to.',
      'directory' => 'Connect Active Directory or LDAP so users are created, updated and disabled automatically.',
      'radius' => 'VPNs, firewalls and other devices that check logins with SohobOTP over RADIUS.',
      'endpoints' => 'Windows and Linux machines running the SohobOTP agent.',
      'admins' => 'People who can sign in to this portal, and what each role may do.',
      'api-keys' => 'Keys for scripts and other applications that use the SohobOTP REST API.',
      'database' => 'Where SohobOTP stores users, tokens and RADIUS data.',
      'ha' => 'Pair two appliances so logins keep working when one of them fails.',
      'audit' => 'A tamper-evident record of every sign-in and change.',
      'account' => 'Your administrator profile, password and sessions.',
  ];
  // A list page (also when a form posted to a sub-route renders it again) shows its intro and no extra crumb.
  $onListPage = null !== $activeItem && ($current === $activeItem['route'] || ($title ?? '') === $activeItem['label']);
  $intro = $onListPage ? ($intros[$activeItem['route']] ?? null) : null;

  $myName = '' !== (string) $me['display_name'] ? (string) $me['display_name'] : (string) $me['username'];
  $initials = '';
  foreach (array_slice(preg_split('/[\s._-]+/u', trim($myName)) ?: [], 0, 2) as $word) {
      $initials .= mb_strtoupper(mb_substr($word, 0, 1));
  }
  $section = null === $activeItem ? null : ($sectionOf[$activeItem['route']] ?? 'More');
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title><?= e($title ?? 'Portal') ?> · <?= e(Portal\Config::brandName()) ?></title>
  <link rel="icon" type="image/png" href="assets/brand-icon.png">
  <link rel="stylesheet" href="<?= e($asset('portal.css')) ?>">
  <script src="<?= e($asset('portal.js')) ?>"></script>
</head>
<body class="app">
  <a class="skip-link" href="#content">Skip to content</a>
  <input type="checkbox" id="nav-toggle" class="nav-toggle" aria-label="Show navigation">
  <aside class="sidebar" aria-label="Sidebar">
    <a class="sidebar-brand" href="<?= e(route('dashboard')) ?>">
      <img src="assets/brand-icon.png" alt="<?= e(Portal\Config::companyName()) ?>" width="34" height="34">
      <span class="brand-text"><span class="brand-name"><?= e(Portal\Config::brandName()) ?></span><span class="brand-sub">Management portal</span></span>
    </a>
    <nav class="sidebar-nav" aria-label="Main">
      <?php foreach ($sections as $heading => $items): ?>
        <?php if ([] === $items) { continue; } ?>
        <div class="nav-section">
          <?php if ('' !== $heading): ?><p class="nav-heading"><?= e($heading) ?></p><?php endif; ?>
          <ul>
            <?php foreach ($items as $navItem): ?>
              <li><a class="nav-link" href="<?= e(route($navItem['route'])) ?>"<?= $navRoute === $navItem['route'] ? ' aria-current="page"' : '' ?>><?= $icon($navItem['route']) ?><span><?= e($navItem['label']) ?></span></a></li>
            <?php endforeach; ?>
          </ul>
        </div>
      <?php endforeach; ?>
      <?php if (null !== $accountItem): ?>
        <div class="nav-section">
          <p class="nav-heading">You</p>
          <ul>
            <li><a class="nav-link" href="<?= e(route($accountItem['route'])) ?>"<?= $navRoute === $accountItem['route'] ? ' aria-current="page"' : '' ?>><?= $icon('account') ?><span><?= e($accountItem['label']) ?></span></a></li>
          </ul>
        </div>
      <?php endif; ?>
    </nav>
    <div class="sidebar-foot">
      <p class="powered">© <?= e(Portal\Config::companyName()) ?> · <a href="<?= e(route('licences')) ?>">Licences</a></p>
    </div>
  </aside>
  <label for="nav-toggle" class="scrim" aria-hidden="true"></label>
  <div class="main">
    <header class="topbar">
      <label for="nav-toggle" class="nav-button icon-button" aria-hidden="true"><?= $icon('menu', '') ?></label>
      <a class="topbar-brand" href="<?= e(route('dashboard')) ?>"><img src="assets/brand-icon.png" alt="" width="28" height="28"><?= e(Portal\Config::brandName()) ?></a>
      <p class="crumbs" aria-label="You are here">
        <?php if (null !== $section && '' !== $section): ?><span><?= e($section) ?></span><?php endif; ?>
        <?php if (null !== $activeItem && !$onListPage): ?><span><a href="<?= e(route($activeItem['route'])) ?>"><?= e($activeItem['label']) ?></a></span><?php endif; ?>
        <span><?= e($title ?? '') ?></span>
      </p>
      <div class="topbar-end">
        <button type="button" class="icon-button theme-toggle" data-theme-toggle data-mode="system" hidden aria-label="Colour theme">
          <?= $icon('contrast', 'theme-icon theme-icon-system') ?><?= $icon('sun', 'theme-icon theme-icon-light') ?><?= $icon('moon', 'theme-icon theme-icon-dark') ?>
        </button>
        <a class="user-chip" href="<?= e(route('account')) ?>" title="My account">
          <span class="avatar" aria-hidden="true"><?= e($initials) ?></span>
          <span class="user-meta"><span class="user-name"><?= e($myName) ?></span><span class="user-role"><?= e(Portal\Roles::label($me['role'])) ?></span></span>
        </a>
        <form method="post" action="<?= e(route('logout')) ?>" class="inline">
          <?= csrf_field() ?>
          <button type="submit" class="icon-button signout" aria-label="Sign out" title="Sign out"><?= $icon('logout', '') ?></button>
        </form>
      </div>
    </header>
    <main class="content" id="content" tabindex="-1">
      <div class="page-header">
        <div>
          <h1><?= e($title ?? '') ?></h1>
          <?php if (null !== $intro): ?><p class="page-intro"><?= e($intro) ?></p><?php endif; ?>
        </div>
      </div>
      <?php require PORTAL_ROOT . '/templates/partials/flashes.php'; ?>
      <?= $content ?>
    </main>
  </div>
</body>
</html>
