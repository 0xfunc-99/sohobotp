<?php
// The protected site: shows what it received.
header('Content-Type: application/json');
echo json_encode(['path' => $_SERVER['REQUEST_URI'], 'cookie' => $_SERVER['HTTP_COOKIE'] ?? '',
    'webauth' => $_SERVER['HTTP_X_WEBAUTH_USER'] ?? '', 'sohobotp_user' => $_SERVER['HTTP_X_SOHOBOTP_USER'] ?? '']);
