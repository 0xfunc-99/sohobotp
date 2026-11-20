<?php
// Test double of the portal's POST /v1/auth/check: alice and bob, code 123456; 999999 = locked.
header('Content-Type: application/json');
if ('/portal/api.php/v1/auth/check' !== parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) || 'POST' !== $_SERVER['REQUEST_METHOD']) {
    http_response_code(404);
    exit('{"error":"not_found"}');
}
if (($_SERVER['HTTP_AUTHORIZATION'] ?? '') !== 'Bearer sohob_testkey_0123456789') {
    http_response_code(401);
    exit('{"error":"unauthorized","message":"bad key"}');
}
$in = json_decode((string) file_get_contents('php://input'), true);
$user = (string) ($in['user'] ?? '');
$code = (string) ($in['code'] ?? '');
$result = !in_array($user, ['alice', 'bob'], true) ? 'unknown' : ('123456' === $code ? 'accepted' : ('999999' === $code ? 'locked' : 'rejected'));
echo json_encode(['user' => $user, 'result' => $result]);
