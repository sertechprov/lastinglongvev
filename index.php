<?php
// Enable CORS for your Cloudflare domain
header("Access-Control-Allow-Origin: https://acipnergy.com"); // Replace with your actual Cloudflare domain
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type");
header("Content-Type: application/json");

// Start session to handle rate-limiting and tracking
session_start();

// Settings for rate limiting
$rate_limit = 20; // Max requests allowed per IP
$time_window = 3600; // Time window in seconds (1 hour)
$now = time();

// Initialize or clean up session requests array
if (!isset($_SESSION['requests'])) {
    $_SESSION['requests'] = [];
}
$requests = &$_SESSION['requests'];
$ip = $_SERVER['REMOTE_ADDR'];

// Remove old entries outside of the time window
foreach ($requests as $ip_address => $data) {
    if ($data['last_request'] + $time_window < $now) {
        unset($requests[$ip_address]);
    }
}

// Honeypot field to catch bots
$honeypotField = $_POST['hidden_address_field'] ?? '';
if (!empty($honeypotField)) {
    echo json_encode(["status" => "fail", "reason" => "bot_detected"]);
    exit();
}

// Check mouse movement validation
$mouseMovement = $_POST['mouse_movement'] ?? 'bot';
if ($mouseMovement !== 'human') {
    echo json_encode(["status" => "fail", "reason" => "mouse_movement_not_detected"]);
    exit();
}

// Rate-limiting logic
if (isset($requests[$ip])) {
    $requests[$ip]['count']++;
    $requests[$ip]['last_request'] = $now;
    if ($requests[$ip]['count'] > $rate_limit) {
        http_response_code(429);
        echo json_encode(["status" => "fail", "reason" => "rate_limit_exceeded"]);
        exit();
    }
} else {
    $requests[$ip] = ['count' => 1, 'last_request' => $now];
}

// If all checks are passed, send success response
echo json_encode(["status" => "success"]);
