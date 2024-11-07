<?php
session_start();

header('Content-Type: application/json'); // Ensure JSON response for AJAX requests

$ip = $_SERVER['REMOTE_ADDR'];
$rate_limit = 20; // Maximum requests
$time_window = 60 * 60; // 1 hour in seconds

// Session requests array initialization
if (!isset($_SESSION['requests'])) {
    $_SESSION['requests'] = [];
}

$requests = &$_SESSION['requests'];
$now = time();

// Clean up old entries
foreach ($requests as $ip_address => $data) {
    if ($data['last_request'] + $time_window < $now) {
        unset($requests[$ip_address]);
    }
}

// Honeypot field check
if (!empty($_POST['hidden_address_field'])) {
    echo json_encode(["status" => "fail", "reason" => "bot_detected"]);
    exit();
}

// Mouse movement check
$mouse_movement = $_POST['mouse_movement'] ?? null;
if ($mouse_movement !== 'human') {
    echo json_encode(["status" => "fail", "reason" => "suspicious_activity"]);
    exit();
}

// User-Agent check
$user_agent = $_SERVER['HTTP_USER_AGENT'];
$suspicious_agents = ['bot', 'crawl', 'spider', 'curl', 'wget'];
foreach ($suspicious_agents as $agent) {
    if (stripos($user_agent, $agent) !== false) {
        echo json_encode(["status" => "fail", "reason" => "bot_user_agent_detected"]);
        exit();
    }
}

// Rate limiting check
if (isset($requests[$ip])) {
    $requests[$ip]['count']++;
    $requests[$ip]['last_request'] = $now;

    if ($requests[$ip]['count'] > $rate_limit) {
        echo json_encode(["status" => "fail", "reason" => "rate_limit_exceeded"]);
        exit();
    }
} else {
    $requests[$ip] = ['count' => 1, 'last_request' => $now];
}

// If all checks pass
echo json_encode(["status" => "success"]);
exit();
