<?php 
// Include config file
require_once "./db/config.php";

// Initialize the session
session_start();

// Check if the user is already logged in, if so redirect to the appropriate dashboard
if (isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true) {
    if ($_SESSION["user_type"] === "admin") {
        header("location: admin/dashboard.php"); // Redirect to admin dashboard
    } else {
        header("location: user/home.php"); // Redirect to user home
    }
    exit;
}

// Handle the login process
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Get the form data
    $username = trim($_POST["username"]);
    $password = trim($_POST["password"]);

    // Check if the input fields are empty
    if (empty($username) || empty($password)) {
        $error_message = "Please enter username and password.";
    } else {
        // Check if the IP is blocked
        $ip_address = $_SERVER['REMOTE_ADDR'];
        $sql = "SELECT blocked_until FROM login_attempts WHERE ip_address = :ip_address";
        if ($stmt = $pdo->prepare($sql)) {
            $stmt->bindParam(":ip_address", $ip_address, PDO::PARAM_STR);
            if ($stmt->execute()) {
                $login_attempt = $stmt->fetch(PDO::FETCH_ASSOC);
                if ($login_attempt && strtotime($login_attempt['blocked_until']) > time()) {
                    $error_message = "Your IP address is temporarily blocked due to multiple failed login attempts. Please try again later.";
                }
            }
        }

        // If the IP is not blocked, proceed with user authentication
        if (!isset($error_message)) {
            // Check the credentials
            $sql = "SELECT id, username, password, user_type FROM users WHERE username = :username LIMIT 1";
            if ($stmt = $pdo->prepare($sql)) {
                $stmt->bindParam(":username", $username, PDO::PARAM_STR);
                if ($stmt->execute()) {
                    if ($stmt->rowCount() == 1) {
                        // Fetch user data
                        $user = $stmt->fetch(PDO::FETCH_ASSOC);
                        // Verify the password
                        if (password_verify($password, $user['password'])) {
                            // Password is correct, start a session and redirect based on user type
                            $_SESSION["loggedin"] = true;
                            $_SESSION["username"] = $user["username"];
                            $_SESSION["user_type"] = $user["user_type"];
                            $_SESSION["id"] = $user["id"]; // Store user ID

                            // Redirect based on user type
                            if ($_SESSION["user_type"] === "admin") {
                                header("location: admin/dashboard.php");
                            } else {
                                header("location: user/home.php");
                            }
                            exit;
                        } else {
                            // Incorrect password, log the failed attempt
                            logFailedAttempt($ip_address);
                            $error_message = "Incorrect username or password.";
                        }
                    } else {
                        // Username not found, log the failed attempt
                        logFailedAttempt($ip_address);
                        $error_message = "Incorrect username or password.";
                    }
                }
            }
        }
    }
}

// Function to log failed login attempts
function logFailedAttempt($ip_address) {
    global $pdo;
    $sql = "SELECT failed_attempts, last_failed_attempt FROM login_attempts WHERE ip_address = :ip_address";
    if ($stmt = $pdo->prepare($sql)) {
        $stmt->bindParam(":ip_address", $ip_address, PDO::PARAM_STR);
        if ($stmt->execute()) {
            $attempt = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($attempt) {
                // If there are failed attempts, increase the count
                $failed_attempts = $attempt['failed_attempts'] + 1;
                $last_failed_attempt = $attempt['last_failed_attempt'];
            } else {
                // First failed attempt
                $failed_attempts = 1;
                $last_failed_attempt = date("Y-m-d H:i:s");
            }

            // Check if the number of failed attempts exceeds the threshold
            if ($failed_attempts >= 5) {
                // Block the IP address for 15 minutes
                $blocked_until = date("Y-m-d H:i:s", strtotime("+15 minutes"));
            } else {
                $blocked_until = null;
            }

            // Update the login_attempts table
            $sql = "INSERT INTO login_attempts (ip_address, failed_attempts, last_failed_attempt, blocked_until)
                    VALUES (:ip_address, :failed_attempts, :last_failed_attempt, :blocked_until)
                    ON DUPLICATE KEY UPDATE
                    failed_attempts = :failed_attempts, last_failed_attempt = :last_failed_attempt, blocked_until = :blocked_until";
            if ($stmt = $pdo->prepare($sql)) {
                $stmt->bindParam(":ip_address", $ip_address, PDO::PARAM_STR);
                $stmt->bindParam(":failed_attempts", $failed_attempts, PDO::PARAM_INT);
                $stmt->bindParam(":last_failed_attempt", $last_failed_attempt, PDO::PARAM_STR);
                $stmt->bindParam(":blocked_until", $blocked_until, PDO::PARAM_STR);
                $stmt->execute();
            }
        }
    }
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        /* Inline CSS for Suspicious Activity Alert */
        .alert-card {
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background-color: #f44336;
            color: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.2);
            z-index: 1000;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            width: 300px;
        }

        .alert-card .alert-content {
            text-align: center;
        }

        .alert-card button {
            background-color: #fff;
            color: #f44336;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }

        .alert-card button:hover {
            background-color: #f44336;
            color: white;
        }
    </style>
</head>
<body>
    <div class="container mt-5">
        <h2>Login</h2>
        
        <?php 
        if (isset($error_message)) {
            echo "<div class='alert alert-danger'>$error_message</div>";
        }

        // Show the alert card if malicious activity is detected
        if (isset($error_message) && strpos($error_message, "temporarily blocked") !== false) {
            echo '
            <div class="alert-card">
                <div class="alert-content">
                    <h2>Suspicious Activity Detected!</h2>
                    <p>Your IP address has been temporarily blocked due to multiple failed login attempts.</p>
                    <button onclick="closeAlert()">Close</button>
                </div>
            </div>';
        }
        ?>
        
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="mb-3">
                <label for="username" class="form-label">Username</label>
                <input type="text" class="form-control" id="username" name="username" required>
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" required>
            </div>
            <button type="submit" class="btn btn-primary">Login</button>
        </form>

        <p class="text-center mt-3">Already have an account? <a href="Register.php">Sign Up here</a>.</p>
    </div>

    <script>
        // Function to close the alert card
        function closeAlert() {
            document.querySelector('.alert-card').style.display = 'none';
        }
    </script>   
</body>
</html>
