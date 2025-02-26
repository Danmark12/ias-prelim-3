<?php
// Start the session
session_start();

// Include config file
require_once "../db/config.php";

// Check if the user is logged in, if not then redirect them to the login page
if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
    header("location: index.php");
    exit;
}

// Fetch login logs for the current user
function getUserLoginLogs($pdo, $userId) {
    $logs = [];
    $sql = "SELECT * FROM login_logs WHERE user_id = :user_id ORDER BY login_time DESC";
    if ($stmt = $pdo->prepare($sql)) {
        $stmt->bindParam(":user_id", $userId, PDO::PARAM_INT);
        if ($stmt->execute()) {
            $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
        }
        unset($stmt);
    }
    return $logs;
}

// Fetch failed login attempts for the current user (by IP address)
function getFailedLoginAttempts($pdo, $ipAddress) {
    $attempts = [];
    $sql = "SELECT * FROM login_attempts WHERE ip_address = :ip_address";
    if ($stmt = $pdo->prepare($sql)) {
        $stmt->bindParam(":ip_address", $ipAddress, PDO::PARAM_STR);
        if ($stmt->execute()) {
            $attempts = $stmt->fetchAll(PDO::FETCH_ASSOC);
        }
        unset($stmt);
    }
    return $attempts;
}

// Get the logged-in user's ID from the session
$userId = $_SESSION["id"];
$ipAddress = $_SERVER['REMOTE_ADDR'];

// Fetch user login logs and failed login attempts
$userLoginLogs = getUserLoginLogs($pdo, $userId);
$failedAttempts = getFailedLoginAttempts($pdo, $ipAddress);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>User Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        /* Global Styles */
        body {
            font-family: 'Roboto', sans-serif;
            background-color: #fafafa;
            margin: 0;
            padding: 20px;
            color: #333;
        }

        h1 {
            color: #333;
            font-size: 2.5rem;
            margin-bottom: 20px;
        }

        h3 {
            color: #555;
            font-size: 1.25rem;
            margin-top: 30px;
            margin-bottom: 15px;
        }

        p {
            font-size: 1rem;
            color: #666;
        }

        /* Tables */
        table {
            width: 100%;
            margin-top: 20px;
            margin-bottom: 40px;
            border-collapse: collapse;
        }

        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }

        th {
            background-color: #6c757d;
            color: white;
            font-weight: 500;
        }

        td {
            background-color: #f9f9f9;
        }

        /* Button Styles */
        .btn-danger {
            background-color: #ff6b6b;
            border-color: #ff6b6b;
            color: white;
            font-size: 1rem;
            padding: 10px 20px;
        }

        .btn-danger:hover {
            background-color: #ff4d4d;
            border-color: #ff4d4d;
            color: white;
        }

        /* Minimalist Card */
        .card {
            background-color: white;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }

        .card-header {
            font-size: 1.25rem;
            color: #333;
        }

        .card-body {
            font-size: 1rem;
            color: #555;
        }

    </style>
</head>
<body>

    <div class="container">
        <h1>Welcome, <b><?php echo htmlspecialchars($_SESSION["username"]); ?></b></h1>
        
        <!-- User Dashboard Card -->
        <div class="card">
            <div class="card-header">
                Your Recent Login Logs
            </div>
            <div class="card-body">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Login Timestamp</th>
                            <th>IP Address</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if(count($userLoginLogs) > 0): ?>
                            <?php foreach ($userLoginLogs as $log): ?>
                                <tr>
                                    <td><?php echo date("Y-m-d H:i:s", strtotime($log['login_time'])); ?></td>
                                    <td><?php echo htmlspecialchars($log['ip_address']); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="2">No login logs available.</td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Failed Login Attempts Card -->
        <div class="card">
            <div class="card-header">
                Your Failed Login Attempts (IP: <?php echo htmlspecialchars($ipAddress); ?>)
            </div>
            <div class="card-body">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Attempt Time</th>
                            <th>IP Address</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if(count($failedAttempts) > 0): ?>
                            <?php foreach ($failedAttempts as $attempt): ?>
                                <tr>
                                    <td><?php echo date("Y-m-d H:i:s", strtotime($attempt['attempt_time'])); ?></td>
                                    <td><?php echo htmlspecialchars($attempt['ip_address']); ?></td>
                                    <td><?php echo htmlspecialchars($attempt['status']); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="3">No failed login attempts found.</td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Logout Button -->
        <p>
            <a href="../Logout.php" class="btn btn-danger">Logout</a>
        </p>
    </div>

</body>
</html>
