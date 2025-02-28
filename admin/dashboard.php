<?php
session_start();
require_once '../db/config.php';

// Check if the user is logged in and is an admin
if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true || $_SESSION["user_type"] !== 'admin') {
    header("location: index.php");
    exit;
}

// Fetch login logs
function getLoginLogs($pdo) {
    $logs = [];
    $sql = "SELECT u.username, l.login_time FROM login_logs l JOIN users u ON l.user_id = u.id ORDER BY l.login_time DESC LIMIT 10";
    if ($stmt = $pdo->prepare($sql)) {
        if ($stmt->execute()) {
            $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
        }
    }
    return $logs;
}

// Fetch failed login attempts and check block status
function getFailedLoginAttempts($pdo, $ipAddress) {
    $attempts = [];
    $sql = "SELECT * FROM login_attempts WHERE ip_address = :ip_address";
    if ($stmt = $pdo->prepare($sql)) {
        $stmt->bindParam(":ip_address", $ipAddress, PDO::PARAM_STR);
        if ($stmt->execute()) {
            $attempts = $stmt->fetchAll(PDO::FETCH_ASSOC);
        }
    }

    // Ensure that it always returns an array, even if no data is found
    if (!$attempts) {
        return [];
    }

    // Check if the user is blocked based on failed attempts and block duration
    foreach ($attempts as $attempt) {
        $blockedUntil = strtotime($attempt['blocked_until']);
        if ($blockedUntil && time() < $blockedUntil) {
            // User is still blocked
            return ['isBlocked' => true, 'blockedUntil' => $blockedUntil];
        }
    }

    return ['isBlocked' => false];
}

// Get the IP address of the current request
$ipAddress = $_SERVER['REMOTE_ADDR'];

// Fetch login logs and failed login attempts
$loginLogs = getLoginLogs($pdo);
$blockStatus = getFailedLoginAttempts($pdo, $ipAddress);
$failedAttempts = getFailedLoginAttempts($pdo, $ipAddress);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f7fa;
        }
        .container {
            margin-top: 20px;
        }
        table {
            margin-bottom: 30px;
        }
        h3 {
            color: #007bff;
        }
        .btn-danger {
            background-color: #dc3545;
            border-color: #dc3545;
        }
        .btn-danger:hover {
            background-color: #c82333;
            border-color: #bd2130;
        }

        /* Popup Card Styles */
        .card {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 999;
        }
    </style>
</head>
<body>
    <div class="container">
        <h3 class="my-3">Welcome, Admin</h3>

        <?php if ($blockStatus['isBlocked']): ?>
            <!-- Blocked Popup Card -->
            <div class="card text-white bg-danger mb-3" style="max-width: 18rem;">
                <div class="card-header">Account Blocked</div>
                <div class="card-body">
                    <h5 class="card-title">You have been blocked due to multiple failed login attempts.</h5>
                    <p class="card-text">Your account will be unblocked on: <?php echo date("Y-m-d H:i:s", $blockStatus['blockedUntil']); ?></p>
                </div>
            </div>
        <?php endif; ?>

        <!-- Recent Login Logs Section -->
        <h3 class="my-3">Recent Login Logs</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Login Timestamp</th>
                </tr>
            </thead>
            <tbody>
                <?php if (count($loginLogs) > 0): ?>
                    <?php foreach ($loginLogs as $log): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($log['username']); ?></td>
                        <td><?php echo date("Y-m-d H:i:s", strtotime($log['login_time'])); ?></td>
                    </tr>
                    <?php endforeach; ?>
                <?php else: ?>
                    <tr>
                        <td colspan="2">No recent login logs found.</td>
                    </tr>
                <?php endif; ?>
            </tbody>
        </table>

        <!-- Failed Login Attempts Section -->
        <?php if (count($failedAttempts) > 0): ?>
            <h3 class="my-3">Failed Login Attempts (IP: <?php echo htmlspecialchars($ipAddress); ?>)</h3>
            <table class="table table-bordered table-striped">
                <thead>
                    <tr>
                        <th>Attempt Time</th>
                        <th>IP Address</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($failedAttempts as $attempt): ?>
                    <tr>
                        <td><?php echo date("Y-m-d H:i:s", strtotime($attempt['last_failed_attempt'])); ?></td>
                        <td><?php echo htmlspecialchars($attempt['ip_address']); ?></td>
                        <td>
                            <?php 
                                // Display status based on failed attempts
                                if ($attempt['failed_attempts'] >= 5) {
                                    echo "Blocked";
                                } else {
                                    echo "Failed";
                                }
                            ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php else: ?>
            <p>No failed login attempts found.</p>
        <?php endif; ?>

        <!-- Logout Button -->
        <p>
            <a href="../Logout.php" class="btn btn-danger">Logout</a>
        </p>
    </div>
</body>
</html>
