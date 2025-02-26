<?php
// Start the session
session_start();

// Include config file
require_once "../db/config.php";

// Check if the user is logged in, if not then redirect them to login page
if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
    header("location: index.php");
    exit;
}

// Fetch login logs for the current user
function getUserLoginLogs($pdo, $userId) {
    $logs = [];
    $sql = "SELECT * FROM login_logs WHERE user_id = :user_id";
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
    <title>User Page</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f8f9fa;
            margin: 0;
            padding: 20px;
        }

        h1 {
            color: #007bff;
            font-size: 2rem;
            margin-bottom: 30px;
        }

        h3 {
            color: #343a40;
            margin-top: 30px;
        }

        table {
            width: 100%;
            margin-top: 15px;
            margin-bottom: 30px;
        }

        th, td {
            text-align: center;
            padding: 12px;
        }

        th {
            background-color: #007bff;
            color: white;
        }

        td {
            background-color: #f1f1f1;
        }

        .btn-danger {
            background-color: #dc3545;
            border-color: #dc3545;
        }

        .btn-danger:hover {
            background-color: #c82333;
            border-color: #bd2130;
        }
    </style>
</head>
<body>

    <h1>Hi, <b><?php echo htmlspecialchars($_SESSION["username"]); ?></b>. Welcome to your account.</h1>
    
    <!-- User's Login Logs -->
    <h3>Your Recent Login Logs</h3>
    <table class="table table-bordered">
        <thead>
            <tr>
                <th>Login Timestamp</th>
                <th>IP Address</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($userLoginLogs as $log): ?>
            <tr>
                <td><?php echo date("Y-m-d H:i:s", strtotime($log['login_time'])); ?></td>
                <td><?php echo htmlspecialchars($log['ip_address']); ?></td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>

    <!-- User's Failed Login Attempts -->
    <h3>Your Failed Login Attempts (IP: <?php echo htmlspecialchars($ipAddress); ?>)</h3>
    <table class="table table-bordered">
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
                <td><?php echo date("Y-m-d H:i:s", strtotime($attempt['attempt_time'])); ?></td>
                <td><?php echo htmlspecialchars($attempt['ip_address']); ?></td>
                <td><?php echo htmlspecialchars($attempt['status']); ?></td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>

    <p>
    <a href="../Logout.php" class="btn btn-danger">Logout</a>
    </p>

</body>
</html>
