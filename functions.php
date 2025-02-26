<?php
// Include config file
require_once "db/config.php";

// Function to track failed login attempts
function trackFailedLoginAttempt($pdo, $ipAddress) {
    $currentTime = date("Y-m-d H:i:s");
    // Check if the IP address already exists in the database
    $sql = "SELECT * FROM login_attempts WHERE ip_address = :ip_address";
    if ($stmt = $pdo->prepare($sql)) {
        $stmt->bindValue(":ip_address", $ipAddress, PDO::PARAM_STR); // Fixed here
        if ($stmt->execute()) {
            $attempts = $stmt->fetchAll(PDO::FETCH_ASSOC);
            if (count($attempts) > 0) {
                // If IP exists, update failed attempts count
                $failedAttempts = $attempts[0]['failed_attempts'] + 1;
                $blockedUntil = $failedAttempts >= 3 ? date("Y-m-d H:i:s", strtotime("+30 minutes")) : null;
                $updateSql = "UPDATE login_attempts SET failed_attempts = :failed_attempts, blocked_until = :blocked_until WHERE ip_address = :ip_address";
                if ($updateStmt = $pdo->prepare($updateSql)) {
                    $updateStmt->bindValue(":failed_attempts", $failedAttempts, PDO::PARAM_INT); // Fixed here
                    $updateStmt->bindValue(":blocked_until", $blockedUntil, PDO::PARAM_STR); // Fixed here
                    $updateStmt->bindValue(":ip_address", $ipAddress, PDO::PARAM_STR); // Fixed here
                    $updateStmt->execute();
                }
            } else {
                // If IP doesn't exist, insert new entry
                $insertSql = "INSERT INTO login_attempts (ip_address, failed_attempts, last_failed_attempt) VALUES (:ip_address, 1, :current_time)";
                if ($insertStmt = $pdo->prepare($insertSql)) {
                    $insertStmt->bindValue(":ip_address", $ipAddress, PDO::PARAM_STR); // Fixed here
                    $insertStmt->bindValue(":current_time", $currentTime, PDO::PARAM_STR); // Fixed here
                    $insertStmt->execute();
                }
            }
        }
    }
}

// Function to get login logs
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

// Function to get failed login attempts by IP address
function getFailedLoginAttempts($pdo, $ipAddress) {
    $attempts = [];
    $sql = "SELECT * FROM login_attempts WHERE ip_address = :ip_address";
    if ($stmt = $pdo->prepare($sql)) {
        $stmt->bindValue(":ip_address", $ipAddress, PDO::PARAM_STR); // Fixed here
        if ($stmt->execute()) {
            $attempts = $stmt->fetchAll(PDO::FETCH_ASSOC);
        }
    }
    return $attempts;
}
?>
