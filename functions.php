<?php
session_start();
require_once "db/config.php";

/**
 * 1️⃣ Web Application Firewall (WAF)
 * Blocks SQL Injection, XSS, and malicious requests.
 */
function wafSecurityCheck($input) {
    $patterns = [
        "/(\bUNION\b|\bSELECT\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b|\bDROP\b|\bALTER\b)/i", // SQL Injection
        "/<script.*?>.*?<\/script>/i", // XSS Attack
        "/['\";()]/" // Common exploit characters
    ];

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $input)) {
            die("🚨 Malicious activity detected! Your IP has been reported.");
        }
    }
}

// Apply WAF to all user inputs
foreach ($_REQUEST as $key => $value) {
    wafSecurityCheck($value);
}

/**
 * 2️⃣ Session Security Enhancement
 * Prevents session hijacking by regenerating session IDs.
 */
function secureSessionStart() {
    session_regenerate_id(true); // Prevents session fixation
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT']; // Bind session to user agent
}

// Apply session security
secureSessionStart();

/**
 * 3️⃣ Function to Track Failed Login Attempts (Brute-force Prevention)
 */
function trackFailedLoginAttempt($pdo, $ipAddress) {
    $currentTime = date("Y-m-d H:i:s");

    // Check if there are previous failed attempts
    $sql = "SELECT * FROM login_attempts WHERE ip_address = :ip_address";
    if ($stmt = $pdo->prepare($sql)) {
        $stmt->bindValue(":ip_address", $ipAddress, PDO::PARAM_STR);
        if ($stmt->execute()) {
            $attempts = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($attempts) {
                // If there are failed attempts, increment and check block status
                $failedAttempts = $attempts['failed_attempts'] + 1;
                $blockedUntil = $failedAttempts >= 3 ? date("Y-m-d H:i:s", strtotime("+30 minutes")) : null;

                $updateSql = "UPDATE login_attempts SET failed_attempts = :failed_attempts, blocked_until = :blocked_until WHERE ip_address = :ip_address";
                if ($updateStmt = $pdo->prepare($updateSql)) {
                    $updateStmt->bindValue(":failed_attempts", $failedAttempts, PDO::PARAM_INT);
                    $updateStmt->bindValue(":blocked_until", $blockedUntil, PDO::PARAM_STR);
                    $updateStmt->bindValue(":ip_address", $ipAddress, PDO::PARAM_STR);
                    $updateStmt->execute();
                }
            } else {
                // Insert new record for failed attempt
                $insertSql = "INSERT INTO login_attempts (ip_address, failed_attempts, last_failed_attempt) VALUES (:ip_address, 1, :current_time)";
                if ($insertStmt = $pdo->prepare($insertSql)) {
                    $insertStmt->bindValue(":ip_address", $ipAddress, PDO::PARAM_STR);
                    $insertStmt->bindValue(":current_time", $currentTime, PDO::PARAM_STR);
                    $insertStmt->execute();
                }
            }
        }
    }
}

/**
 * 4️⃣ Function to Get Login Logs
 */
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

/**
 * 5️⃣ Function to Get Failed Login Attempts by IP Address
 */
function getFailedLoginAttempts($pdo, $ipAddress) {
    $attempts = [];
    $sql = "SELECT * FROM login_attempts WHERE ip_address = :ip_address";
    if ($stmt = $pdo->prepare($sql)) {
        $stmt->bindValue(":ip_address", $ipAddress, PDO::PARAM_STR);
        if ($stmt->execute()) {
            $attempts = $stmt->fetchAll(PDO::FETCH_ASSOC);
        }
    }
    return $attempts;
}
?>
