<?php
// Include config file
require_once "db/config.php";

// Initialize the session
session_start();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // SQL Injection vulnerability (for testing)
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $stmt = $pdo->query($sql); // Using PDO

    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
        $_SESSION["loggedin"] = true;
        $_SESSION["id"] = $user["id"];
        $_SESSION["username"] = $user["username"];
        $_SESSION["user_type"] = $user["user_type"];

        if ($user["user_type"] == "admin") {
            header("Location: admin/dashboard.php"); // Redirect to admin dashboard
        } else {
            header("Location: user/home.php"); // Redirect to user home
        }
        exit;
    } else {
        $login_err = "Invalid username or password.";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { font: 14px sans-serif; }
        .wrapper { width: 360px; padding: 20px; margin: 0 auto; margin-top: 50px; }
    </style>
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div id="loginForm" class="mb-5">
                    <h2 class="text-center mb-4">Login</h2>
                    <?php
                    if (!empty($login_err)) {
                        echo '<div class="alert alert-danger">' . $login_err . '</div>';
                    }
                    ?>
                    <form action="" method="post">
                        <div class="mb-3">
                            <label class="form-label">Username</label>
                            <input type="text" name="username" class="form-control" >
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Password</label>
                            <input type="password" name="password" class="form-control" >
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Login</button>
                        <p class="text-center mt-3">Don't have an account? <a href="register.php">Sign up</a></p>
                    </form>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
