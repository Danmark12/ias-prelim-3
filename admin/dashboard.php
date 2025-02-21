<?php
// Include config file
require_once "../db/config.php";

// Initialize the session
session_start();

// Check if the user is logged in, if not then redirect them to the login page
if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
    header("location:./index.php");
    exit;
}

// Function to get user statistics
function getUserStatistics($pdo) {
    $stats = [
        "admin" => 0,
        "user" => 0,
        "temp-user" => 0, // Assuming 'temp-user' is stored in the database
        "total" => 0
    ];

    $sql = "SELECT user_type, COUNT(*) as count FROM users GROUP BY user_type";
    if ($stmt = $pdo->prepare($sql)) {
        if ($stmt->execute()) {
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $stats[$row["user_type"]] = $row["count"];
            }
        }
        unset($stmt);
    }

    // Total users (admin + user + temp-user)
    $stats["total"] = array_sum($stats);
    return $stats;
}

// Fetch user statistics
$userStats = getUserStatistics($pdo);

// Fetch user accounts
$userAccounts = [];
$sql = "SELECT username, user_type, created_at FROM users ORDER BY created_at DESC";
if ($stmt = $pdo->prepare($sql)) {
    if ($stmt->execute()) {
        $userAccounts = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    unset($stmt);
}

// Fetch recent logins
$recentLogins = [];
$sql = "SELECT u.username, u.user_type, l.login_time FROM login_logs l JOIN users u ON l.user_id = u.id ORDER BY l.login_time DESC LIMIT 10";
if ($stmt = $pdo->prepare($sql)) {
    if ($stmt->execute()) {
        $recentLogins = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    unset($stmt);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>

    <style>
        .flex-container {
            display: flex;
            flex-direction: wrap;
            flex-wrap: wrap;
            justify-content: center;
            margin-top: 15px;
        }

        .flex-container > div {
            background-color: #f1f1f1;
            width: 400px;
            margin-left: 2rem;
            text-align: center;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg bg-body-tertiary">
        <div class="container-fluid">
            <a class="navbar-brand" href="dashboard.php">Home</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarSupportedContent">
                <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                    <!--
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page" href="#">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#">Link</a>
                    </li>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                            Dropdown
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="#">Action</a></li>
                            <li><a class="dropdown-item" href="#">Another action</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="#">Something else here</a></li>
                        </ul>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link disabled" aria-disabled="true">Disabled</a>
                    </li>
                    -->
                </ul>
                <form class="d-flex" role="search">
                    <a href="../logout.php" class="btn btn-danger">Logout</a>
                </form>
            </div>
        </div>
    </nav>
    <h1 style="margin-left:20px">Hi, <b><?php echo htmlspecialchars($_SESSION["username"]); ?></b>. Welcome to the dashboard.</h1>
    
    <!--Start Dashboard-->
    <div class="flex-container">
        <!-- Card 1: Total Admin Users -->
        <div class="card text-bg-success mb-3">
            <div class="card-body">
                <h5 class="card-title">Admin Users</h5>
                <h1 id="totalAdmins"><?php echo $userStats['admin']; ?></h1>
            </div>
        </div>

        <!-- Card 2: Total Users -->
        <div class="card text-bg-primary mb-3">
            <div class="card-body">
                <h5 class="card-title">Users</h5>
                <h1 id="totalUsers"><?php echo $userStats['user']; ?></h1>
            </div>
        </div>

        <!-- Card 3: Temp Users -->
        <div class="card text-bg-danger text-white mb-3">
            <div class="card-body">
                <h5 class="card-title">Temp Users</h5>
                <h1 id="totalTempUsers"><?php echo $userStats['temp-user']; ?></h1>
            </div>
        </div>

        <!-- Card 4: Total User Accounts -->
        <div class="card text-bg-warning text-white mb-3">
            <div class="card-body">
                <h5 class="card-title">Total Users</h5>
                <h1 id="totalAllUsers"><?php echo $userStats['total']; ?></h1>
            </div>
        </div>
    </div>

    <div class="container">
        <h3>User Accounts</h3>
        <table class="table table-bordered">
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Registration Date</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($userAccounts as $user): ?>
                <tr>
                    <td><?php echo htmlspecialchars($user['username']); ?></td>
                    <td><?php echo htmlspecialchars($user['user_type']); ?></td>
                    <td><?php echo date("Y-m-d H:i:s", strtotime($user['created_at'])); ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <h3>Recent Logins</h3>
        <table class="table table-bordered" id="recentLoginsTable">
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Login Timestamp</th>
                    <th>Time Elapsed</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($recentLogins as $login): ?>
                <tr data-login-time="<?php echo htmlspecialchars($login['login_time']); ?>">
                    <td><?php echo htmlspecialchars($login['username']); ?></td>
                    <td><?php echo htmlspecialchars($login['user_type']); ?></td>
                    <td><?php echo date("Y-m-d H:i:s", strtotime($login['login_time'])); ?></td>
                    <td class="time-elapsed"></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <button class="btn btn-primary" onclick="printToPDF()">Print to PDF</button>
    </div>
    <!--End Dashboard-->             

<script>
    function printToPDF() {
        // Select the entire content between Start and End Dashboard tags
        const element = document.querySelector("body"); // Select everything in the body, including cards and tables
        html2canvas(element).then((canvas) => {
            const imgData = canvas.toDataURL("image/png");
            const pdf = new jspdf.jsPDF("p", "mm", "a4");
            const imgWidth = 190;
            const imgHeight = (canvas.height * imgWidth) / canvas.width;
            pdf.addImage(imgData, "PNG", 10, 10, imgWidth, imgHeight);
            pdf.save("dashboard.pdf");
        });
    }

    function timeElapsed(timestamp) {
        const currentTime = Date.now() / 1000;
        const timeDiff = currentTime - new Date(timestamp).getTime() / 1000;

        const intervals = {
            year: 31536000,
            month: 2592000,
            week: 604800,
            day: 86400,
            hour: 3600,
            minute: 60,
            second: 1
        };

        for (const [unit, seconds] of Object.entries(intervals)) {
            const elapsed = timeDiff / seconds;
            if (elapsed >= 1) {
                const rounded = Math.floor(elapsed);
                return `${rounded} ${unit}${rounded > 1 ? 's' : ''} ago`;
            }
        }

        return 'Just now';
    }

    // Apply the time elapsed to the table rows
    window.onload = function() {
        const rows = document.querySelectorAll('#recentLoginsTable tbody tr');
        rows.forEach(row => {
            const loginTime = row.getAttribute('data-login-time');
            const timeElapsedStr = timeElapsed(loginTime);
            row.querySelector('.time-elapsed').textContent = timeElapsedStr;
        });
    }
</script>
</body>
</html>