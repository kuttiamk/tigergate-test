<?php
// =============================================================================
// vulnerable-php/index.php – DVWA-Style Vulnerable PHP Application
// =============================================================================
// PURPOSE: A simple PHP web app similar to DVWA (Damn Vulnerable Web Application).
//          Used for training security engineers and testing Tigergate/SonarQube.
//
// PAGES (via ?page= parameter):
//   login     – Login form (SQLi, no brute-force protection)
//   sqli      – SQL Injection demo
//   xss       – Cross-Site Scripting demo
//   fileread  – Local File Inclusion / Path Traversal
//   upload    – Unsafe file upload
//   exec      – OS command injection
//   info      – phpinfo() exposure
//
// ⚠️  INTENTIONAL ISSUES (SonarQube will detect ALL of these):
//   1. 🔴 SQL Injection in every database call
//   2. 🔴 XSS – reflected user input without escaping
//   3. 🔴 Local File Inclusion (LFI) / Path Traversal
//   4. 🔴 OS Command Injection via shell_exec()
//   5. 🔴 Unrestricted file upload (accepts PHP files!)
//   6. 🔴 phpinfo() page exposed
//   7. 🟡 Hardcoded database credentials
//   8. 🟡 Passwords stored in plain text
//   9. 🟡 MD5 used for "hashing" (cryptographically broken)
//  10. 🟡 Error messages expose DB structure
//  11. 🟡 No CSRF protection on any form
//  12. 🟡 register_globals style coding (using extract($_GET))
// =============================================================================

// =============================================================================
// HARDCODED CREDENTIALS
// BAD: SonarQube: "Credentials should not be hardcoded"
// =============================================================================
define('DB_HOST', getenv('DB_HOST') ?: 'localhost');
define('DB_USER', getenv('DB_USER') ?: 'root');
define('DB_PASS', getenv('DB_PASS') ?: 'root123');       // BAD: Hardcoded fallback!
define('DB_NAME', getenv('DB_NAME') ?: 'megadb');

// BAD: All $_GET, $_POST variables "imported" into current scope
// SonarQube: "Make sure user-controlled data is properly sanitized"
// BAD: This is the old register_globals anti-pattern
extract($_GET);   // 🔴 BAD: Any GET param becomes a variable! (Variable injection)

// Connect to MySQL — BAD: No error handling for connection failure
$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);

// BAD: Error message exposes full DB connection details
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);  // BAD: Info disclosure
}

// Current page — default to login
$page = isset($_GET['page']) ? $_GET['page'] : 'login';

// =============================================================================
// SESSION MANAGEMENT
// BAD: Session started without security settings
// =============================================================================
// BAD: No session.cookie_httponly, no session.cookie_secure
session_start();  // BAD: Vulnerable to session fixation

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <!-- BAD: No Content-Security-Policy header -->
    <title>MegaCorp Vulnerable App</title>
    <style>
        body { background:#111; color:#eee; font-family:monospace; padding:20px; }
        nav a { color:#e94560; margin-right:15px; text-decoration:none; }
        .vuln-box { background:#1a1a2e; border:1px solid #e94560; padding:16px; border-radius:8px; margin:16px 0; }
        .warning { color:#ffd700; }
        input,textarea { background:#1a1a2e; color:#eee; border:1px solid #555; padding:8px; width:100%; margin:4px 0; }
        button,input[type=submit] { background:#e94560; color:#fff; border:none; padding:8px 18px; cursor:pointer; }
        pre { background:#000; padding:10px; overflow:auto; }
    </style>
</head>
<body>

<h1>🔓 MegaCorp – Vulnerable PHP App (DVWA-Style)</h1>
<p class="warning">⚠️ This app is intentionally vulnerable for security training. DO NOT use in production!</p>

<nav>
    <a href="?page=login">Login</a>
    <a href="?page=sqli">SQL Injection</a>
    <a href="?page=xss">XSS</a>
    <a href="?page=fileread">File Read (LFI)</a>
    <a href="?page=upload">File Upload</a>
    <a href="?page=exec">Command Exec</a>
    <a href="?page=info">PHP Info</a>
</nav>

<hr>

<?php

// =============================================================================
// LOGIN PAGE – SQL Injection + Weak Auth
// =============================================================================
if ($page === 'login') {
    echo '<div class="vuln-box">';
    echo '<h2>🔐 Login (SQL Injection Vulnerable)</h2>';
    echo '<p class="warning">Try: username = <code>admin\' --</code> with any password</p>';

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = $_POST['username'];  // BAD: No sanitization!
        $password = $_POST['password'];  // BAD: No sanitization!

        // BAD: Password logged!
        error_log("Login attempt: user=$username pass=$password");  // BAD!

        // 🔴 BAD: SQL INJECTION via string concatenation
        // ATTACK: username = "admin' --" | logs in as admin without password!
        $query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
        //                                              ^^^^^^^^^ SQL INJECTION!

        // BAD: Error reporting enabled — shows SQL errors to user
        $result = $conn->query($query);  // 🔴 Direct query with user input!

        if ($result && $result->num_rows > 0) {
            $user = $result->fetch_assoc();
            $_SESSION['user'] = $user;  // BAD: Full user object (with password) in session
            $_SESSION['role'] = $user['role'];
            echo "<p style='color:green'>✅ Welcome {$user['username']}! (Role: {$user['role']})</p>";
            echo "<pre>User data: " . print_r($user, true) . "</pre>";  // BAD: Dumps password!
        } else {
            // BAD: Shows DB errors to user
            if ($conn->error) {
                echo "<p style='color:red'>DB Error: {$conn->error}</p>";  // BAD: SQL error exposed
            } else {
                echo "<p style='color:red'>Invalid credentials</p>";
            }
        }
    }

    // No CSRF token on form — SonarQube flags this
    echo '<form method="POST">';
    echo '<input type="text"     name="username" placeholder="Username (try: admin\'--)" /><br>';
    echo '<input type="password" name="password" placeholder="Password (anything works)" /><br>';
    echo '<input type="submit"   value="Login" />';
    echo '</form></div>';
}

// =============================================================================
// SQL INJECTION PAGE
// =============================================================================
elseif ($page === 'sqli') {
    echo '<div class="vuln-box">';
    echo '<h2>💉 SQL Injection Demo</h2>';
    echo '<p class="warning">Try: ID = <code>1 UNION SELECT username,password,email,1,1,1 FROM users --</code></p>';

    if (isset($_GET['id'])) {
        $id = $_GET['id'];  // BAD: No validation, no casting to int

        // 🔴 BAD: Classic SQL Injection in URL parameter
        $query = "SELECT * FROM users WHERE id = $id";  // 🔴 SQL INJECTION!

        $result = $conn->query($query);

        if ($result) {
            echo '<pre>';
            while ($row = $result->fetch_assoc()) {
                print_r($row);  // BAD: Dumps all columns including password
            }
            echo '</pre>';
        } else {
            // BAD: Raw SQL error shown to user — reveals table structure
            echo "<p style='color:red'>SQL Error: {$conn->error}</p>";  // BAD!
        }
    }

    echo '<form method="GET">';
    echo '<input type="hidden" name="page" value="sqli">';
    echo '<input type="text" name="id" placeholder="User ID (e.g., 1 OR 1=1)" />';
    echo '<input type="submit" value="Get User" />';
    echo '</form></div>';
}

// =============================================================================
// XSS PAGE – Reflected Cross-Site Scripting
// =============================================================================
elseif ($page === 'xss') {
    echo '<div class="vuln-box">';
    echo '<h2>🧨 XSS – Cross-Site Scripting Demo</h2>';
    echo '<p class="warning">Try: <code>&lt;script&gt;alert(\'XSS\')&lt;/script&gt;</code></p>';

    if (isset($_GET['name'])) {
        $name = $_GET['name'];  // BAD: Reflected without any escaping!

        // 🔴 BAD: PHP echo of unescaped user input = Reflected XSS
        // SonarQube: "Make sure this reflected value is properly sanitized"
        // FIX WOULD BE: echo "Hello " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
        echo "<p>Hello <strong>$name</strong>!</p>";  // 🔴 XSS!
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['comment'])) {
        $comment = $_POST['comment'];  // BAD: Stored XSS (stored in DB below)

        // 🔴 BAD: Stored XSS — comment stored raw, echoed raw elsewhere
        $query = "INSERT INTO audit_logs (action, payload) VALUES ('comment', '$comment')";
        $conn->query($query);  // BAD: SQLi + Stored XSS in one line!
        echo "<p style='color:green'>Comment saved: $comment</p>";  // BAD: Immediate XSS echo
    }

    echo '<form method="GET">';
    echo '<input type="hidden" name="page" value="xss">';
    echo '<input type="text" name="name" placeholder="Type your name: <script>alert(1)</script>" />';
    echo '<input type="submit" value="Submit (Reflected XSS)" />';
    echo '</form>';

    echo '<form method="POST">';
    echo '<input type="hidden" name="page" value="xss">';
    echo '<textarea name="comment" placeholder="Comment (Stored XSS demo)"></textarea><br>';
    echo '<input type="submit" value="Save Comment (Stored XSS)" />';
    echo '</form></div>';
}

// =============================================================================
// FILE READ PAGE – Local File Inclusion / Path Traversal
// =============================================================================
elseif ($page === 'fileread') {
    echo '<div class="vuln-box">';
    echo '<h2>📂 Path Traversal / LFI Demo</h2>';
    echo '<p class="warning">Try: filename = <code>../../etc/passwd</code></p>';

    if (isset($_GET['filename'])) {
        $filename = $_GET['filename'];  // BAD: No validation of path!

        // 🔴 BAD: Path Traversal — user can read any file on the server!
        // SonarQube: "Make sure this file path is sanitized"
        // ATTACK: ?filename=../../etc/passwd reads the Linux password file
        if (file_exists($filename)) {
            echo "<h3>Contents of: $filename</h3>";  // BAD: Reflected path without escaping
            echo "<pre>" . file_get_contents($filename) . "</pre>";  // 🔴 PATH TRAVERSAL!
        } else {
            echo "<p>File not found: $filename</p>";  // BAD: Path reflected back
        }
    }

    echo '<form method="GET">';
    echo '<input type="hidden" name="page" value="fileread">';
    echo '<input type="text" name="filename" placeholder="e.g., /etc/passwd or ../../etc/hosts" />';
    echo '<input type="submit" value="Read File" />';
    echo '</form></div>';
}

// =============================================================================
// FILE UPLOAD PAGE – Unrestricted File Upload
// =============================================================================
elseif ($page === 'upload') {
    echo '<div class="vuln-box">';
    echo '<h2>📤 Unrestricted File Upload Demo</h2>';
    echo '<p class="warning">Upload a PHP webshell: <code>&lt;?php system($_GET[\'cmd\']); ?&gt;</code> saved as shell.php</p>';

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
        $file = $_FILES['file'];
        $dest = '/tmp/uploads/' . $file['name'];  // BAD: Uses original filename!

        // 🔴 BAD: No file type validation! PHP files accepted = Remote Code Execution
        // SonarQube: "Make sure the content of this file is safe"
        // FIX WOULD BE: Check extension whitelist + MIME type + Content-Type
        if (move_uploaded_file($file['tmp_name'], $dest)) {
            echo "<p style='color:green'>✅ File uploaded: $dest</p>";  // BAD: Full path exposed
            echo "<p>Access at: <a href='/uploads/{$file['name']}'>/uploads/{$file['name']}</a></p>";
        } else {
            echo "<p style='color:red'>Upload failed</p>";
        }
    }

    echo '<form method="POST" enctype="multipart/form-data">';
    echo '<input type="hidden" name="page" value="upload">';
    echo '<input type="file" name="file" /><br>';
    echo '<input type="submit" value="Upload (No validation!)" />';
    echo '</form></div>';
}

// =============================================================================
// COMMAND EXECUTION PAGE – OS Command Injection
// =============================================================================
elseif ($page === 'exec') {
    echo '<div class="vuln-box">';
    echo '<h2>💻 OS Command Injection Demo</h2>';
    echo '<p class="warning">Try: cmd = <code>id; cat /etc/passwd; ls /</code></p>';

    if (isset($_GET['cmd'])) {
        $cmd = $_GET['cmd'];  // BAD: User-controlled OS command!

        echo "<p>Running: <code>$cmd</code></p>";  // BAD: Reflected XSS too

        // 🔴 BAD: shell_exec() with user input = full OS command injection
        // SonarQube: "Make sure dangerous command execution is necessary here"
        // Any command the web server user can run — could be rm -rf, curl malware, etc.
        $output = shell_exec($cmd);  // 🔴 OS COMMAND INJECTION!

        echo "<pre>$output</pre>";   // BAD: Command output shown to user
    }

    echo '<form method="GET">';
    echo '<input type="hidden" name="page" value="exec">';
    echo '<input type="text" name="cmd" placeholder="OS command: id; whoami; ls /" />';
    echo '<input type="submit" value="Execute!" />';
    echo '</form></div>';
}

// =============================================================================
// PHP INFO PAGE – Information Disclosure
// =============================================================================
elseif ($page === 'info') {
    // 🔴 BAD: phpinfo() exposes server config, PHP settings, env vars, installed modules
    // SonarQube: "Exposing phpinfo() to users is dangerous"
    // Attackers can extract DB passwords, path info, and server details
    phpinfo();  // 🔴 CRITICAL INFO DISCLOSURE!
}

?>

<hr>
<p style="color:#666; font-size:12px;">
    <!-- BAD: Version info in footer — tells attackers what to target -->
    PHP <?php echo PHP_VERSION; ?> | MySQL <?php echo $conn->server_version; ?>
</p>

</body>
</html>

<?php
$conn->close();
?>
