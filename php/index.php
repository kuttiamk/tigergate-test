<?php
// Vulnerability 1: Reflected Cross-Site Scripting (XSS)
$name = $_GET['name'];
// Flaw: Echoing unescaped user input
echo "Hello, " . $name . "!";

// Vulnerability 2: Path Traversal / Local File Inclusion (LFI)
$page = $_GET['page'];
// Flaw: Including arbitrary files based on user input
include("/var/www/html/" . $page);

// Vulnerability 3: Hardcoded credentials
$db_pass = "super_secret_db_password_123";
?>
