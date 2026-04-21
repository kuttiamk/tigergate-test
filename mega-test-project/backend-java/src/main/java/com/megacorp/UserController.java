// =============================================================================
// backend-java/src/main/java/com/megacorp/UserController.java
// =============================================================================
// PURPOSE: Spring Boot REST controller for user management and orders.
//
// ENDPOINTS:
//   GET  /api/users           – List users (SQL Injection via native query)
//   GET  /api/users/{id}      – Get user (IDOR – no ownership check)
//   POST /api/login           – Login (weak auth, password in log)
//   GET  /api/orders          – List orders (N+1 problem)
//   GET  /api/admin           – Admin panel (no authentication!)
//
// ⚠️  INTENTIONAL ISSUES:
//   1. 🔴 SQL Injection via native query string concatenation
//   2. 🔴 IDOR (Insecure Direct Object Reference) on /users/{id}
//   3. 🟡 No authentication or authorization on ANY endpoint
//   4. 🟡 Password logged in plain text
//   5. 🟡 Stack traces returned to clients
//   6. 🟡 Unused private variables (code smell)
//   7. 🟡 Magic numbers instead of constants
//   8. 🟡 Duplicate code across methods (DRY violation)
//   9. 🟡 Method too long (> 40 lines) – code smell
//  10. 🟡 Generic Exception caught everywhere
// =============================================================================
package com.megacorp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api")
// BAD: No @PreAuthorize or security annotations — every endpoint is public
public class UserController {

    @Autowired
    private JdbcTemplate jdbcTemplate; // Used for raw SQL queries

    // BAD: Logger uses class name but we log sensitive data with it
    private static final Logger logger = Logger.getLogger(UserController.class.getName());

    // BAD: Unused private fields — SonarQube: "Remove this unused field"
    private String unusedField = "I am never used"; // BAD: Code smell
    private int magicNumber = 9999; // BAD: Magic number, no constant

    // ==========================================================================
    // GET /api/users?search=...
    // 🔴 SQL INJECTION via native query concatenation!
    // ATTACK: ?search=' UNION SELECT username,password FROM users --
    // ==========================================================================
    @GetMapping("/users")
    public ResponseEntity<List<Map<String, Object>>> getUsers(
            @RequestParam(required = false, defaultValue = "") String search) {

        // 🔴 BAD: String concatenation in SQL query = SQL Injection!
        // SonarQube: "Make sure formatting this SQL query is safe here"
        // FIX WOULD BE: jdbcTemplate.queryForList("SELECT ... WHERE username LIKE ?",
        // "%" + search + "%")
        String sql = "SELECT id, username, email, role, password FROM users " +
                "WHERE username LIKE '%" + search + "%'"; // 🔴 SQL INJECTION!
        // ^^^^^^^^^^^
        // The password column is also selected — data exposure!

        logger.info("Executing user search with query: " + sql); // BAD: Full SQL in logs

        try {
            List<Map<String, Object>> users = jdbcTemplate.queryForList(sql);
            return ResponseEntity.ok(users); // BAD: Returns password field in response!
        } catch (Exception e) {
            // BAD: Full exception (including DB schema info) returned to client
            logger.severe("Error: " + e.getMessage());
            throw new RuntimeException("Database error: " + e.getMessage()); // BAD: Info leak
        }
    }

    // ==========================================================================
    // GET /api/users/{id}
    // BAD: IDOR — any user can access any other user's data without auth
    // BAD: SQL Injection via path variable
    // ==========================================================================
    @GetMapping("/users/{id}")
    public ResponseEntity<Map<String, Object>> getUserById(@PathVariable String id) {
        // BAD: Input not validated — id could be "1 OR 1=1"
        // BAD: String concatenation = SQL Injection again
        String sql = "SELECT * FROM users WHERE id = " + id; // 🔴 SQL INJECTION + IDOR!

        logger.info("Fetching user with id: " + id);

        List<Map<String, Object>> results = jdbcTemplate.queryForList(sql);

        if (results.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        // BAD: Returns password field directly!
        return ResponseEntity.ok(results.get(0));
    }

    // ==========================================================================
    // POST /api/login – Authentication
    // BAD: Multiple security issues in authentication flow
    // ==========================================================================
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");

        // BAD: Password logged in plain text — SonarQube: "Make sure logging this is
        // safe"
        logger.info("Login attempt: username=" + username + " password=" + password); // 🔴 BAD!

        // 🔴 BAD: SQL Injection — same pattern repeated (DRY violation too)
        String sql = "SELECT * FROM users WHERE username='" + username +
                "' AND password='" + password + "'"; // 🔴 SQL INJECTION!
        // ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        // ATTACK: username = "admin' -- " bypasses the password check

        try {
            List<Map<String, Object>> users = jdbcTemplate.queryForList(sql);

            if (users.isEmpty()) {
                return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
            }

            Map<String, Object> user = users.get(0);

            // BAD: Full user object (including password) returned in response!
            // BAD: No JWT or session token generated — just returning raw user data
            logger.info("User logged in: " + user.toString()); // BAD: Logs PII + password
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "user", user // BAD: password column included!
            ));
        } catch (Exception e) {
            // BAD: Generic catch — hides actual error type
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }

    // ==========================================================================
    // GET /api/orders – Orders list with N+1 problem
    // ==========================================================================
    @GetMapping("/orders")
    public ResponseEntity<List<Map<String, Object>>> getOrders() {
        // Query 1 — get all orders
        List<Map<String, Object>> orders = jdbcTemplate.queryForList("SELECT * FROM orders");

        // 🟡 N+1 PROBLEM: One query per order to get username
        // Should be: SELECT o.*, u.username FROM orders o JOIN users u ON o.user_id =
        // u.id
        orders.forEach(order -> {
            Object userId = order.get("user_id");
            // BAD: Query inside a loop — N+1!
            List<Map<String, Object>> users = jdbcTemplate.queryForList(
                    "SELECT username, email FROM users WHERE id = " + userId // BAD: SQLi too!
            );
            if (!users.isEmpty()) {
                order.put("user", users.get(0)); // Attaches user info including email
            }
        });

        return ResponseEntity.ok(orders);
    }

    // ==========================================================================
    // GET /api/admin – Admin endpoint with NO authentication
    // BAD: Any anonymous user can call this!
    // SonarQube: "Make sure granting public access is safe here"
    // ==========================================================================
    @GetMapping("/admin")
    public ResponseEntity<?> adminPanel() {
        // BAD: Returns all users including passwords — completely unsecured
        List<Map<String, Object>> allUsers = jdbcTemplate.queryForList(
                "SELECT id, username, password, email, role FROM users" // BAD: password in select
        );

        // BAD: Returns system property (internal info exposure)
        String systemInfo = System.getProperty("os.name") + " | " + System.getProperty("java.version");

        return ResponseEntity.ok(Map.of(
                "users", allUsers, // BAD: All user data + passwords
                "system", systemInfo, // BAD: OS + JVM version exposure
                "db_url", System.getenv("SPRING_DATASOURCE_URL"), // BAD: DB URL exposed
                "db_pass", System.getenv("SPRING_DATASOURCE_PASSWORD") // 🔴 PASSWORD EXPOSED!
        ));
    }
}
