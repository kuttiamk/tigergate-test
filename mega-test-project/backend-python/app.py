# =============================================================================
# backend-python/app.py – Flask REST API
# =============================================================================
# PURPOSE: Python/Flask backend that provides:
#   GET  /api/products        – List all products (SQL injection vulnerable)
#   POST /api/login           – User login (weak auth, YAML injection)
#   GET  /api/search          – Search products (SQL + XSS injection)
#   POST /api/calc            – Calculator endpoint (eval() = RCE!)
#   GET  /api/file            – File read endpoint (Path Traversal!)
#   POST /api/yaml-parse      – YAML parsing (Deserialization attack)
#
# ⚠️  INTENTIONAL ISSUES (SonarQube will detect):
#   1. 🔴 SQL Injection via f-string query building
#   2. 🔴 Remote Code Execution via eval()
#   3. 🔴 Path Traversal via open(user_input)
#   4. 🔴 YAML Deserialization via yaml.load() without Loader
#   5. 🔴 OS Command Injection via os.system()
#   6. 🟡 Hardcoded database credentials
#   7. 🟡 Debug mode enabled
#   8. 🟡 Sensitive data (passwords) logged
#   9. 🟡 No input validation
#  10. 🟡 Generic exception handlers hiding real errors
# =============================================================================

import os
import yaml          # BAD: yaml.load() without Loader is dangerous
import mysql.connector
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)

# BAD: Debug enabled — exposes interactive Werkzeug debugger to anyone
# SonarQube: "Make sure using a non-standardized cryptographic algorithm is safe"
app.config['DEBUG'] = True                               # BAD!

# BAD: Hardcoded secret key — same across all deployments
# SonarQube: "Credentials should not be hardcoded"
app.config['SECRET_KEY'] = 'flask_secret_key_1234'      # BAD!

# BAD: CORS allows everything
CORS(app, resources={r"/*": {"origins": "*"}})           # BAD: Wildcard CORS

# =============================================================================
# HARDCODED DATABASE CREDENTIALS
# SonarQube: "Credentials should not be hardcoded"
# =============================================================================
DB_CONFIG = {
    "host":     os.environ.get("DB_HOST", "localhost"),
    "user":     os.environ.get("DB_USER", "root"),
    "password": os.environ.get("DB_PASS", "root123"),    # BAD: Hardcoded fallback!
    "database": os.environ.get("DB_NAME", "megadb")
}

# BAD: Credentials printed at startup
print(f"[DB] Connecting: user={DB_CONFIG['user']} pass={DB_CONFIG['password']}")  # BAD!

# Unused import — SonarQube: "Remove this unused import"
import hashlib  # BAD: Imported but never used

# Unused constant — SonarQube: "Remove this unused variable"
UNUSED_CONSTANT = "I am never used"  # BAD: Code smell


def get_db():
    """
    BAD: Creates a new DB connection on every request.
    Should use a connection pool (e.g., SQLAlchemy with pool_size).
    This causes performance issues at scale (connection exhaustion).
    """
    # BAD: No connection timeout, no retry logic
    return mysql.connector.connect(**DB_CONFIG)


# =============================================================================
# BAD HELPER FUNCTION – Does too many things, too long
# SonarQube: "Refactor this function to reduce its complexity"
# =============================================================================
def validate_and_log(data, source):
    """
    BAD: This function is supposed to validate data but actually does nothing.
    It just logs — including potentially sensitive data!
    """
    # BAD: Logs the entire raw request data — may include passwords, tokens
    print(f"[{source}] Received data: {data}")  # BAD: PII/credentials in logs!
    # BAD: No actual validation done — always returns True
    return True


# =============================================================================
# GET /api/products – List all products
# BAD: SQL Injection via search parameter
# =============================================================================
@app.route('/api/products', methods=['GET'])
def get_products():
    search = request.args.get('search', '')

    # 🔴 BAD: SQL INJECTION!
    # Python f-string used to build SQL — attacker can manipulate entire query
    # ATTACK: search = "' UNION SELECT username,password,email,1,1 FROM users --"
    query = f"SELECT * FROM products WHERE name LIKE '%{search}%'"  # 🔴 SQL INJECTION!

    try:
        conn   = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query)
        products = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(products)
    except Exception as e:
        # BAD: Generic exception — real error hidden
        # BAD: Exception detail returned to client
        return jsonify({"error": str(e)}), 500  # BAD: Info disclosure


# =============================================================================
# POST /api/login – Authenticate user
# BAD: Multiple auth issues
# =============================================================================
@app.route('/api/login', methods=['POST'])
def login():
    data     = request.json
    username = data.get('username', '')
    password = data.get('password', '')

    # BAD: Password logged in plain text
    print(f"Login attempt: username={username}, password={password}")  # 🔴 BAD!

    validate_and_log(data, 'login')   # Logs sensitive data

    # 🔴 BAD: SQL INJECTION via format string
    # ATTACK: username = "admin' --" bypasses password check entirely
    query = "SELECT * FROM users WHERE username='%s' AND password='%s'" % (username, password)

    try:
        conn   = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query)           # BAD: Parameterized query not used!
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            # BAD: Returning full user object including password
            return jsonify({"status": "success", "user": user})  # BAD: Exposes password!
        else:
            return jsonify({"status": "failed"}), 401
    except:                            # BAD: Bare except — catches EVERYTHING including KeyboardInterrupt
        return jsonify({"error": "Login failed"}), 500  # BAD: Silent failure


# =============================================================================
# GET /api/calc – Calculator (eval = REMOTE CODE EXECUTION!)
# SonarQube: "eval() should not be used"
# ATTACK: /api/calc?expr=__import__('os').system('rm+-rf+/')
# =============================================================================
@app.route('/api/calc', methods=['GET'])
def calculator():
    expr = request.args.get('expr', '1+1')  # User-controlled input

    try:
        # 🔴 CRITICAL: eval() with user input = Remote Code Execution!
        # SonarQube: "Make sure executing this expression is safe"
        result = eval(expr)  # 🔴 NEVER USE eval() WITH USER INPUT!
        return jsonify({"expression": expr, "result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# =============================================================================
# GET /api/file – Read file from server (Path Traversal!)
# SonarQube: "Make sure this file path is sanitized"
# ATTACK: /api/file?name=../../etc/passwd
# =============================================================================
@app.route('/api/file', methods=['GET'])
def read_file():
    filename = request.args.get('name', 'readme.txt')  # User-controlled path!

    try:
        # 🔴 BAD: Path Traversal vulnerability!
        # No check that filename stays within intended directory
        # SonarQube: "Make sure this path is sanitized"
        with open(filename, 'r') as f:    # 🔴 PATH TRAVERSAL!
            content = f.read()
        return jsonify({"file": filename, "content": content})
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================================
# POST /api/yaml-parse – YAML Deserialization Attack
# SonarQube: "Do not let yaml.load() deserialize arbitrary objects"
# ATTACK: Send YAML with !!python/object/apply:os.system ['rm -rf /']
# =============================================================================
@app.route('/api/yaml-parse', methods=['POST'])
def parse_yaml():
    raw  = request.data.decode('utf-8')

    try:
        # 🔴 BAD: yaml.load() without Loader=yaml.SafeLoader
        # Allows arbitrary Python object execution via YAML
        # SonarQube: "Use yaml.safe_load() instead of yaml.load()"
        data = yaml.load(raw)  # 🔴 YAML DESERIALIZATION RCE!
        return jsonify({"parsed": str(data)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# =============================================================================
# GET /api/os-command – OS Command Injection
# SonarQube: "OS commands should not be vulnerable to injection attacks"
# ATTACK: /api/os-command?cmd=id;cat+/etc/passwd
# =============================================================================
@app.route('/api/os-command', methods=['GET'])
def run_os_command():
    cmd = request.args.get('cmd', 'echo hello')

    # 🔴 BAD: os.system() with user input = command injection
    # SonarQube: "Make sure dangerous command execution is necessary here"
    output = os.popen(cmd).read()  # 🔴 OS COMMAND INJECTION!

    return jsonify({"command": cmd, "output": output})


# =============================================================================
# GET /api/orders – N+1 query demo
# BAD: A separate DB query for each order
# =============================================================================
@app.route('/api/orders', methods=['GET'])
def get_orders():
    conn   = get_db()
    cursor = conn.cursor(dictionary=True)

    # Query 1: Get all orders
    cursor.execute("SELECT * FROM orders")
    orders = cursor.fetchall()

    result = []
    for order in orders:
        # BAD: N+1 — one extra query PER order
        # Should use a JOIN: SELECT o.*, u.username FROM orders o JOIN users u ON o.user_id = u.id
        cursor.execute(f"SELECT username FROM users WHERE id = {order['user_id']}")  # BAD: SQLi too
        user = cursor.fetchone()
        result.append({**order, "username": user['username'] if user else None})

    cursor.close()
    conn.close()
    return jsonify(result)


# =============================================================================
# 404 Error Handler
# BAD: Exposes server info in error response
# =============================================================================
@app.errorhandler(404)
def not_found(e):
    import platform
    # BAD: Server platform/version info exposed
    return jsonify({
        "error": "Not found",
        "server": platform.platform(),    # BAD: OS info disclosure
        "python": platform.python_version()  # BAD: Runtime version exposed
    }), 404


# =============================================================================
# START THE SERVER
# BAD: Debug=True in production + listening on all interfaces
# =============================================================================
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 5000))
    print(f"[START] Flask running on port {PORT} with SECRET_KEY={app.config['SECRET_KEY']}")  # BAD!
    app.run(
        host='0.0.0.0',   # BAD: Listens on all interfaces
        port=PORT,
        debug=True         # 🔴 BAD: Debug mode in production allows arbitrary code exec via debugger PIN
    )
