# =============================================================================
# python/app.py – TigerGate CNAPP Test: Python Flask Vulnerable Application
# =============================================================================
# PURPOSE: Intentionally vulnerable Flask application for security testing.
# Covers SAST (SonarQube), DAST, and Tigergate CWPP/CNAPP runtime detection.
#
# ⚠️  EDUCATIONAL USE ONLY — Never deploy in production.
#
# VULNERABILITIES COVERED:
#   CWE-89  – SQL Injection (×4)
#   CWE-78  – OS Command Injection
#   CWE-94  – eval() Code Injection
#   CWE-94  – Server-Side Template Injection (SSTI) via render_template_string
#   CWE-22  – Path Traversal
#   CWE-502 – Insecure Deserialization (pickle + yaml.load)
#   CWE-918 – SSRF via urllib
#   CWE-798 – Hardcoded credentials + API keys
#   CWE-327 – Weak MD5 password hashing
#   CWE-676 – Use of dangerous function (os.system)
# =============================================================================

from flask import Flask, request, render_template_string, jsonify, send_file
import sqlite3
import os
import pickle
import base64
import yaml
import hashlib
import urllib.request
import subprocess

app = Flask(__name__)

# =============================================================================
# VULN: CWE-798 – Hardcoded Credentials
# SonarQube Rule: S6418 "Credentials should not be hardcoded"
# FIX: Use environment variables: os.environ.get('SECRET_KEY')
# =============================================================================
app.secret_key       = 'superflasksecret123'              # 🔴 Hardcoded Flask secret!
DB_PASSWORD          = 'root123'                          # 🔴 Hardcoded DB password!
STRIPE_API_KEY       = 'sk_live_FAKE123456789abcdefgh'    # 🔴 Hardcoded API key!
JWT_SECRET           = 'megaweakjwtsecret'                # 🔴 Hardcoded JWT secret!

# VULN: Debug mode ON in production — exposes interactive debugger + stack traces
# SonarQube Rule: S4507
DEBUG_MODE = True                                         # 🔴 Never True in production!


def get_db():
    """Return SQLite connection — using file-based SQLite for demo portability."""
    conn = sqlite3.connect('megadb.sqlite')
    conn.row_factory = sqlite3.Row
    return conn


# =============================================================================
# ENDPOINT 1: GET /api/user?id=...
# VULN: CWE-89 – SQL Injection via f-string
# SonarQube Rule: S3649
# ATTACK: curl "http://localhost:5000/api/user?id=1 OR 1=1"
# ATTACK: curl "http://localhost:5000/api/user?id=1 UNION SELECT username,password,3,4 FROM users"
# FIX: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
# =============================================================================
@app.route('/api/user')
def get_user():
    user_id = request.args.get('id')
    conn = get_db()
    try:
        # 🔴 CRITICAL: User input directly in SQL — SQL Injection!
        query = f"SELECT id, username, email, password, ssn FROM users WHERE id = {user_id}"
        result = conn.execute(query).fetchall()       # 🔴 CWE-89!
        return jsonify([dict(row) for row in result])
    except Exception as e:
        # VULN: Exception detail exposed (includes SQL syntax error with injected code)
        return jsonify({'error': str(e)}), 500        # 🔴 Info disclosure!
    finally:
        conn.close()


# =============================================================================
# ENDPOINT 2: GET /api/products?search=...
# VULN: CWE-89 – SQL Injection via string concatenation in SELECT + LIKE
# ATTACK: curl "http://localhost:5000/api/products?search=Laptop' UNION SELECT username,password,email,4,5 FROM users--"
# FIX: cursor.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{search}%",))
# =============================================================================
@app.route('/api/products')
def search_products():
    search = request.args.get('search', '')
    conn = get_db()
    try:
        # 🔴 BAD: String concatenation in SQL LIKE clause
        sql = "SELECT * FROM products WHERE name LIKE '%" + search + "%'"  # 🔴 SQLi!
        results = conn.execute(sql).fetchall()
        return jsonify([dict(row) for row in results])
    except Exception as e:
        return jsonify({'error': str(e), 'sql': sql}), 500  # 🔴 SQL exposed!
    finally:
        conn.close()


# =============================================================================
# ENDPOINT 3: POST /api/login
# VULN: CWE-89 – SQL Injection in authentication + CWE-327 – MD5 password hashing
# ATTACK: {'username': "admin'--", 'password': 'anything'}
# VULN 2: Passwords hashed with MD5 — easily crackable (use bcrypt instead)
# FIX: Parameterized query + bcrypt.checkpw(password.encode(), user['password_hash'])
# =============================================================================
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username', '')
    password = data.get('password', '')

    # 🔴 BAD: MD5 is cryptographically broken for passwords
    pwd_hash = hashlib.md5(password.encode()).hexdigest()  # 🔴 CWE-327: MD5!

    # 🔴 BAD: SQL Injection in authentication
    sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{pwd_hash}'"  # 🔴 SQLi!
    print(f"[LOG] Login: user={username} pwd={password} hash={pwd_hash}")  # 🔴 Password logged!

    conn = get_db()
    try:
        user = conn.execute(sql).fetchone()
        if user:
            return jsonify({'status': 'success', 'user': dict(user)})  # 🔴 Returns password hash!
        return jsonify({'status': 'failure'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


# =============================================================================
# ENDPOINT 4: GET /api/calc?expr=...
# VULN: CWE-94 – eval() Remote Code Execution
# SonarQube Rule: S1523 "Executing code dynamically is security-sensitive"
# ATTACK: curl "http://localhost:5000/api/calc?expr=__import__('os').popen('id').read()"
# ATTACK: curl "http://localhost:5000/api/calc?expr=__import__('subprocess').check_output(['cat','/etc/passwd']).decode()"
# FIX: Use ast.literal_eval() or a math expression library. NEVER eval() user input.
# =============================================================================
@app.route('/api/calc')
def calculate():
    expr = request.args.get('expr', '1+1')
    try:
        # 🔴 CRITICAL: eval() executes arbitrary Python! Full RCE!
        result = eval(expr)              # 🔴 CWE-94!
        return jsonify({'expression': expr, 'result': result})
    except Exception as e:
        return jsonify({'error': str(e), 'traceback': str(e.__traceback__)}), 400  # 🔴 Traceback!


# =============================================================================
# ENDPOINT 5: GET /api/greet?name=...
# VULN: CWE-94 – Server-Side Template Injection (SSTI)
# ATTACK: curl "http://localhost:5000/api/greet?name={{7*7}}"  → Response: Hello, 49!
# ATTACK: curl "http://localhost:5000/api/greet?name={{self.__init__.__globals__.__builtins__['__import__']('os').popen('id').read()}}"
# WHY: render_template_string() with user input allows Jinja2 expression evaluation!
# FIX: Escape user input before templating: markupsafe.escape(name)
#      Or better: return f"Hello, {name}!" (pure Python, no template)
# =============================================================================
@app.route('/api/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # 🔴 CRITICAL: SSTI — user input rendered as a Jinja2 template!
    template = f"<h1>Hello, {name}!</h1><p>Welcome to MegaCorp.</p>"   # template with user input
    return render_template_string(template)   # 🔴 CWE-94 SSTI!


# =============================================================================
# ENDPOINT 6: GET /api/file?name=...
# VULN: CWE-22 – Path Traversal
# SonarQube Rule: S2083
# ATTACK: curl "http://localhost:5000/api/file?name=/etc/passwd"
# ATTACK: curl "http://localhost:5000/api/file?name=../../etc/shadow"
# FIX:
#   safe_path = os.path.realpath(os.path.join(BASE_DIR, name))
#   if not safe_path.startswith(BASE_DIR): abort(403)
# =============================================================================
@app.route('/api/file')
def read_file():
    filename = request.args.get('name', '')
    # 🔴 BAD: No path validation — reads any file on the server!
    try:
        with open(filename, 'r') as f:         # 🔴 CWE-22 Path Traversal!
            content = f.read()
        return jsonify({'file': filename, 'content': content})
    except Exception as e:
        return jsonify({'error': str(e)}), 404


# =============================================================================
# ENDPOINT 7: GET /api/ping?target=...
# VULN: CWE-78 – OS Command Injection via os.system()
# SonarQube Rule: S4721
# ATTACK: curl "http://localhost:5000/api/ping?target=8.8.8.8;id"
# ATTACK: curl "http://localhost:5000/api/ping?target=8.8.8.8&&cat+/etc/passwd"
# FIX: Use subprocess with list args (no shell): subprocess.run(['ping', '-c', '1', target])
#      Validate target is a valid IP/hostname first.
# =============================================================================
@app.route('/api/ping')
def ping():
    target = request.args.get('target', '127.0.0.1')
    # 🔴 CRITICAL: Shell injection! Attacker can chain commands with ; && || ``
    os.system(f"ping -c 1 {target}")              # 🔴 CWE-78!
    # Also bad: uses os.system (no output capture) — subprocess.run is preferred
    result = subprocess.run(f"ping -c 1 {target}", shell=True, capture_output=True, text=True)  # 🔴 shell=True!
    return jsonify({'target': target, 'output': result.stdout, 'errors': result.stderr})


# =============================================================================
# ENDPOINT 8: GET /api/fetch?url=...
# VULN: CWE-918 – Server-Side Request Forgery (SSRF)
# ATTACK: curl "http://localhost:5000/api/fetch?url=http://169.254.169.254/latest/meta-data/"
#         → Returns AWS IAM credentials!
# ATTACK: curl "http://localhost:5000/api/fetch?url=file:///etc/passwd"
#         → Reads local file (urllib supports file:// !)
# FIX: Block internal IPs (10.x, 172.16.x, 192.168.x, 169.254.x), block file:// scheme
# =============================================================================
@app.route('/api/fetch')
def fetch_url():
    url = request.args.get('url', '')
    try:
        # 🔴 CRITICAL: Fetches any URL — internal services, metadata, file://
        response = urllib.request.urlopen(url)    # 🔴 CWE-918 SSRF!
        content  = response.read().decode('utf-8', errors='replace')
        return jsonify({'url': url, 'status': response.status, 'body': content[:2000]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# =============================================================================
# ENDPOINT 9: POST /api/deserialize
# VULN: CWE-502 – Insecure Deserialization via pickle
# ATTACK: Create malicious pickle:
#   import pickle, base64, os
#   payload = base64.b64encode(pickle.dumps(os.system('id'))).decode()
# WHY: pickle can instantiate arbitrary Python objects → code execution
# FIX: Never pickle/unpickle untrusted data. Use JSON + strict schema validation.
# =============================================================================
@app.route('/api/deserialize', methods=['POST'])
def deserialize():
    data = request.json or {}
    encoded = data.get('data', '')
    try:
        # 🔴 CRITICAL: pickle.loads() on user-supplied data → arbitrary code execution!
        raw = base64.b64decode(encoded)
        obj = pickle.loads(raw)                   # 🔴 CWE-502 RCE via pickle!
        return jsonify({'result': str(obj)})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# =============================================================================
# ENDPOINT 10: POST /api/yaml-load
# VULN: CWE-502 – YAML Deserialization RCE via yaml.load() without SafeLoader
# ATTACK payload (send as body):
#   !!python/object/apply:os.system ['id']
# WHY: yaml.load() can instantiate arbitrary Python objects from YAML
# FIX: ALWAYS use yaml.safe_load() which only supports basic types
# =============================================================================
@app.route('/api/yaml-load', methods=['POST'])
def yaml_load():
    raw_yaml = request.data.decode('utf-8')
    try:
        # 🔴 CRITICAL: yaml.load() without SafeLoader can execute OS commands!
        parsed = yaml.load(raw_yaml, Loader=yaml.Loader)  # 🔴 CWE-502 YAML RCE!
        # FIX would be: yaml.safe_load(raw_yaml)
        return jsonify({'parsed': str(parsed)})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# =============================================================================
# ENDPOINT 11: GET /api/delete?id=...
# VULN: CWE-89 – SQL Injection in DELETE + Missing Authorization
# ATTACK: curl "http://localhost:5000/api/delete?id=1 OR 1=1"  → Deletes ALL records!
# FIX: Parameterized query + proper authentication/authorization check
# =============================================================================
@app.route('/api/delete')
def delete_user():
    user_id = request.args.get('id')
    # 🔴 BAD: No auth check + SQL injection in DELETE
    sql = f"DELETE FROM users WHERE id = {user_id}"  # 🔴 SQLi! id=1 OR 1=1 deletes all!
    conn = get_db()
    try:
        conn.execute(sql)
        conn.commit()
        return jsonify({'deleted': user_id, 'sql': sql})  # 🔴 SQL exposed in response!
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


# =============================================================================
# ENDPOINT 12: GET /api/platform-info
# VULN: CWE-200 – Information Exposure (OS + Python + path details)
# SonarQube Rule: S4507
# This is commonly "harmless" looking but gives attackers recon data
# FIX: Remove this endpoint or require authentication
# =============================================================================
@app.route('/api/platform-info')
def platform_info():
    import sys, platform
    # 🔴 BAD: Exposes OS, Python version, paths — useful for targeted exploits
    return jsonify({
        'os':         platform.system(),
        'os_version': platform.version(),
        'python':     sys.version,
        'path':       sys.path,               # 🔴 Reveals server filesystem structure!
        'cwd':        os.getcwd(),            # 🔴 Reveals working directory!
        'env':        dict(os.environ),       # 🔴 CRITICAL: ALL environment variables!
    })


if __name__ == '__main__':
    # 🔴 BAD: Debug mode exposes interactive Werkzeug debugger (RCE in browser!)
    # 🔴 BAD: host='0.0.0.0' listens on all interfaces including public network
    app.run(debug=DEBUG_MODE, host='0.0.0.0', port=5000)  # 🔴 debug=True!
