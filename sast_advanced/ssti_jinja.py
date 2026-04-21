# =============================================================================
# sast_advanced/ssti_jinja.py – TigerGate CNAPP Test: Advanced SAST
# =============================================================================
# PURPOSE: Demonstrates Server-Side Template Injection (SSTI) in Jinja2/Flask.
# SSTI allows attackers to execute arbitrary Python code by escaping 
# the template sandbox.
#
# VULNERABILITY: CWE-94 – Improper Control of Resource Identifiers ('Code Injection')
# CVE Reference: Many Jinja2-based SSTI vulnerabilities (HTB CTF examples)
# SonarQube Rule: S5131 – Disabling HTML auto-escaping is security-sensitive
# OWASP Reference: A03:2021 – Injection
#
# EXPLOIT PAYLOADS (for educational reference):
#   Basic:  {{ 7*7 }}                                → returns 49
#   RCE:    {{ ''.__class__.__mro__[1].__subclasses__()[396]('id', shell=True, ...) }}
#   Filter: {% for x in ().__class__.__base__.__subclasses__() %}...{% endfor %}
# =============================================================================

from flask import Flask, request, render_template_string, redirect
import os
import subprocess

app = Flask(__name__)

# BAD: Debug mode exposes interactive debugger (full code execution!)
app.config['DEBUG'] = True
# BAD: Secret key is hardcoded and weak
app.config['SECRET_KEY'] = 'ssti_secret_123'

# =============================================================================
# 🔴 VULN: SSTI via render_template_string with unescaped user input
# =============================================================================
HOMEPAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Vulnerable App</title></head>
<body>
  <h1>Hello, {{ name }}!</h1>
  <p>Your message: {{ message }}</p>
</body>
</html>
"""

@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    message = request.args.get('message', '')
    
    # 🔴 VULN: User-controlled 'name' injected directly into template string!
    # FIX: Use render_template('greet.html', name=name) with a separate template file
    vulnerable_template = f"<h1>Hello, {name}!</h1><p>{message}</p>"
    return render_template_string(vulnerable_template)   # 🔴 SSTI!

# =============================================================================
# 🔴 VULN: Endpoint that demonstrates a path to full SSTI sandbox escape
# =============================================================================
@app.route('/render')
def render_user_template():
    user_template = request.args.get('template', 'Hello World')
    
    # 🔴 CRITICAL: User submits the entire template content — maximum SSTI risk!
    # Payload: ?template={{ ''.__class__.__mro__[1].__subclasses__() }}
    return render_template_string(user_template)   # 🔴 Complete SSTI/RCE!

# =============================================================================
# 🔴 VULN: Insecure Redirect (CWE-601 / Open Redirect)
# =============================================================================
@app.route('/goto')
def open_redirect():
    # BAD: User-controlled URL redirect with no validation
    # Exploit: /goto?next=https://phishing.com
    next_url = request.args.get('next', '/')
    return redirect(next_url)   # 🔴 Open Redirect — phishing entry point!

# =============================================================================
# 🔴 VULN: XML External Entity (XXE) Injection (CWE-611)
# =============================================================================
@app.route('/parse-xml', methods=['POST'])
def parse_xml():
    import xml.etree.ElementTree as ET
    xml_data = request.data
    
    # 🔴 BAD: ElementTree does NOT resolve XXE by default from Python 3.8+
    # However, lxml.etree without resolve_entities=False does! This simulates
    # a common mistake when using lxml instead:
    try:
        # BAD: If using lxml: lxml.etree.fromstring(xml_data) - XXE via external entities!
        # Payload: <?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
        tree = ET.fromstring(xml_data)    # Simulated unsafe parser
        return {'tag': tree.tag, 'text': tree.text}
    except Exception as e:
        return {'error': str(e)}, 400    # BAD: Error info exposed!

# =============================================================================
# 🔴 VULN: OS Command Injection (CWE-78) in a utility endpoint
# =============================================================================
@app.route('/ping')
def ping_host():
    host = request.args.get('host', 'localhost')
    # 🔴 BAD: User-controlled 'host' flows directly to shell command!
    # Payload: ?host=127.0.0.1; cat /etc/passwd
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT)
    return output.decode(), 200, {'Content-Type': 'text/plain'}

if __name__ == '__main__':
    # BAD: Bound to 0.0.0.0 — debug app accessible to entire network
    app.run(host='0.0.0.0', port=6000, debug=True)
