from flask import Flask, request
import os
import sqlite3
import urllib.request

app = Flask(__name__)

# Vulnerability 1: SQL Injection
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Flaw: String concatenation in SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    result = cursor.fetchall()
    return str(result)

# Vulnerability 2: Command Injection
@app.route('/ping')
def ping():
    target = request.args.get('target')
    # Flaw: Passing user input directly to system shell
    os.system(f"ping -c 1 {target}")
    return "Ping executed!"

# Vulnerability 3: Server-Side Request Forgery (SSRF)
@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    # Flaw: Fetching arbitrary user-provided URL unprotected
    response = urllib.request.urlopen(url)
    return response.read()

if __name__ == '__main__':
    app.run(debug=True)
