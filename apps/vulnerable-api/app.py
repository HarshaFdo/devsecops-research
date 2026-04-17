from flask import Flask, request, jsonify
import sqlite3
import subprocess
import hashlib

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded secret key
SECRET_KEY = "hardcoded_secret_key"
API_KEY = "sk-prod-abc123xyz"

def get_db(): 
    conn = sqlite3.connect('users.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)''')
    conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'password123', 'admin')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2, 'user1', 'pass456', 'user')")
    conn.commit()
    return conn

# VULNERABILITY 2: SQL Injection
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    conn = get_db()

    # Directly concatenating user input - SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = conn.execute(query).fetchone()
    if result:
        return jsonify({"status": "success", "role": result[3]})
    else:
        return jsonify({"status": "failed"}), 401
    
# VULNERABILITY 3: Command Injection
@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host')
    # Directly passing user input to shell command - Command Injection vulnerability
    output = subprocess.check_output(f"ping -c 4 {host}", shell=True)
    return jsonify({"output": output.decode()})

# VULNERABILITY 4: Insecure Hashing
@app.route('/hash', methods=['GET'])
def hash_data():
    data = request.args.get('data')
    # MD5 is cryptographically broken and should not be used for hashing sensitive data
    hashed = hashlib.md5(data.encode()).hexdigest()
    return jsonify({"hashed_data": hashed})

# VULNERABILITY 5: Exposing Sensitive Information
@app.route('/secret', methods=['GET'])
def debug():
    # Exposing sensitive information in the response
    import os 
    return jsonify({
        "env_vars": dict(os.environ),
        "secret_key": SECRET_KEY,
        "api_key": API_KEY
    })

# VULNERABILITY 6: Broken Access Control
@app.route('/admin', methods=['GET'])
def get_all_users():
    # No authentication or authorization checks - Broken Access Control vulnerability
    conn = get_db()
    users = conn.execute("SELECT * FROM users").fetchall()
    return jsonify({"users": [list(u) for u in users]})

if __name__ == '__main__':
    # VULNERABILITY 7: Running in Debug Mode in Production
    app.run(debug=True, host='0.0.0.0', port=5000)