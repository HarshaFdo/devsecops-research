from flask import Flask, request, jsonify, redirect, make_response
import sqlite3
import subprocess
import hashlib
import pickle
import base64
import urllib.request
import xml.etree.ElementTree as ET
import os
import random
import traceback
import json

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

# VULNERABILITY 8: Path Traversal
@app.route('/download', methods=['GET'])
def download_file():
    filename = request.args.get('filename')
    # User-controlled filename passed directly to open() - Path Traversal vulnerability
    filepath = os.path.join('files', filename)
    with open(filepath, 'r') as f:
        content = f.read()
    return jsonify({"content": content})

# VULNERABILITY 9: Insecure Deserialization
@app.route('/load-session', methods=['POST'])
def load_session():
    session_data = request.form.get('session')
    # Untrusted data passed to pickle.loads() - Insecure Deserialization vulnerability
    decoded = base64.b64decode(session_data)
    session_obj = pickle.loads(decoded)
    return jsonify({"session": str(session_obj)})

# VULNERABILITY 10: Server-Side Request Forgery (SSRF)
@app.route('/fetch-url', methods=['GET'])
def fetch_url():
    target_url = request.args.get('url')
    # User-supplied URL fetched server-side with no validation - SSRF vulnerability
    response = urllib.request.urlopen(target_url)
    return jsonify({"content": response.read().decode(errors='ignore')})

# VULNERABILITY 11: XML External Entity (XXE) Injection
@app.route('/parse-xml', methods=['POST'])
def parse_xml():
    xml_data = request.data
    # XML parsed without disabling external entity resolution - XXE vulnerability
    parser = ET.XMLParser()
    tree = ET.fromstring(xml_data, parser=parser)
    return jsonify({"root_tag": tree.tag})

# VULNERABILITY 12: Open Redirect
@app.route('/redirect', methods=['GET'])
def open_redirect():
    next_url = request.args.get('next')
    # Unvalidated redirect target from user input - Open Redirect vulnerability
    return redirect(next_url)

# VULNERABILITY 13: Insecure Cookie Configuration
@app.route('/set-cookie', methods=['GET'])
def set_cookie():
    resp = make_response(jsonify({"status": "cookie set"}))
    # Cookie set without Secure or HttpOnly flags - Insecure Cookie vulnerability
    resp.set_cookie('session_id', 'abc123', secure=False, httponly=False)
    return resp

# VULNERABILITY 14: Second SQL Injection instance (search endpoint)
@app.route('/search', methods=['GET'])
def search_users():
    term = request.args.get('term')
    conn = get_db()
    # Directly concatenating user input into a second, independent query path - SQL Injection vulnerability
    query = f"SELECT id, username, role FROM users WHERE username LIKE '%{term}%'"
    results = conn.execute(query).fetchall()
    return jsonify({"results": [list(r) for r in results]})

# VULNERABILITY 15: Insecure Direct Object Reference (IDOR)
@app.route('/user/<int:user_id>', methods=['GET'])
def get_user(user_id):
    conn = get_db()
    # No check that the requester is authorised to view this specific user record - IDOR vulnerability
    user = conn.execute("SELECT id, username, role FROM users WHERE id=?", (user_id,)).fetchone()
    if user:
        return jsonify({"id": user[0], "username": user[1], "role": user[2]})
    return jsonify({"status": "not found"}), 404

# VULNERABILITY 16: Mass Assignment
@app.route('/profile/update', methods=['POST'])
def update_profile():
    conn = get_db()
    data = request.get_json()
    user_id = data.get('id')
    # Blindly accepting any client-supplied field name, including 'role', with no allow-list - Mass Assignment vulnerability
    field_names = [k for k in data.keys() if k != 'id']
    set_clause = ', '.join([f"{name}=?" for name in field_names])
    values = [data[name] for name in field_names] + [user_id]
    conn.execute(f"UPDATE users SET {set_clause} WHERE id=?", values)
    conn.commit()
    return jsonify({"status": "updated"})

# VULNERABILITY 17: Unrestricted File Upload
@app.route('/upload', methods=['POST'])
def upload_file():
    uploaded = request.files.get('file')
    # No validation of file extension, content type, or size - Unrestricted File Upload vulnerability
    save_path = os.path.join('uploads', uploaded.filename)
    uploaded.save(save_path)
    return jsonify({"status": "uploaded", "path": save_path})

# VULNERABILITY 18: Insecure Random Token Generation
@app.route('/reset-token', methods=['GET'])
def reset_token():
    username = request.args.get('username')
    # Using the non-cryptographic 'random' module to generate a password-reset token - Insecure Randomness vulnerability
    token = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    return jsonify({"username": username, "reset_token": token})

# VULNERABILITY 19: Weak/Forgeable JWT
@app.route('/token', methods=['POST'])
def issue_token():
    username = request.form.get('username')
    # Hand-rolled token signed with a weak, hardcoded key using MD5 - Weak/Forgeable JWT vulnerability
    payload = json.dumps({"username": username, "role": "user"})
    signature = hashlib.md5((payload + SECRET_KEY).encode()).hexdigest()
    token = base64.b64encode(payload.encode()).decode() + '.' + signature
    return jsonify({"token": token})

# VULNERABILITY 20: Missing CSRF Protection
@app.route('/transfer', methods=['POST'])
def transfer_funds():
    conn = get_db()
    from_id = request.form.get('from_id')
    to_id = request.form.get('to_id')
    amount = request.form.get('amount')
    # State-changing action with no CSRF token validation - Missing CSRF Protection vulnerability
    conn.execute("UPDATE users SET role=role WHERE id=? OR id=?", (from_id, to_id))
    conn.commit()
    return jsonify({"status": "transferred", "amount": amount})

# VULNERABILITY 21: Plaintext Password Storage
@app.route('/register', methods=['POST'])
def register():
    conn = get_db()
    username = request.form.get('username')
    password = request.form.get('password')
    # Password stored directly with no hashing - Plaintext Password Storage vulnerability
    conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'user')", (username, password))
    conn.commit()
    return jsonify({"status": "registered"})

# VULNERABILITY 22: Verbose Error / Stack Trace Exposure
@app.route('/calculate', methods=['GET'])
def calculate():
    numerator = request.args.get('numerator')
    denominator = request.args.get('denominator')
    try:
        result = int(numerator) / int(denominator)
        return jsonify({"result": result})
    except Exception as e:
        # Returning the full stack trace to the client - Verbose Error Exposure vulnerability
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

if __name__ == '__main__':
    # VULNERABILITY 7: Running in Debug Mode in Production
    app.run(debug=True, host='0.0.0.0', port=5000)