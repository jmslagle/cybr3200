"""
Challenge 4: Token Entropy Crisis (Extra Credit)
Difficulty: Medium-Hard (30-45 min)
Vulnerability: Weak Session Token Generation with Insufficient Entropy (CWE-330, CWE-331)

The server generates tokens using: MD5(username + timestamp_seconds + small_random)
Students must:
1. Recognize the pattern from their own tokens
2. Find the admin's login timestamp from logs
3. Brute-force the small random component (0-999)

Trust boundary failure: Server trusts that MD5 provides sufficient entropy,
but the inputs are guessable/enumerable.
"""

from flask import Flask, request, make_response, redirect, url_for
import hashlib
import time
import random
import os

app = Flask(__name__)

# The admin logged in at this specific time (visible in "audit logs")
# 1737450000 = January 21, 2025 10:00:00 UTC (approximately)
ADMIN_LOGIN_TIMESTAMP = 1737450000
ADMIN_RANDOM_COMPONENT = 42  # Small enough to brute force

# Generate the admin token using the same algorithm
def generate_admin_token():
    token_input = f"admin{ADMIN_LOGIN_TIMESTAMP}{ADMIN_RANDOM_COMPONENT}"
    return hashlib.md5(token_input.encode()).hexdigest()

ADMIN_TOKEN = generate_admin_token()

ACTIVE_SESSIONS = {
    ADMIN_TOKEN: {
        "username": "admin",
        "role": "admin",
        "login_time": ADMIN_LOGIN_TIMESTAMP,
    }
}

USERS = {
    "analyst": {"password": "analyst2026", "role": "analyst"},
    "operator": {"password": "oper@t0r!", "role": "operator"},
    "auditor": {"password": "aud1t123", "role": "auditor"},
}

FLAG = os.environ.get("FLAG", "flag{test_flag_not_real}")


def generate_token(username):
    """
    VULNERABILITY: Weak token generation
    Token = MD5(username + unix_timestamp + random(0-999))
    
    The random component is too small to provide real entropy.
    If an attacker knows the username and approximate login time,
    they can enumerate all possible tokens.
    """
    timestamp = int(time.time())
    random_component = random.randint(0, 999)
    token_input = f"{username}{timestamp}{random_component}"
    token = hashlib.md5(token_input.encode()).hexdigest()
    
    ACTIVE_SESSIONS[token] = {
        "username": username,
        "role": USERS[username]["role"],
        "login_time": timestamp,
    }
    
    return token, timestamp, random_component


def get_session(token):
    """Retrieve session data"""
    return ACTIVE_SESSIONS.get(token)


@app.route("/")
def index():
    token = request.cookies.get("session")
    session = get_session(token) if token else None
    
    if session:
        return f"""
        <html>
        <head><title>SecureOps Dashboard</title></head>
        <body>
            <h1>SecureOps Monitoring Dashboard</h1>
            <p>Logged in as: <strong>{session['username']}</strong></p>
            <p>Role: {session['role']}</p>
            <hr>
            <h3>Navigation:</h3>
            <ul>
                <li><a href="/status">System Status</a></li>
                <li><a href="/audit">Audit Logs</a></li>
                <li><a href="/vault">Secure Vault</a> (Admin Only)</li>
                <li><a href="/logout">Logout</a></li>
            </ul>
        </body>
        </html>
        """
    
    return """
    <html>
    <head><title>SecureOps Dashboard</title></head>
    <body>
        <h1>SecureOps Monitoring Dashboard</h1>
        <p>Enterprise security monitoring and operations center.</p>
        <p><a href="/login">Login</a></p>
        <hr>
        <p><em>Test accounts: analyst/analyst2026, operator/oper@t0r!, auditor/aud1t123</em></p>
    </body>
    </html>
    """


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    debug_info = None
    
    if request.method == "POST":
        username = request.form.get("username", "").lower()
        password = request.form.get("password", "")
        
        if username in USERS and USERS[username]["password"] == password:
            token, timestamp, rand = generate_token(username)
            resp = make_response(redirect(url_for("index")))
            resp.set_cookie("session", token)
            return resp
        else:
            error = "Authentication failed"
    
    return f"""
    <html>
    <head><title>Login - SecureOps</title></head>
    <body>
        <h1>SecureOps Login</h1>
        {"<p style='color:red'>" + error + "</p>" if error else ""}
        <form method="POST">
            <p>Username: <input type="text" name="username"></p>
            <p>Password: <input type="password" name="password"></p>
            <p><input type="submit" value="Authenticate"></p>
        </form>
        <hr>
        <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    """


@app.route("/status")
def status():
    token = request.cookies.get("session")
    session = get_session(token) if token else None
    
    if not session:
        return redirect(url_for("login"))
    
    return """
    <html>
    <head><title>System Status - SecureOps</title></head>
    <body>
        <h1>System Status</h1>
        <table border="1" cellpadding="10">
            <tr><th>Component</th><th>Status</th></tr>
            <tr><td>Web Server</td><td style="color:green">Online</td></tr>
            <tr><td>Database</td><td style="color:green">Online</td></tr>
            <tr><td>Auth Service</td><td style="color:green">Online</td></tr>
            <tr><td>Monitoring</td><td style="color:green">Online</td></tr>
        </table>
        <hr>
        <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    """


@app.route("/audit")
def audit():
    """
    Audit logs reveal when admin logged in - key information for the attack
    """
    token = request.cookies.get("session")
    session = get_session(token) if token else None
    
    if not session:
        return redirect(url_for("login"))
    
    return f"""
    <html>
    <head><title>Audit Logs - SecureOps</title></head>
    <body>
        <h1>Security Audit Logs</h1>
        <p>Showing recent authentication events:</p>
        
        <pre style="background:#f5f5f5;padding:15px;border:1px solid #ccc;font-family:monospace;">
[2025-01-21 09:45:12 UTC] INFO  auth: System startup complete
[2025-01-21 09:58:33 UTC] INFO  auth: Session cleanup job started
[2025-01-21 10:00:00 UTC] INFO  auth: User 'admin' authenticated successfully
[2025-01-21 10:00:00 UTC] DEBUG auth: Token generated for admin at timestamp {ADMIN_LOGIN_TIMESTAMP}
[2025-01-21 10:00:01 UTC] INFO  auth: Admin session established
[2025-01-21 10:15:44 UTC] INFO  auth: User 'operator' authenticated successfully  
[2025-01-21 10:22:18 UTC] INFO  auth: User 'analyst' authenticated successfully
[2025-01-21 11:30:00 UTC] INFO  auth: Session cleanup job completed
        </pre>
        
        <hr>
        <h3>Token Generation Algorithm (for auditors):</h3>
        <p><em>Tokens are generated using industry-standard MD5 hashing:</em></p>
        <code>token = MD5(username + unix_timestamp + random_padding)</code>
        <p><em>Random padding provides additional entropy (range: 0-999)</em></p>
        
        <hr>
        <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    """


@app.route("/vault")
def vault():
    token = request.cookies.get("session")
    session = get_session(token) if token else None
    
    if not session:
        return redirect(url_for("login"))
    
    if session["role"] != "admin":
        return f"""
        <html>
        <head><title>Access Denied - SecureOps</title></head>
        <body>
            <h1>Secure Vault - Access Denied</h1>
            <p>Your role ({session['role']}) does not have access to the vault.</p>
            <p>Administrator privileges required.</p>
            <hr>
            <p><a href="/">Back to Home</a></p>
        </body>
        </html>
        """
    
    return f"""
    <html>
    <head><title>Secure Vault - SecureOps</title></head>
    <body>
        <h1>Secure Vault</h1>
        <p>Welcome, Administrator.</p>
        
        <div style="background:#efe;padding:20px;border:2px solid green;">
            <h2>Master Encryption Key:</h2>
            <code>{FLAG}</code>
        </div>
        
        <hr>
        <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    """


@app.route("/logout")
def logout():
    token = request.cookies.get("session")
    # Proper logout - but doesn't help with the admin token that's still valid
    if token and token in ACTIVE_SESSIONS and token != ADMIN_TOKEN:
        del ACTIVE_SESSIONS[token]
    
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("session")
    return resp


# Hint endpoint for students who are stuck
@app.route("/hint")
def hint():
    return """
    <html>
    <head><title>Stuck?</title></head>
    <body>
        <h1>Hints for Security Researchers</h1>
        <ol>
            <li>Examine how your own session token is generated</li>
            <li>Check the audit logs for interesting timestamps</li>
            <li>Consider: what inputs go into token generation?</li>
            <li>How many possibilities do you really need to try?</li>
            <li>Python's hashlib and requests modules are your friends</li>
        </ol>
        <hr>
        <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    """


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
