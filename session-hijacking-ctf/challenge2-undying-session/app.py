"""
Challenge 2: The Undying Session
Difficulty: Easy (10-15 min)
Vulnerability: Session tokens never expire / Replay attack (CWE-613)

The server generates cryptographically random tokens but never expires them.
A "leaked" admin token from a security incident report is still valid.

Trust boundary failure: Server trusts any token that was ever valid,
regardless of age or context.
"""

from flask import Flask, request, make_response, redirect, url_for
import secrets
import os

app = Flask(__name__)

# In a real app this would be a database
# The "leaked" token is hardcoded to simulate a breach from 6 months ago
LEAKED_ADMIN_TOKEN = "a]48f!Kx9#mZq2$vL7@nR5"

ACTIVE_SESSIONS = {
    # This token was "leaked" in a security incident 6 months ago
    # but was never invalidated
    LEAKED_ADMIN_TOKEN: {
        "username": "admin",
        "role": "admin",
        "created": "2025-07-15T14:32:00Z",  # 6 months old!
    }
}

USERS = {
    "guest": {"password": "guest123", "role": "user"},
    "analyst": {"password": "analyst456", "role": "user"},
    "intern": {"password": "intern789", "role": "user"},
}

FLAG = os.environ.get("FLAG", "flag{test_flag_not_real}")


def create_session(username, role):
    """Generate a new session token"""
    token = secrets.token_urlsafe(16)
    ACTIVE_SESSIONS[token] = {
        "username": username,
        "role": role,
        "created": "2026-01-21T10:00:00Z",
    }
    return token


def get_session(token):
    """Retrieve session data - NO EXPIRATION CHECK!"""
    return ACTIVE_SESSIONS.get(token)


@app.route("/")
def index():
    token = request.cookies.get("session_id")
    session = get_session(token) if token else None
    
    if session:
        return f"""
        <html>
        <head><title>Incident Response Portal</title></head>
        <body>
            <h1>ACME Corp Incident Response Portal</h1>
            <p>Logged in as: <strong>{session['username']}</strong></p>
            <p>Role: {session['role']}</p>
            <hr>
            <p><a href="/incidents">View Security Incidents</a></p>
            <p><a href="/classified">Classified Reports</a></p>
            <p><a href="/logout">Logout</a></p>
        </body>
        </html>
        """
    
    return """
    <html>
    <head><title>Incident Response Portal</title></head>
    <body>
        <h1>ACME Corp Incident Response Portal</h1>
        <p>Please <a href="/login">login</a> to access the system.</p>
        <hr>
        <p><em>Available accounts: guest/guest123, analyst/analyst456, intern/intern789</em></p>
    </body>
    </html>
    """


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").lower()
        password = request.form.get("password", "")
        
        if username in USERS and USERS[username]["password"] == password:
            token = create_session(username, USERS[username]["role"])
            resp = make_response(redirect(url_for("index")))
            resp.set_cookie("session_id", token)
            return resp
        else:
            error = "Invalid credentials"
    
    return f"""
    <html>
    <head><title>Login - Incident Response Portal</title></head>
    <body>
        <h1>Portal Login</h1>
        {"<p style='color:red'>" + error + "</p>" if error else ""}
        <form method="POST">
            <p>Username: <input type="text" name="username"></p>
            <p>Password: <input type="password" name="password"></p>
            <p><input type="submit" value="Login"></p>
        </form>
        <hr>
        <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    """


@app.route("/incidents")
def incidents():
    token = request.cookies.get("session_id")
    session = get_session(token) if token else None
    
    if not session:
        return redirect(url_for("login"))
    
    return """
    <html>
    <head><title>Security Incidents</title></head>
    <body>
        <h1>Recent Security Incidents</h1>
        
        <h3>INC-2025-0142: Session Token Leak (RESOLVED)</h3>
        <p><strong>Date:</strong> July 15, 2025</p>
        <p><strong>Severity:</strong> High</p>
        <p><strong>Description:</strong> During routine log analysis, an administrator's 
        session token was discovered in debug logs that were briefly exposed:</p>
        <pre style="background:#fee;padding:10px;border:1px solid red;">
[2025-07-15 14:32:00] DEBUG auth.session: Admin login successful
[2025-07-15 14:32:00] DEBUG auth.session: Generated token: a]48f!Kx9#mZq2$vL7@nR5
[2025-07-15 14:32:00] DEBUG auth.session: Session stored for user 'admin'
        </pre>
        <p><strong>Remediation:</strong> Debug logging disabled. Logs rotated. 
        <span style="color:green">Issue marked resolved.</span></p>
        <p><em>Note: Token rotation deemed unnecessary as exposure window was minimal.</em></p>
        
        <hr>
        
        <h3>INC-2025-0089: Phishing Attempt</h3>
        <p><strong>Date:</strong> March 22, 2025</p>
        <p><strong>Severity:</strong> Medium</p>
        <p><strong>Description:</strong> Phishing emails targeting employees detected and blocked.</p>
        
        <hr>
        <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    """


@app.route("/classified")
def classified():
    token = request.cookies.get("session_id")
    session = get_session(token) if token else None
    
    if not session:
        return redirect(url_for("login"))
    
    if session["role"] != "admin":
        return """
        <html>
        <head><title>Access Denied</title></head>
        <body>
            <h1>Access Denied</h1>
            <p>You do not have permission to view classified reports.</p>
            <p>Administrator access required.</p>
            <hr>
            <p><a href="/">Back to Home</a></p>
        </body>
        </html>
        """
    
    return f"""
    <html>
    <head><title>Classified Reports</title></head>
    <body>
        <h1>Classified Reports</h1>
        <p>Welcome, Administrator.</p>
        <div style="background:#efe;padding:20px;border:2px solid green;">
            <h2>Top Secret Encryption Key:</h2>
            <code>{FLAG}</code>
        </div>
        <hr>
        <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    """


@app.route("/logout")
def logout():
    # Note: This logout does properly remove the session (unlike challenge 3)
    # But that doesn't help if old tokens are never expired!
    token = request.cookies.get("session_id")
    if token and token in ACTIVE_SESSIONS:
        # Don't delete the leaked token to keep the challenge working
        if token != LEAKED_ADMIN_TOKEN:
            del ACTIVE_SESSIONS[token]
    
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("session_id")
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
