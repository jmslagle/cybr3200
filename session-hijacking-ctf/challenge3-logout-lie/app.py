"""
Challenge 3: Logout is a Lie
Difficulty: Easy-Medium (10-15 min)
Vulnerability: Insufficient Session Expiration on Logout (CWE-613)

MECHANIC: Admin panel requires "logout verification" before showing sensitive data.
Logout sets a verification cookie but ONLY deletes the auth cookie client-side.
Students must:
1. Log in as manager, capture the auth_token
2. Visit /admin - told they need to complete "logout verification" first
3. Click logout - gets logout_verified cookie, loses auth_token cookie
4. Replay the captured auth_token while keeping logout_verified
5. Both cookies present = flag

Trust boundary failure: Server trusts that deleting the client cookie
terminates the session. The session remains valid server-side.
"""

from flask import Flask, request, make_response, redirect
import secrets
import os

app = Flask(__name__)

# Server-side session store
ACTIVE_SESSIONS = {}

USERS = {
    "developer": {"password": "dev2026!", "role": "developer"},
    "tester": {"password": "test123", "role": "tester"},
    "manager": {"password": "manage456", "role": "manager"},
}

FLAG = os.environ.get("FLAG", "flag{test_flag_not_real}")


def create_session(username, role):
    """Generate a new session token"""
    token = secrets.token_hex(24)
    ACTIVE_SESSIONS[token] = {
        "username": username,
        "role": role,
    }
    return token


def get_session(token):
    """Retrieve session data"""
    return ACTIVE_SESSIONS.get(token)


@app.route("/")
def index():
    token = request.cookies.get("auth_token")
    session = get_session(token) if token else None
    
    if session:
        return f"""
        <html>
        <head><title>DevPay - Employee Portal</title></head>
        <body>
            <h1>DevPay Employee Portal</h1>
            <p>Welcome back, <strong>{session['username']}</strong>!</p>
            <p>Role: {session['role']}</p>
            <hr>
            <h3>Quick Actions:</h3>
            <ul>
                <li><a href="transfer">Transfer Funds</a></li>
                <li><a href="admin">Admin Panel</a></li>
                <li><a href="logout">Secure Logout</a></li>
            </ul>
            <hr>
            <p style="color:green"><em>✓ Your session is secured with military-grade encryption</em></p>
        </body>
        </html>
        """
    
    return """
    <html>
    <head><title>DevPay - Employee Portal</title></head>
    <body>
        <h1>DevPay Employee Portal</h1>
        <p>Welcome to the DevPay secure employee payment system.</p>
        <p><a href="login">Login to your account</a></p>
        <hr>
        <p><em>Test accounts: developer/dev2026!, tester/test123, manager/manage456</em></p>
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
            resp = make_response(redirect("."))
            resp.set_cookie("auth_token", token)
            # Clear logout verification on new login - forces replay attack
            resp.set_cookie("logout_verified", "", expires=0)
            return resp
        else:
            error = "Invalid username or password"
    
    return f"""
    <html>
    <head><title>Login - DevPay</title></head>
    <body>
        <h1>DevPay Secure Login</h1>
        {"<p style='color:red'>" + error + "</p>" if error else ""}
        <form method="POST">
            <p>Username: <input type="text" name="username" autocomplete="off"></p>
            <p>Password: <input type="password" name="password"></p>
            <p><input type="submit" value="Secure Login"></p>
        </form>
        <hr>
        <p><a href=".">Back to Home</a></p>
    </body>
    </html>
    """


@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    token = request.cookies.get("auth_token")
    session = get_session(token) if token else None
    
    if not session:
        return redirect("login")
    
    message = None
    if request.method == "POST":
        message = "Transfer functionality disabled in demo mode."
    
    return f"""
    <html>
    <head><title>Transfer Funds - DevPay</title></head>
    <body>
        <h1>Transfer Funds</h1>
        <p>Logged in as: {session['username']}</p>
        {"<p style='color:blue'>" + message + "</p>" if message else ""}
        <form method="POST">
            <p>Recipient: <input type="text" name="recipient"></p>
            <p>Amount: $<input type="number" name="amount"></p>
            <p><input type="submit" value="Transfer"></p>
        </form>
        <hr>
        <p><a href=".">Back to Home</a></p>
    </body>
    </html>
    """


@app.route("/admin")
def admin():
    token = request.cookies.get("auth_token")
    session = get_session(token) if token else None
    logout_verified = request.cookies.get("logout_verified")
    
    if not session:
        return redirect("login")
    
    if session["role"] != "manager":
        return """
        <html>
        <head><title>Access Denied - DevPay</title></head>
        <body>
            <h1>Access Denied</h1>
            <p>This area is restricted to managers only.</p>
            <p>Your role: """ + session["role"] + """</p>
            <hr>
            <p><a href=".">Back to Home</a></p>
        </body>
        </html>
        """
    
    # Check if logout verification is complete
    if logout_verified != "true":
        return f"""
        <html>
        <head><title>Verification Required - DevPay</title></head>
        <body>
            <h1>Manager Admin Panel</h1>
            <p>Welcome, {session['username']}!</p>
            
            <div style="background:#fff3cd;padding:20px;border:2px solid #ffc107;">
                <h2>⚠️ Security Verification Required</h2>
                <p>Due to enhanced security policies, you must complete a 
                <strong>logout verification cycle</strong> before accessing sensitive data.</p>
                <p>This confirms your session has proper security controls.</p>
                <p><strong>Please <a href="logout">logout</a> and log back in to verify your session.</strong></p>
            </div>
            
            <hr>
            <h3>Non-Sensitive Information:</h3>
            <p>Active sessions: {len(ACTIVE_SESSIONS)}</p>
            <p>Your session token (first 16 chars): <code>{token[:16]}...</code></p>
            
            <hr>
            <p><a href=".">Back to Home</a></p>
        </body>
        </html>
        """
    
    # Both valid session AND logout_verified cookie present - show flag
    return f"""
    <html>
    <head><title>Admin Panel - DevPay</title></head>
    <body>
        <h1>Manager Admin Panel</h1>
        <p>Welcome, {session['username']}!</p>
        <p style="color:green">✓ Session verification complete</p>
        
        <h2>System Status</h2>
        <p>Active sessions: {len(ACTIVE_SESSIONS)}</p>
        
        <div style="background:#efe;padding:20px;border:2px solid green;">
            <h2>Payroll Master Key:</h2>
            <code>{FLAG}</code>
        </div>
        
        <hr>
        <p><a href=".">Back to Home</a></p>
    </body>
    </html>
    """


@app.route("/logout")
def logout():
    """
    VULNERABILITY: Only deletes client-side cookie!
    Server-side session is NOT invalidated.
    
    Sets logout_verified cookie to "true" - this is the trap.
    Student needs to:
    1. Have captured auth_token before clicking this
    2. After logout, manually restore auth_token cookie
    3. Now they have both auth_token AND logout_verified
    """
    
    resp = make_response("""
    <html>
    <head><title>Logged Out - DevPay</title></head>
    <body>
        <h1>Securely Logged Out</h1>
        <p style="color:green">✓ Your session has been terminated.</p>
        <p style="color:green">✓ All session data has been cleared.</p>
        <p style="color:green">✓ Logout verification recorded.</p>
        <p style="color:green">✓ You have been safely logged out.</p>
        <hr>
        <p>You may now <a href="login">log back in</a> with full access.</p>
        <p><a href=".">Return to Home</a></p>
    </body>
    </html>
    """)
    
    # Set verification cookie
    resp.set_cookie("logout_verified", "true")
    
    # Delete auth cookie (but NOT the server-side session!)
    # BUG: Should also do: del ACTIVE_SESSIONS[token]
    resp.delete_cookie("auth_token")
    
    return resp


@app.route("/debug/sessions")
def debug_sessions():
    """Shows active session count - hints that sessions persist after logout"""
    token = request.cookies.get("auth_token")
    logout_verified = request.cookies.get("logout_verified")
    
    return f"""
    <html>
    <head><title>Debug Info</title></head>
    <body>
        <h1>Debug Information</h1>
        <p>Active server-side sessions: <strong>{len(ACTIVE_SESSIONS)}</strong></p>
        <p>Your auth_token cookie: <strong>{"Present" if token else "Not present"}</strong></p>
        <p>Your logout_verified cookie: <strong>{logout_verified if logout_verified else "Not present"}</strong></p>
        <p><em>Note: This endpoint is for development purposes only.</em></p>
        <hr>
        <p><a href=".">Back to Home</a></p>
    </body>
    </html>
    """


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
