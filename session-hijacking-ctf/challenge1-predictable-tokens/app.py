"""
Challenge 1: Predictable Tokens
Difficulty: Easy (10-15 min)
Vulnerability: Weak/predictable session token generation (CWE-330)

The server generates session tokens by base64-encoding "user_<user_id>".
Students must recognize the pattern and forge an admin token.

Trust boundary failure: Server trusts that only it can generate valid tokens,
but the generation algorithm is trivially reversible.
"""

from flask import Flask, request, make_response, redirect, url_for
import base64
import os

app = Flask(__name__)

# Simulated user database
USERS = {
    "guest": {"id": 1001, "password": "guest123", "role": "user"},
    "alice": {"id": 1002, "password": "alice456", "role": "user"},
    "bob": {"id": 1003, "password": "bob789", "role": "user"},
    # Admin exists but students don't know credentials
    "admin": {"id": 1000, "password": os.environ.get("ADMIN_PASS", "REDACTED"), "role": "admin"},
}

FLAG = os.environ.get("FLAG", "flag{test_flag_not_real}")


def generate_token(user_id):
    """
    VULNERABILITY: Predictable token generation
    Token is just base64("user_<id>") - trivially reversible
    """
    token_data = f"user_{user_id}"
    return base64.b64encode(token_data.encode()).decode()


def validate_token(token):
    """Decode token and return user_id if valid"""
    try:
        decoded = base64.b64decode(token).decode()
        if decoded.startswith("user_"):
            user_id = int(decoded.split("_")[1])
            # Find user by ID
            for username, data in USERS.items():
                if data["id"] == user_id:
                    return username, data
        return None, None
    except Exception:
        return None, None


@app.route("/")
def index():
    token = request.cookies.get("session_token")
    if token:
        username, user_data = validate_token(token)
        if username:
            return f"""
            <html>
            <head><title>SecureBank Portal</title></head>
            <body>
                <h1>Welcome to SecureBank</h1>
                <p>Logged in as: <strong>{username}</strong></p>
                <p>Role: {user_data['role']}</p>
                <p>Account ID: {user_data['id']}</p>
                <hr>
                <p><a href="/dashboard">View Dashboard</a></p>
                <p><a href="/logout">Logout</a></p>
            </body>
            </html>
            """
    
    return """
    <html>
    <head><title>SecureBank Portal</title></head>
    <body>
        <h1>Welcome to SecureBank</h1>
        <p>Please <a href="/login">login</a> to continue.</p>
        <hr>
        <p><em>Test accounts available: guest/guest123, alice/alice456, bob/bob789</em></p>
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
            token = generate_token(USERS[username]["id"])
            resp = make_response(redirect(url_for("index")))
            resp.set_cookie("session_token", token)
            return resp
        else:
            error = "Invalid credentials"
    
    return f"""
    <html>
    <head><title>Login - SecureBank</title></head>
    <body>
        <h1>SecureBank Login</h1>
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


@app.route("/dashboard")
def dashboard():
    token = request.cookies.get("session_token")
    if not token:
        return redirect(url_for("login"))
    
    username, user_data = validate_token(token)
    if not username:
        return redirect(url_for("login"))
    
    # Only admin can see the flag
    if user_data["role"] == "admin":
        return f"""
        <html>
        <head><title>Admin Dashboard - SecureBank</title></head>
        <body>
            <h1>Admin Dashboard</h1>
            <p>Welcome, Administrator!</p>
            <div style="background:#efe;padding:20px;border:2px solid green;">
                <h2>System Secret:</h2>
                <code>{FLAG}</code>
            </div>
            <hr>
            <p><a href="/">Back to Home</a></p>
        </body>
        </html>
        """
    else:
        return f"""
        <html>
        <head><title>Dashboard - SecureBank</title></head>
        <body>
            <h1>User Dashboard</h1>
            <p>Welcome, {username}!</p>
            <p>Your account balance: $1,234.56</p>
            <p style="color:gray"><em>Admin features are restricted.</em></p>
            <hr>
            <p><a href="/">Back to Home</a></p>
        </body>
        </html>
        """


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("session_token")
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
