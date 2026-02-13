"""
Guardian SIEM v2.0 — Dashboard Authentication
Flask middleware providing user login, session management, and role-based
access control for the SOC dashboard.
  - bcrypt password hashing
  - Session-based authentication
  - API key support for programmatic access
  - Role system: admin, analyst, viewer
  - SQLite user store
"""

import os
import sqlite3
import secrets
import hashlib
import hmac
import time
import yaml
import functools
from datetime import datetime

from flask import request, redirect, url_for, session, jsonify, render_template_string

try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False


# ---- User Database ----

class UserDB:
    """SQLite-based user store with bcrypt password hashing."""

    def __init__(self, db_path=None):
        if db_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(base_dir, "database", "guardian_users.db")
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'viewer',
            api_key TEXT UNIQUE,
            created_at TEXT,
            last_login TEXT,
            enabled INTEGER DEFAULT 1
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_apikey ON users(api_key)")
        conn.commit()

        # Create default admin user if no users exist
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            self._create_default_admin(conn)
        conn.close()

    def _create_default_admin(self, conn):
        """Create a default admin account on first run."""
        password = "guardian-admin"  # Must be changed on first login
        pw_hash = self._hash_password(password)
        api_key = secrets.token_hex(32)

        conn.execute(
            "INSERT INTO users (username, password_hash, role, api_key, created_at) VALUES (?, ?, ?, ?, ?)",
            ("admin", pw_hash, "admin", api_key, datetime.now().isoformat())
        )
        conn.commit()
        print(f"[Auth] Default admin created — username: admin  password: guardian-admin")
        print(f"[Auth] ⚠️  CHANGE THE DEFAULT PASSWORD IMMEDIATELY")
        print(f"[Auth] API Key: {api_key}")

    def authenticate(self, username, password):
        """Verify username/password. Returns user dict or None."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? AND enabled = 1", (username,)
        ).fetchone()
        conn.close()

        if row is None:
            return None

        if self._verify_password(password, row["password_hash"]):
            # Update last login
            self._update_last_login(username)
            return {
                "id": row["id"],
                "username": row["username"],
                "role": row["role"],
                "api_key": row["api_key"],
            }
        return None

    def authenticate_api_key(self, api_key):
        """Verify API key. Returns user dict or None."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM users WHERE api_key = ? AND enabled = 1", (api_key,)
        ).fetchone()
        conn.close()

        if row:
            return {
                "id": row["id"],
                "username": row["username"],
                "role": row["role"],
            }
        return None

    def create_user(self, username, password, role="viewer"):
        """Create a new user account."""
        pw_hash = self._hash_password(password)
        api_key = secrets.token_hex(32)
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, api_key, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, pw_hash, role, api_key, datetime.now().isoformat())
            )
            conn.commit()
            return {"username": username, "role": role, "api_key": api_key}
        except sqlite3.IntegrityError:
            return None
        finally:
            conn.close()

    def change_password(self, username, new_password):
        """Change a user's password."""
        pw_hash = self._hash_password(new_password)
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE users SET password_hash = ? WHERE username = ?", (pw_hash, username))
        conn.commit()
        conn.close()

    def list_users(self):
        """Return all users (without password hashes)."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT id, username, role, created_at, last_login, enabled FROM users").fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def delete_user(self, username):
        """Delete a user account."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        conn.close()

    def _update_last_login(self, username):
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE users SET last_login = ? WHERE username = ?",
                     (datetime.now().isoformat(), username))
        conn.commit()
        conn.close()

    @staticmethod
    def _hash_password(password):
        """Hash a password with bcrypt (or SHA-256 fallback)."""
        if HAS_BCRYPT:
            return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        else:
            salt = secrets.token_hex(16)
            h = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
            return f"sha256:{salt}:{h}"

    @staticmethod
    def _verify_password(password, pw_hash):
        """Verify a password against its hash."""
        if HAS_BCRYPT and pw_hash.startswith("$2"):
            return bcrypt.checkpw(password.encode(), pw_hash.encode())
        elif pw_hash.startswith("sha256:"):
            parts = pw_hash.split(":")
            if len(parts) == 3:
                salt, stored = parts[1], parts[2]
                computed = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
                return hmac.compare_digest(computed, stored)
        return False


# ---- Flask Auth Middleware ----

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Guardian SIEM — Login</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0a0e17;
    color: #e0e0e0;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
  }
  .login-box {
    background: #111827;
    border: 1px solid #1e293b;
    border-radius: 12px;
    padding: 40px;
    width: 380px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
  }
  .login-box h1 {
    font-size: 1.5em;
    margin-bottom: 8px;
    color: #00e5ff;
  }
  .login-box p.subtitle {
    color: #6b7280;
    font-size: 0.9em;
    margin-bottom: 24px;
  }
  .form-group {
    margin-bottom: 16px;
  }
  .form-group label {
    display: block;
    margin-bottom: 6px;
    font-size: 0.85em;
    color: #9ca3af;
  }
  .form-group input {
    width: 100%;
    padding: 10px 14px;
    background: #1e293b;
    border: 1px solid #374151;
    border-radius: 6px;
    color: #e0e0e0;
    font-size: 0.95em;
    outline: none;
    transition: border-color 0.2s;
  }
  .form-group input:focus {
    border-color: #00e5ff;
  }
  .btn {
    width: 100%;
    padding: 12px;
    background: #00e5ff;
    color: #0a0e17;
    border: none;
    border-radius: 6px;
    font-weight: 600;
    font-size: 1em;
    cursor: pointer;
    margin-top: 8px;
    transition: background 0.2s;
  }
  .btn:hover { background: #00b8d4; }
  .error {
    background: rgba(255,0,0,0.1);
    border: 1px solid #ff4444;
    color: #ff6666;
    padding: 10px;
    border-radius: 6px;
    margin-bottom: 16px;
    font-size: 0.85em;
  }
  .shield { font-size: 2em; margin-bottom: 12px; }
</style>
</head>
<body>
<div class="login-box">
  <div class="shield">🛡️</div>
  <h1>Guardian SIEM</h1>
  <p class="subtitle">Security Operations Center — Authenticate</p>
  {% if error %}
  <div class="error">{{ error }}</div>
  {% endif %}
  <form method="POST" action="/login">
    <div class="form-group">
      <label>Username</label>
      <input type="text" name="username" autocomplete="username" required autofocus>
    </div>
    <div class="form-group">
      <label>Password</label>
      <input type="password" name="password" autocomplete="current-password" required>
    </div>
    <button type="submit" class="btn">Sign In</button>
  </form>
</div>
</body>
</html>"""


def setup_auth(app, config=None):
    """
    Initialize authentication on a Flask app.

    Args:
        app: Flask app instance
        config: Config dict with auth settings

    Returns:
        UserDB instance
    """
    if config is None:
        config = {}

    auth_config = config.get("auth", {})
    enabled = auth_config.get("enabled", True)

    user_db = UserDB()

    if not enabled:
        # Auth disabled — all routes are public
        app.config["AUTH_ENABLED"] = False
        return user_db

    app.config["AUTH_ENABLED"] = True

    # Public routes that don't require auth
    public_routes = {"/login", "/api/health"}

    @app.before_request
    def require_auth():
        if not app.config.get("AUTH_ENABLED", True):
            return None

        # Skip auth for public routes
        if request.path in public_routes:
            return None

        # Skip auth for static files
        if request.path.startswith("/static/"):
            return None

        # Check API key in header
        api_key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if api_key:
            user = user_db.authenticate_api_key(api_key)
            if user:
                request.current_user = user
                return None
            return jsonify({"error": "Invalid API key"}), 401

        # Check session
        if session.get("authenticated"):
            request.current_user = {
                "username": session.get("username"),
                "role": session.get("role"),
            }
            return None

        # Not authenticated — redirect to login for browser, 401 for API
        if request.path.startswith("/api/"):
            return jsonify({"error": "Authentication required"}), 401

        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            user = user_db.authenticate(username, password)
            if user:
                session["authenticated"] = True
                session["username"] = user["username"]
                session["role"] = user["role"]
                session.permanent = True
                return redirect("/")
            error = "Invalid username or password"
        return render_template_string(LOGIN_HTML, error=error)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect("/login")

    # Admin API: manage users
    @app.route("/api/auth/users", methods=["GET"])
    def list_users():
        if not _is_admin():
            return jsonify({"error": "Admin required"}), 403
        return jsonify(user_db.list_users())

    @app.route("/api/auth/users", methods=["POST"])
    def create_user():
        if not _is_admin():
            return jsonify({"error": "Admin required"}), 403
        data = request.get_json()
        if not data or not data.get("username") or not data.get("password"):
            return jsonify({"error": "username and password required"}), 400
        result = user_db.create_user(
            data["username"],
            data["password"],
            data.get("role", "viewer")
        )
        if result:
            return jsonify(result), 201
        return jsonify({"error": "User already exists"}), 409

    @app.route("/api/auth/password", methods=["POST"])
    def change_password():
        data = request.get_json()
        if not data or not data.get("new_password"):
            return jsonify({"error": "new_password required"}), 400
        username = getattr(request, "current_user", {}).get("username", "")
        if not username:
            username = session.get("username", "")
        if username:
            user_db.change_password(username, data["new_password"])
            return jsonify({"status": "password_changed"})
        return jsonify({"error": "Not authenticated"}), 401

    def _is_admin():
        user = getattr(request, "current_user", None)
        if user and user.get("role") == "admin":
            return True
        return session.get("role") == "admin"

    return user_db


def require_role(role):
    """Decorator to restrict a route to a specific role."""
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            user = getattr(request, "current_user", None)
            user_role = user.get("role", "") if user else session.get("role", "")

            role_hierarchy = {"admin": 3, "analyst": 2, "viewer": 1}
            if role_hierarchy.get(user_role, 0) < role_hierarchy.get(role, 0):
                return jsonify({"error": f"Role '{role}' or higher required"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator
