import logging
import os
import re
import secrets
import sqlite3
import time
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from db import get_db_connection, init_db
from notes import (
    create_folder,
    create_note,
    delete_folder,
    delete_note,
    get_folder_by_id,
    get_note_by_id,
    get_user_folders,
    get_user_notes,
    update_note,
)

app = Flask(__name__)

# Security configuration for session cookies
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-shield-secret-key-change-me")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Configure security audit logging (never logs passwords or note content)
LOG_PATH = os.path.join(os.path.dirname(__file__), "security.log")
security_logger = logging.getLogger("shield_security")
security_logger.setLevel(logging.INFO)
security_logger.propagate = False
if not security_logger.handlers:
    file_handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    security_logger.addHandler(file_handler)

# Simple in-memory rate limiter for brute-force login protection
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_WINDOW_SECONDS = 120
FAILED_LOGIN_ATTEMPTS = {}

# Initialize database tables on startup
init_db()


# --- Security Hooks (CSRF & HTTP Security Headers) ---

@app.before_request
def enforce_csrf_protection():
    """Generate a per-session CSRF token and validate it on all POST requests."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    if request.method == "POST":
        sent_token = request.form.get("csrf_token", "")
        expected_token = session.get("csrf_token", "")
        if not sent_token or not secrets.compare_digest(sent_token, expected_token):
            security_logger.warning(
                "CSRF_REJECTED path=%s ip=%s",
                request.path,
                request.remote_addr,
            )
            abort(403)


@app.context_processor
def inject_csrf_token():
    """Make csrf_token available automatically inside all Jinja2 templates."""
    return {"csrf_token": session.get("csrf_token", "")}


@app.after_request
def apply_security_headers(response):
    """Apply standard HTTP security headers on all secured routes."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"

    # Apply strict CSP on secured pages, but skip on /vulnerable so the XSS demo can execute
    if request.endpoint != "vulnerable_demo":
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self';"
        )
    return response


# --- Helper Functions ---

def login_required(view_func):
    """Decorator to ensure only authenticated users can access protected routes."""
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to access your notes.", "danger")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped_view


def is_rate_limited(client_ip, username):
    """Check if the client IP and username have exceeded the failed login threshold."""
    key = (client_ip, username.lower())
    now = time.time()
    recent = [t for t in FAILED_LOGIN_ATTEMPTS.get(key, []) if now - t < LOCKOUT_WINDOW_SECONDS]
    FAILED_LOGIN_ATTEMPTS[key] = recent
    return len(recent) >= MAX_FAILED_ATTEMPTS


def record_failed_login(client_ip, username):
    """Record a failed login timestamp for brute-force tracking."""
    key = (client_ip, username.lower())
    FAILED_LOGIN_ATTEMPTS.setdefault(key, []).append(time.time())


def clear_failed_logins(client_ip, username):
    """Clear failed login tracking after a successful authentication."""
    key = (client_ip, username.lower())
    FAILED_LOGIN_ATTEMPTS.pop(key, None)


# --- Authentication Routes ---

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("notes_dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Server-side input validation
        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("register.html")

        if not re.fullmatch(r"[A-Za-z0-9_]{3,50}", username):
            flash("Username must be 3-50 characters (letters, numbers, underscores only).", "danger")
            return render_template("register.html")

        if len(password) < 6 or len(password) > 100:
            flash("Password must be between 6 and 100 characters.", "danger")
            return render_template("register.html")

        # Hash password with scrypt before storing
        hashed_password = generate_password_hash(password, method="scrypt")

        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password),
            )
            conn.commit()
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists. Please choose another one.", "danger")
        finally:
            conn.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        client_ip = request.remote_addr

        if not username or not password:
            flash("Please enter both username and password.", "danger")
            return render_template("login.html")

        # Enforce brute-force rate limiting
        if is_rate_limited(client_ip, username):
            security_logger.warning(
                "RATE_LIMIT_EXCEEDED user=%s ip=%s",
                username,
                client_ip,
            )
            flash("Too many failed login attempts. Please wait 2 minutes and try again.", "danger")
            return render_template("login.html"), 429

        conn = get_db_connection()
        user = conn.execute(
            "SELECT user_id, username, password FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            clear_failed_logins(client_ip, username)
            csrf_token = secrets.token_hex(32)
            session.clear()
            session["csrf_token"] = csrf_token
            session["user_id"] = user["user_id"]
            session["username"] = user["username"]
            security_logger.info(
                "LOGIN_SUCCESS user=%s user_id=%s ip=%s",
                user["username"],
                user["user_id"],
                client_ip,
            )
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("notes_dashboard"))

        # Log failed login attempt without logging the password
        record_failed_login(client_ip, username)
        security_logger.warning(
            "LOGIN_FAILED user=%s ip=%s",
            username,
            client_ip,
        )
        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# --- Notes & Folders Routes (Secured) ---

@app.route("/notes")
@login_required
def notes_dashboard():
    user_id = session["user_id"]
    folder_id = request.args.get("folder_id", type=int)
    search_query = request.args.get("q", "").strip()[:100]

    # Verify folder ownership on the server if a folder filter is requested
    if folder_id is not None:
        folder = get_folder_by_id(folder_id)
        if not folder:
            abort(404)
        if folder["user_id"] != user_id:
            security_logger.warning(
                "ACCESS_DENIED action=view_folder by_user=%s folder_id=%s owner=%s ip=%s",
                user_id,
                folder_id,
                folder["user_id"],
                request.remote_addr,
            )
            return render_template("access_denied.html"), 403

    folders = get_user_folders(user_id)
    notes = get_user_notes(user_id, folder_id=folder_id, search_query=search_query or None)

    return render_template(
        "notes.html",
        folders=folders,
        notes=notes,
        active_folder_id=folder_id,
        search_query=search_query,
    )


@app.route("/folders/add", methods=["POST"])
@login_required
def add_folder():
    user_id = session["user_id"]
    name = request.form.get("name", "").strip()

    if not name or len(name) > 40:
        flash("Folder name is required and must be 40 characters or fewer.", "danger")
        return redirect(url_for("notes_dashboard"))

    create_folder(user_id, name)
    flash("Folder created.", "success")
    return redirect(url_for("notes_dashboard"))


@app.route("/folders/<int:folder_id>/delete", methods=["POST"])
@login_required
def remove_folder(folder_id):
    user_id = session["user_id"]
    folder = get_folder_by_id(folder_id)

    if not folder:
        abort(404)

    if folder["user_id"] != user_id:
        security_logger.warning(
            "ACCESS_DENIED action=delete_folder by_user=%s folder_id=%s owner=%s ip=%s",
            user_id,
            folder_id,
            folder["user_id"],
            request.remote_addr,
        )
        return render_template("access_denied.html"), 403

    delete_folder(folder_id, user_id)
    flash("Folder deleted.", "info")
    return redirect(url_for("notes_dashboard"))


@app.route("/notes/add", methods=["POST"])
@login_required
def add_note():
    user_id = session["user_id"]
    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()
    folder_id = request.form.get("folder_id", type=int)

    # Server-side input validation for required fields and length limits
    if not title or not content:
        flash("Note title and content are both required.", "danger")
        return redirect(url_for("notes_dashboard"))

    if len(title) > 100:
        flash("Note title must be 100 characters or fewer.", "danger")
        return redirect(url_for("notes_dashboard"))

    if len(content) > 2000:
        flash("Note content must be 2000 characters or fewer.", "danger")
        return redirect(url_for("notes_dashboard"))

    # Verify folder ownership if a folder was selected
    if folder_id is not None:
        folder = get_folder_by_id(folder_id)
        if not folder or folder["user_id"] != user_id:
            security_logger.warning(
                "ACCESS_DENIED action=assign_folder by_user=%s folder_id=%s ip=%s",
                user_id,
                folder_id,
                request.remote_addr,
            )
            return render_template("access_denied.html"), 403

    create_note(user_id, title, content, folder_id=folder_id)
    flash("Note saved securely.", "success")
    return redirect(url_for("notes_dashboard", folder_id=folder_id) if folder_id else url_for("notes_dashboard"))


@app.route("/notes/<int:note_id>")
@login_required
def view_note(note_id):
    user_id = session["user_id"]
    note = get_note_by_id(note_id)

    if not note:
        abort(404)

    # Server-side ownership check
    if note["user_id"] != user_id:
        security_logger.warning(
            "ACCESS_DENIED action=view_note by_user=%s note_id=%s owner=%s ip=%s",
            user_id,
            note_id,
            note["user_id"],
            request.remote_addr,
        )
        return render_template("access_denied.html"), 403

    return render_template("view_note.html", note=note)


@app.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
@login_required
def edit_note(note_id):
    user_id = session["user_id"]
    note = get_note_by_id(note_id)

    if not note:
        abort(404)

    # Server-side ownership check before viewing or editing
    if note["user_id"] != user_id:
        security_logger.warning(
            "ACCESS_DENIED action=edit_note by_user=%s note_id=%s owner=%s ip=%s",
            user_id,
            note_id,
            note["user_id"],
            request.remote_addr,
        )
        return render_template("access_denied.html"), 403

    folders = get_user_folders(user_id)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        folder_id = request.form.get("folder_id", type=int)

        if not title or not content:
            flash("Note title and content are both required.", "danger")
            return render_template("edit_note.html", note=note, folders=folders)

        if len(title) > 100 or len(content) > 2000:
            flash("Title (max 100) or content (max 2000) exceeded length limit.", "danger")
            return render_template("edit_note.html", note=note, folders=folders)

        if folder_id is not None:
            folder = get_folder_by_id(folder_id)
            if not folder or folder["user_id"] != user_id:
                security_logger.warning(
                    "ACCESS_DENIED action=assign_folder by_user=%s folder_id=%s ip=%s",
                    user_id,
                    folder_id,
                    request.remote_addr,
                )
                return render_template("access_denied.html"), 403

        update_note(note_id, user_id, title, content, folder_id=folder_id)
        flash("Note updated securely.", "success")
        return redirect(url_for("view_note", note_id=note_id))

    return render_template("edit_note.html", note=note, folders=folders)


@app.route("/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def remove_note(note_id):
    user_id = session["user_id"]
    note = get_note_by_id(note_id)

    if not note:
        abort(404)

    # Server-side ownership check before deletion
    if note["user_id"] != user_id:
        security_logger.warning(
            "ACCESS_DENIED action=delete_note by_user=%s note_id=%s owner=%s ip=%s",
            user_id,
            note_id,
            note["user_id"],
            request.remote_addr,
        )
        return render_template("access_denied.html"), 403

    delete_note(note_id, user_id)
    flash("Note deleted.", "info")
    return redirect(url_for("notes_dashboard"))


# --- Deliberately Vulnerable Local Demo (Stored XSS Demonstration) ---

@app.route("/vulnerable")
@login_required
def vulnerable_demo():
    """
    Deliberately vulnerable local endpoint for CS471 Stored XSS demonstration.
    Renders stored notes without output encoding using Jinja2's |safe filter.
    """
    user_id = session["user_id"]
    notes = get_user_notes(user_id)
    return render_template("vulnerable.html", notes=notes)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)