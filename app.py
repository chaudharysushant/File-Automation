import os
import hashlib
import re
import secrets
import smtplib
import ssl
import sys
import threading
from collections import deque
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
import psycopg2
from psycopg2 import sql
from werkzeug.security import check_password_hash, generate_password_hash

import main


app = Flask(__name__)

PASSWORD_RESET_TTL = timedelta(minutes=30)
MIN_PASSWORD_LENGTH = 6
MAX_PASSWORD_LENGTH = 128

# Used to keep the login timing similar whether or not the username exists.
_DUMMY_PASSWORD_HASH = generate_password_hash("dashboard-placeholder-password")


def get_dashboard_secret_key():
    configured = (os.getenv("DASHBOARD_SECRET_KEY") or "").strip()
    if configured:
        return configured

    secret_file = os.getenv("DASHBOARD_SECRET_KEY_FILE")
    if not secret_file:
        secret_file = str(Path(__file__).resolve().with_name(".dashboard_secret_key"))
    path = Path(secret_file)
    if path.exists():
        stored = path.read_text(encoding="utf-8").strip()
        if stored:
            return stored

    generated = secrets.token_urlsafe(32)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(generated, encoding="utf-8")
        os.chmod(path, 0o600)
    except OSError:
        return generated
    return generated


app.secret_key = get_dashboard_secret_key()
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("DASHBOARD_COOKIE_SECURE", "false").lower()
    in {"1", "true", "yes"},
)
_state_lock = threading.Lock()
_run_lock = threading.Lock()
_logs = deque(maxlen=500)
_next_log_id = 1
_console = sys.stdout
_login_attempts = {}
_login_attempts_lock = threading.Lock()
_state = {
    "running": False,
    "run_pending": False,
    "last_started": None,
    "last_finished": None,
    "last_error": None,
}


def schema():
    return os.getenv("PG_SCHEMA", "public")


def normalize_email(email):
    return (email or "").strip().lower()


def valid_email(email):
    return len(email) <= 254 and re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) is not None


def get_routes():
    conn = psycopg2.connect(**main.get_db_config())
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                sql.SQL("""
                    SELECT client_id, source, destination, filename_regex, enabled
                    FROM {}.file_route
                    ORDER BY client_id, source, destination
                """).format(sql.Identifier(schema()))
            )
            return [
                {"client_id": row[0], "source": row[1], "destination": row[2],
                 "filename_regex": row[3], "enabled": row[4]}
                for row in cursor.fetchall()
            ]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Account storage
# ---------------------------------------------------------------------------

def get_account_by_username(username):
    conn = psycopg2.connect(**main.get_db_config())
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                sql.SQL("""
                    SELECT account_id, username, email, password_hash
                    FROM {}.dashboard_account
                    WHERE LOWER(username) = LOWER(%s)
                """).format(sql.Identifier(schema())),
                (username,),
            )
            return cursor.fetchone()
    finally:
        conn.close()


def get_account_by_email(email):
    conn = psycopg2.connect(**main.get_db_config())
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                sql.SQL("""
                    SELECT account_id, username, email, password_hash
                    FROM {}.dashboard_account
                    WHERE email IS NOT NULL AND LOWER(email) = %s
                """).format(sql.Identifier(schema())),
                (email,),
            )
            return cursor.fetchone()
    finally:
        conn.close()


def create_account(username, email, password_hash):
    conn = psycopg2.connect(**main.get_db_config())
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    sql.SQL("""
                        INSERT INTO {}.dashboard_account (username, email, password_hash)
                        VALUES (%s, %s, %s)
                        RETURNING account_id
                    """).format(sql.Identifier(schema())),
                    (username, email, password_hash),
                )
                return cursor.fetchone() is not None
    except psycopg2.errors.UniqueViolation:
        return False
    finally:
        conn.close()


def save_password_reset(email, token_hash):
    conn = psycopg2.connect(**main.get_db_config())
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    sql.SQL("""
                        UPDATE {}.dashboard_account
                        SET reset_token_hash = %s,
                            reset_expires_at = CURRENT_TIMESTAMP + INTERVAL '30 minutes'
                        WHERE email IS NOT NULL AND LOWER(email) = %s
                        RETURNING account_id
                    """).format(sql.Identifier(schema())),
                    (token_hash, email),
                )
                return cursor.fetchone() is not None
    finally:
        conn.close()


def clear_password_reset(token_hash):
    conn = psycopg2.connect(**main.get_db_config())
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    sql.SQL("""
                        UPDATE {}.dashboard_account
                        SET reset_token_hash = NULL, reset_expires_at = NULL
                        WHERE reset_token_hash = %s
                    """).format(sql.Identifier(schema())),
                    (token_hash,),
                )
    finally:
        conn.close()


def password_reset_account(token_hash):
    conn = psycopg2.connect(**main.get_db_config())
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                sql.SQL("""
                    SELECT account_id
                    FROM {}.dashboard_account
                    WHERE reset_token_hash = %s
                      AND reset_expires_at > CURRENT_TIMESTAMP
                """).format(sql.Identifier(schema())),
                (token_hash,),
            )
            row = cursor.fetchone()
            return row[0] if row else None
    finally:
        conn.close()


def update_password_from_reset(token_hash, password_hash):
    conn = psycopg2.connect(**main.get_db_config())
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    sql.SQL("""
                        UPDATE {}.dashboard_account
                        SET password_hash = %s,
                            reset_token_hash = NULL,
                            reset_expires_at = NULL
                        WHERE reset_token_hash = %s
                          AND reset_expires_at > CURRENT_TIMESTAMP
                        RETURNING account_id
                    """).format(sql.Identifier(schema())),
                    (password_hash, token_hash),
                )
                return cursor.fetchone() is not None
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Password reset tokens
# ---------------------------------------------------------------------------

def token_digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

def smtp_configured():
    return bool(os.getenv("DASHBOARD_SMTP_HOST") and os.getenv("DASHBOARD_SMTP_FROM"))


def password_reset_mail_configured():
    return smtp_configured() and bool(os.getenv("DASHBOARD_PUBLIC_URL"))


def send_email(recipient, subject, body):
    host = (os.getenv("DASHBOARD_SMTP_HOST") or "").strip()
    sender = (os.getenv("DASHBOARD_SMTP_FROM") or "").strip()
    if not host or not sender:
        raise RuntimeError("SMTP is not configured")

    port = int(os.getenv("DASHBOARD_SMTP_PORT", "587"))
    username = os.getenv("DASHBOARD_SMTP_USERNAME", "")
    password = os.getenv("DASHBOARD_SMTP_PASSWORD", "")
    use_ssl = os.getenv("DASHBOARD_SMTP_USE_SSL", "false").lower() in {"1", "true", "yes"}

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = recipient
    message.set_content(body)

    if use_ssl:
        with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=15) as server:
            if username and password:
                server.login(username, password)
            server.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.ehlo()
            server.starttls(context=ssl.create_default_context())
            if username and password:
                server.login(username, password)
            server.send_message(message)


def send_password_reset_email(token, recipient):
    public_url = (os.getenv("DASHBOARD_PUBLIC_URL") or "").rstrip("/")
    reset_url = f"{public_url}{url_for('reset_password', token=token)}"
    send_email(
        recipient,
        "Reset your SFTP dashboard password",
        "A password reset was requested for the SFTP dashboard.\n\n"
        f"Use this one-time link within {int(PASSWORD_RESET_TTL.total_seconds() // 60)} minutes:\n"
        f"{reset_url}\n\n"
        "If you did not request this, you can ignore this message.",
    )


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------

def get_csrf_token():
    return session.setdefault("csrf_token", secrets.token_urlsafe(32))


def valid_csrf_token():
    expected = session.get("csrf_token", "")
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    return bool(expected and supplied and secrets.compare_digest(expected, supplied))


def login_is_throttled(address):
    now = datetime.now(timezone.utc)
    with _login_attempts_lock:
        attempts = [when for when in _login_attempts.get(address, []) if now - when < timedelta(minutes=5)]
        _login_attempts[address] = attempts
        return len(attempts) >= 10


def record_login_failure(address):
    now = datetime.now(timezone.utc)
    with _login_attempts_lock:
        attempts = [when for when in _login_attempts.get(address, []) if now - when < timedelta(minutes=5)]
        attempts.append(now)
        _login_attempts[address] = attempts


def clear_login_failures(address):
    with _login_attempts_lock:
        _login_attempts.pop(address, None)


def record_log(message, level="info", client_id=None):
    global _next_log_id
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _state_lock:
        _logs.append({"id": _next_log_id, "timestamp": timestamp, "level": level,
                  "message": str(message), "client_id": client_id})
        _next_log_id += 1
    _console.write(f"[{timestamp}] {message}\n")
    _console.flush()


class WorkerLogStream:
    def __init__(self):
        self.pending = ""
        self.client_id = None

    def write(self, value):
        self.pending += value
        while "\n" in self.pending:
            line, self.pending = self.pending.split("\n", 1)
            if line:
                self._record(line)
        _console.write(value)
        return len(value)

    def flush(self):
        _console.flush()
        if self.pending:
            self._record(self.pending)
            self.pending = ""

    def _record(self, message):
        global _next_log_id
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with _state_lock:
            _logs.append({"id": _next_log_id, "timestamp": timestamp, "level": "info",
                          "message": message, "client_id": self.client_id})
            _next_log_id += 1


def run_cycle():
    if not _run_lock.acquire(blocking=False):
        return
    with _state_lock:
        _state["running"] = True
        _state["run_pending"] = False
        _state["last_started"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        _state["last_error"] = None
    current_client_id = None
    try:
        log_stream = WorkerLogStream()
        with redirect_stdout(log_stream):
            print("Checking database for active client_ids...")
            for client_id in main.get_client_ids():
                current_client_id = client_id
                log_stream.client_id = client_id
                print(f"Processing client_id: {client_id}")
                main.copy_files(client_id)
            log_stream.flush()
    except Exception as error:
        with _state_lock:
            _state["last_error"] = str(error)
        record_log(f"Worker error: {error}", "error", current_client_id)
    finally:
        with _state_lock:
            _state["running"] = False
            _state["last_finished"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        _run_lock.release()


# ---------------------------------------------------------------------------
# Authentication routes
# ---------------------------------------------------------------------------

@app.before_request
def protect_dashboard():
    if request.endpoint in {"login", "register",
                            "forgot_password", "reset_password"}:
        return None
    if not session.get("authenticated"):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Authentication required"}), 401
        return redirect(url_for("login"))
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not valid_csrf_token():
        return jsonify({"error": "Invalid or missing CSRF token"}), 403


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("authenticated"):
        return redirect(url_for("index"))

    error = None
    status = 200
    token = get_csrf_token()
    if request.method == "POST":
        if not valid_csrf_token():
            error = "Your sign-in form expired. Please try again."
            status = 400
        elif login_is_throttled(request.remote_addr or "unknown"):
            error = "Too many sign-in attempts. Please wait a few minutes and try again."
            status = 429
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            try:
                account = get_account_by_username(username)
            except Exception:
                app.logger.exception("Dashboard account storage is unavailable")
                return "Dashboard account storage is unavailable. Apply create_dashboard_account.sql.", 503
            password_hash = account[3] if account else _DUMMY_PASSWORD_HASH
            valid_password = check_password_hash(password_hash, password)
            if account and valid_password:
                clear_login_failures(request.remote_addr or "unknown")
                session.clear()
                session["authenticated"] = True
                session["account_id"] = account[0]
                session["username"] = account[1]
                session["csrf_token"] = secrets.token_urlsafe(32)
                session.permanent = True
                return redirect(url_for("index"))
            record_login_failure(request.remote_addr or "unknown")
            error = "Username or password is incorrect."
            status = 401

    return render_template(
        "login.html",
        csrf_token=token,
        error=error,
        registered=request.args.get("registered") == "1",
        reset=request.args.get("reset") == "1",
    ), status


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("authenticated"):
        return redirect(url_for("index"))

    error = None
    status = 200
    token = get_csrf_token()
    if request.method == "POST":
        if not valid_csrf_token():
            error = "Your sign-up form expired. Please try again."
            status = 400
        else:
            username = request.form.get("username", "").strip()
            email = normalize_email(request.form.get("email", ""))
            password = request.form.get("password", "")
            confirmation = request.form.get("confirmation", "")
            if len(username) < 3 or len(username) > 64:
                error = "Username must be between 3 and 64 characters."
                status = 400
            elif not valid_email(email):
                error = "Enter a valid email address."
                status = 400
            elif len(password) < MIN_PASSWORD_LENGTH or len(password) > MAX_PASSWORD_LENGTH:
                error = f"Password must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH} characters."
                status = 400
            elif password != confirmation:
                error = "The passwords do not match."
                status = 400
            else:
                try:
                    created = create_account(username, email, generate_password_hash(password))
                except Exception:
                    app.logger.exception("Unable to create the account")
                    error = "Unable to create the account. Check the database and try again."
                    status = 503
                else:
                    if not created:
                        error = "That username or email is already registered. Sign in instead."
                        status = 409
                    else:
                        return redirect(url_for("login", registered="1"))

    return render_template(
        "login.html",
        csrf_token=token,
        error=error,
        register_mode=True,
        registered=False,
        form_username=request.form.get("username", ""),
        form_email=request.form.get("email", ""),
    ), status


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    error = None
    notice = None
    status = 200
    token = get_csrf_token()
    if request.method == "POST":
        if not valid_csrf_token():
            error = "Your form expired. Please try again."
            status = 400
        elif not password_reset_mail_configured():
            error = "Password reset email is not configured. Contact the administrator."
            status = 503
        else:
            email = normalize_email(request.form.get("email", ""))
            if not valid_email(email):
                error = "Enter a valid email address."
                status = 400
            else:
                reset_token = secrets.token_urlsafe(32)
                token_hash = token_digest(reset_token)
                try:
                    if save_password_reset(email, token_hash):
                        try:
                            send_password_reset_email(reset_token, email)
                        except Exception:
                            clear_password_reset(token_hash)
                            app.logger.exception("Password reset email could not be sent")
                            error = "Password reset email could not be sent. Contact the administrator."
                            status = 503
                    if error is None:
                        notice = "If an account exists for that email, a reset link has been sent."
                except Exception:
                    app.logger.exception("Password reset request failed")
                    error = "Password reset is temporarily unavailable. Contact the administrator."
                    status = 503

    return render_template(
        "login.html",
        csrf_token=token,
        error=error,
        notice=notice,
        forgot_mode=True,
        registered=False,
        reset=False,
    ), status


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = token_digest(token)
    try:
        if password_reset_account(token_hash) is None:
            return "This password reset link is invalid or expired.", 400
    except Exception:
        app.logger.exception("Password reset storage is unavailable")
        return "Password reset is temporarily unavailable. Contact the administrator.", 503

    error = None
    status = 200
    csrf_token = get_csrf_token()
    if request.method == "POST":
        if not valid_csrf_token():
            error = "Your reset form expired. Please try again."
            status = 400
        else:
            password = request.form.get("password", "")
            confirmation = request.form.get("confirmation", "")
            if len(password) < MIN_PASSWORD_LENGTH or len(password) > MAX_PASSWORD_LENGTH:
                error = f"Password must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH} characters."
                status = 400
            elif password != confirmation:
                error = "The passwords do not match."
                status = 400
            else:
                try:
                    changed = update_password_from_reset(token_hash, generate_password_hash(password))
                except Exception:
                    app.logger.exception("Password reset failed")
                    error = "Password reset is temporarily unavailable. Contact the administrator."
                    status = 503
                else:
                    if changed:
                        return redirect(url_for("login", reset="1"))
                    return "This password reset link is invalid or expired.", 400

    return render_template(
        "login.html",
        csrf_token=csrf_token,
        error=error,
        reset_mode=True,
        reset_token=token,
        registered=False,
        reset=False,
    ), status


@app.get("/api/csrf")
def csrf():
    return jsonify({"csrf_token": get_csrf_token()})


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
def index():
    return render_template("dashboard.html", csrf_token=get_csrf_token())


@app.get("/api/status")
def status():
    with _state_lock:
        result = dict(_state)
        result["log_count"] = len(_logs)
    return jsonify(result)


@app.get("/api/routes")
def route_list():
    try:
        return jsonify(get_routes())
    except Exception as error:
        return jsonify({"error": str(error)}), 503


@app.get("/api/logs")
def log_list():
    try:
        after_id = int(request.args.get("after", "0"))
    except ValueError:
        return jsonify({"error": "after must be an integer"}), 400
    client_id = request.args.get("client_id")
    with _state_lock:
        return jsonify([
            entry for entry in _logs
            if entry["id"] > after_id
            and (client_id is None or str(entry.get("client_id")) == client_id)
        ])


@app.post("/api/run")
def run_now():
    with _state_lock:
        if _state["running"] or _state["run_pending"]:
            return jsonify({"error": "A sync is already running or queued"}), 409
        _state["run_pending"] = True
    try:
        threading.Thread(target=run_cycle, name="manual-file-sync", daemon=True).start()
    except RuntimeError as error:
        with _state_lock:
            _state["run_pending"] = False
        return jsonify({"error": str(error)}), 500
    record_log("Manual sync started")
    return jsonify({"message": "Manual sync started"}), 202


if __name__ == "__main__":
    from waitress import serve

    serve(
        app,
        host="0.0.0.0",
        port=int(os.getenv("DASHBOARD_INTERNAL_PORT", "8080")),
        threads=8,
    )
