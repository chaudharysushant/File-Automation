import os
import hashlib
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

from flask import Flask, jsonify, redirect, render_template, request, send_file, session, url_for
import psycopg2
from psycopg2 import sql
from werkzeug.security import check_password_hash, generate_password_hash

import main


app = Flask(__name__)


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
_state = {
    "running": False,
    "run_pending": False,
    "last_started": None,
    "last_finished": None,
    "last_error": None,
}


def get_routes():
    schema = os.getenv("PG_SCHEMA", "public")
    conn = psycopg2.connect(**main.get_db_config())
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                sql.SQL("""
                    SELECT client_id, source, destination, filename_regex, enabled
                    FROM {}.file_route
                    ORDER BY client_id, source, destination
                """).format(sql.Identifier(schema))
            )
            return [
                {"client_id": row[0], "source": row[1], "destination": row[2],
                 "filename_regex": row[3], "enabled": row[4]}
                for row in cursor.fetchall()
            ]
    finally:
        conn.close()


def get_dashboard_account():
    schema = os.getenv("PG_SCHEMA", "public")
    conn = psycopg2.connect(**main.get_db_config())
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                sql.SQL("""
                    SELECT username, password_hash
                    FROM {}.dashboard_account
                    WHERE account_id = 1
                """).format(sql.Identifier(schema))
            )
            return cursor.fetchone()
    finally:
        conn.close()


def create_dashboard_account(username, password_hash):
    schema = os.getenv("PG_SCHEMA", "public")
    conn = psycopg2.connect(**main.get_db_config())
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    sql.SQL("""
                        INSERT INTO {}.dashboard_account (account_id, username, password_hash)
                        VALUES (1, %s, %s)
                        ON CONFLICT (account_id) DO NOTHING
                        RETURNING account_id
                    """).format(sql.Identifier(schema)),
                    (username, password_hash),
                )
                return cursor.fetchone() is not None
    finally:
        conn.close()


def password_reset_mail_configured():
    required = (
        "DASHBOARD_RESET_EMAIL",
        "DASHBOARD_SMTP_HOST",
        "DASHBOARD_SMTP_FROM",
        "DASHBOARD_PUBLIC_URL",
    )
    return all(os.getenv(name) for name in required)


def save_password_reset(username, token_hash):
    schema = os.getenv("PG_SCHEMA", "public")
    conn = psycopg2.connect(**main.get_db_config())
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    sql.SQL("""
                        UPDATE {}.dashboard_account
                        SET reset_token_hash = %s,
                            reset_expires_at = CURRENT_TIMESTAMP + INTERVAL '30 minutes'
                        WHERE account_id = 1 AND username = %s
                        RETURNING account_id
                    """).format(sql.Identifier(schema)),
                    (token_hash, username),
                )
                return cursor.fetchone() is not None
    finally:
        conn.close()


def clear_password_reset(token_hash):
    schema = os.getenv("PG_SCHEMA", "public")
    conn = psycopg2.connect(**main.get_db_config())
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    sql.SQL("""
                        UPDATE {}.dashboard_account
                        SET reset_token_hash = NULL, reset_expires_at = NULL
                        WHERE account_id = 1 AND reset_token_hash = %s
                    """).format(sql.Identifier(schema)),
                    (token_hash,),
                )
    finally:
        conn.close()


def password_reset_is_valid(token_hash):
    schema = os.getenv("PG_SCHEMA", "public")
    conn = psycopg2.connect(**main.get_db_config())
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                sql.SQL("""
                    SELECT 1
                    FROM {}.dashboard_account
                    WHERE account_id = 1
                      AND reset_token_hash = %s
                      AND reset_expires_at > CURRENT_TIMESTAMP
                """).format(sql.Identifier(schema)),
                (token_hash,),
            )
            return cursor.fetchone() is not None
    finally:
        conn.close()


def update_password_from_reset(token_hash, password_hash):
    schema = os.getenv("PG_SCHEMA", "public")
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
                        WHERE account_id = 1
                          AND reset_token_hash = %s
                          AND reset_expires_at > CURRENT_TIMESTAMP
                        RETURNING account_id
                    """).format(sql.Identifier(schema)),
                    (password_hash, token_hash),
                )
                return cursor.fetchone() is not None
    finally:
        conn.close()


def send_password_reset_email(token):
    host = os.getenv("DASHBOARD_SMTP_HOST")
    port = int(os.getenv("DASHBOARD_SMTP_PORT", "587"))
    sender = os.getenv("DASHBOARD_SMTP_FROM")
    recipient = os.getenv("DASHBOARD_RESET_EMAIL")
    public_url = os.getenv("DASHBOARD_PUBLIC_URL", "").rstrip("/")
    reset_url = f"{public_url}{url_for('reset_password', token=token)}"

    message = EmailMessage()
    message["Subject"] = "Reset your SFTP dashboard password"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        "A password reset was requested for the SFTP dashboard.\n\n"
        f"Use this one-time link within 30 minutes: {reset_url}\n\n"
        "If you did not request this, you can ignore this message."
    )

    username = os.getenv("DASHBOARD_SMTP_USERNAME", "")
    password = os.getenv("DASHBOARD_SMTP_PASSWORD", "")
    use_ssl = os.getenv("DASHBOARD_SMTP_USE_SSL", "false").lower() in {"1", "true", "yes"}
    if use_ssl:
        with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=15) as server:
            if username and password:
                server.login(username, password)
            server.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.starttls(context=ssl.create_default_context())
            if username and password:
                server.login(username, password)
            server.send_message(message)


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


def get_csrf_token():
    return session.setdefault("csrf_token", secrets.token_urlsafe(32))


def valid_csrf_token():
    expected = session.get("csrf_token", "")
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    return bool(expected and supplied and secrets.compare_digest(expected, supplied))


@app.before_request
def protect_dashboard():
    if request.endpoint in {"login", "register", "forgot_password", "reset_password"}:
        return None
    if not session.get("authenticated"):
        try:
            account = get_dashboard_account()
        except Exception:
            app.logger.exception("Dashboard account storage is unavailable")
            message = "Dashboard account storage is unavailable. Apply create_dashboard_account.sql."
            if request.path.startswith("/api/"):
                return jsonify({"error": message}), 503
            return message, 503
        if account is None:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Dashboard registration is required"}), 401
            return redirect(url_for("register"))
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
    try:
        account = get_dashboard_account()
    except Exception:
        app.logger.exception("Dashboard account storage is unavailable")
        return "Dashboard account storage is unavailable. Apply create_dashboard_account.sql.", 503
    if account is None:
        return redirect(url_for("register"))

    if request.method == "POST":
        if not valid_csrf_token():
            error = "Your sign-in form expired. Please try again."
            status = 400
        else:
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            stored_username, password_hash = account
            valid_username = secrets.compare_digest(username, stored_username)
            valid_password = check_password_hash(password_hash, password)
            if valid_username and valid_password:
                session.clear()
                session["authenticated"] = True
                session["csrf_token"] = secrets.token_urlsafe(32)
                session.permanent = True
                return redirect(url_for("index"))
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

    try:
        if get_dashboard_account() is not None:
            return redirect(url_for("login"))
    except Exception:
        app.logger.exception("Dashboard account storage is unavailable")
        return "Dashboard account storage is unavailable. Apply create_dashboard_account.sql.", 503

    error = None
    status = 200
    token = get_csrf_token()
    if request.method == "POST":
        if not valid_csrf_token():
            error = "Your registration form expired. Please try again."
            status = 400
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            confirmation = request.form.get("confirmation", "")
            if len(username) < 3 or len(username) > 64:
                error = "Username must be between 3 and 64 characters."
                status = 400
            elif len(password) < 12 or len(password) > 128:
                error = "Password must be between 12 and 128 characters."
                status = 400
            elif password != confirmation:
                error = "The passwords do not match."
                status = 400
            else:
                try:
                    created = create_dashboard_account(
                        username,
                        generate_password_hash(password),
                    )
                except Exception:
                    app.logger.exception("Dashboard account registration failed")
                    error = "Unable to create the account. Check the database and try again."
                    status = 503
                else:
                    if created:
                        return redirect(url_for("login", registered="1"))
                    return redirect(url_for("login"))

    return render_template(
        "login.html",
        csrf_token=token,
        error=error,
        register_mode=True,
        registered=False,
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
            username = request.form.get("username", "").strip()
            reset_token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(reset_token.encode("utf-8")).hexdigest()
            try:
                if save_password_reset(username, token_hash):
                    try:
                        send_password_reset_email(reset_token)
                    except Exception:
                        clear_password_reset(token_hash)
                        app.logger.exception("Password reset email could not be sent")
                        error = "Password reset email could not be sent. Contact the administrator."
                        status = 503
                if error is None:
                    notice = "If the account exists, a reset link has been sent to the configured recovery email."
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
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    try:
        if not password_reset_is_valid(token_hash):
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
            if len(password) < 12 or len(password) > 128:
                error = "Password must be between 12 and 128 characters."
                status = 400
            elif password != confirmation:
                error = "The passwords do not match."
                status = 400
            else:
                try:
                    changed = update_password_from_reset(
                        token_hash,
                        generate_password_hash(password),
                    )
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
    return send_file(Path(__file__).with_name("ui.html"), mimetype="text/html")


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