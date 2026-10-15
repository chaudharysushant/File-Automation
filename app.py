import os
import atexit
import hashlib
import re
import secrets
import signal
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

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is an optional runtime dependency
    psutil = None

import main


app = Flask(__name__)

PASSWORD_RESET_TTL = timedelta(minutes=30)
MIN_PASSWORD_LENGTH = 6
MAX_PASSWORD_LENGTH = 128

SETTINGS_TABLE = "file_automation_setting"
AUTO_MODE_SETTING_KEY = "auto_mode_enabled"
AUTO_MODE_LAST_RUN_KEY = "auto_mode_last_run"
DEFAULT_AUTO_INTERVAL_MINUTES = 60
# Individual client copy logs are cleared automatically on this cadence.
CLIENT_LOG_CLEANUP_LAST_RUN_KEY = "client_log_cleanup_last_run"
DEFAULT_CLIENT_LOG_CLEANUP_DAYS = 7
CLIENT_LOG_MAX_ENTRIES = 500
# Application-wide advisory lock id so only one instance runs a scheduled check.
SCHEDULER_LOCK_KEY = 76410231
# Matches the copy notification printed by main.copy_files.
_COPIED_LINE = re.compile(r"^COPIED:\s*(?P<source>.+?)\s*->\s*(?P<target>.+?)\s*$")

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
# Per-client copy history: client_id -> deque of {"id", "client_id", "filename", "timestamp"}.
_client_logs = {}
_next_client_log_id = 1
_client_logs_lock = threading.Lock()
_console = sys.stdout
_login_attempts = {}
_login_attempts_lock = threading.Lock()
_state = {
    "running": False,
    "run_pending": False,
    "last_started": None,
    "last_finished": None,
    "last_error": None,
    "current_client": None,
    "auto_mode": False,
    "last_check": None,
    "next_check": None,
    "last_result": None,
    "client_log_last_cleanup": None,
    "client_log_next_cleanup": None,
}

_scheduler_thread = None
_scheduler_lock = threading.Lock()
_scheduler_stop = threading.Event()
_scheduler_wake = threading.Event()

_client_log_cleanup_thread = None
_client_log_cleanup_lock = threading.Lock()
_client_log_cleanup_stop = threading.Event()
_client_log_cleanup_wake = threading.Event()


def schema():
    return os.getenv("PG_SCHEMA", "public")


def normalize_email(email):
    return (email or "").strip().lower()


def valid_email(email):
    return len(email) <= 254 and re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) is not None


def resolve_stored_path(value):
    return str(main.resolve_route_path(value)) if value else None


def _storage_path():
    base = os.getenv("FILE_ROUTE_BASE_PATH")
    path = Path(base) if base else Path("/")
    while not path.exists() and path != path.parent:
        path = path.parent
    return path


def system_metrics():
    if psutil is None:
        return {"available": False, "reason": "psutil is not installed"}

    storage_path = _storage_path()
    load_avg = None
    try:
        load_avg = [round(value, 2) for value in os.getloadavg()]
    except (AttributeError, OSError):
        load_avg = None

    memory = psutil.virtual_memory()
    disk = psutil.disk_usage(str(storage_path))
    return {
        "available": True,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cpu": {
            "percent": round(psutil.cpu_percent(interval=0.1), 1),
            "logical_count": psutil.cpu_count(logical=True),
            "physical_count": psutil.cpu_count(logical=False),
            "load_avg": load_avg,
        },
        "memory": {
            "total": memory.total,
            "used": memory.used,
            "available": memory.available,
            "percent": round(memory.percent, 1),
        },
        "disk": {
            "path": str(storage_path),
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "percent": round(disk.percent, 1),
        },
    }


def get_routes():
    conn = psycopg2.connect(**main.get_db_config())
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                sql.SQL("""
                    SELECT client_id, source, destination, filename_regex, enabled, carrier
                    FROM {}.file_route
                    ORDER BY client_id, source, destination
                """).format(sql.Identifier(schema()))
            )
            return [
                {"client_id": row[0],
                 "source": resolve_stored_path(row[1]),
                 "destination": resolve_stored_path(row[2]),
                 "filename_regex": row[3], "enabled": row[4], "carrier": row[5]}
                for row in cursor.fetchall()
            ]
    finally:
        conn.close()


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


def token_digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


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


def parse_copied_filename(message):
    match = _COPIED_LINE.match(str(message).strip())
    if not match:
        return None
    return Path(match.group("source")).name


def record_client_log(client_id, filename, timestamp=None):
    global _next_client_log_id
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    key = "" if client_id is None else str(client_id)
    with _client_logs_lock:
        entries = _client_logs.setdefault(key, deque(maxlen=CLIENT_LOG_MAX_ENTRIES))
        entries.append({
            "id": _next_client_log_id,
            "client_id": key,
            "filename": filename,
            "timestamp": timestamp,
        })
        _next_client_log_id += 1


def get_client_logs(client_id):
    key = "" if client_id is None else str(client_id)
    with _client_logs_lock:
        entries = _client_logs.get(key)
        return list(entries) if entries else []


def clear_client_logs(client_id=None):
    with _client_logs_lock:
        if client_id is None:
            removed = sum(len(entries) for entries in _client_logs.values())
            _client_logs.clear()
        else:
            key = str(client_id)
            entries = _client_logs.pop(key, None)
            removed = len(entries) if entries else 0
    return removed


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
        if self.client_id is not None:
            filename = parse_copied_filename(message)
            if filename:
                record_client_log(self.client_id, filename, timestamp)


def auto_interval_minutes():
    try:
        minutes = int(os.getenv("AUTO_TRANSFER_INTERVAL_MINUTES", str(DEFAULT_AUTO_INTERVAL_MINUTES)))
    except (TypeError, ValueError):
        minutes = DEFAULT_AUTO_INTERVAL_MINUTES
    return max(1, minutes)


def client_log_cleanup_interval():
    try:
        days = float(os.getenv("CLIENT_LOG_CLEANUP_DAYS", str(DEFAULT_CLIENT_LOG_CLEANUP_DAYS)))
    except (TypeError, ValueError):
        days = float(DEFAULT_CLIENT_LOG_CLEANUP_DAYS)
    return timedelta(days=max(0.0, days))


def compute_next_client_log_cleanup(last_run, now, interval):
    if last_run is None:
        return now + interval
    candidate = last_run + interval
    return candidate if candidate > now else now


def run_client_log_cleanup():
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    removed = clear_client_logs()
    try:
        set_setting(CLIENT_LOG_CLEANUP_LAST_RUN_KEY, now)
    except Exception:
        app.logger.warning("Client log cleanup time could not be persisted")
    _update_scheduler_state(
        client_log_last_cleanup=now,
        client_log_next_cleanup=None,
    )
    record_log(f"Client log cleanup removed {removed} entrie(s)")
    return removed


def parse_timestamp(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def compute_next_check(last_run, now, interval):
    if last_run is None:
        return now + interval
    candidate = last_run + interval
    return candidate if candidate > now else now


def ensure_settings_table():
    conn = psycopg2.connect(**main.get_db_config())
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    sql.SQL("""
                        CREATE TABLE IF NOT EXISTS {}.{} (
                            setting_key TEXT PRIMARY KEY,
                            setting_value TEXT,
                            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                        )
                    """).format(sql.Identifier(schema()), sql.Identifier(SETTINGS_TABLE))
                )
    finally:
        conn.close()


def get_setting(key, default=None):
    conn = psycopg2.connect(**main.get_db_config())
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                sql.SQL("SELECT setting_value FROM {}.{} WHERE setting_key = %s").format(
                    sql.Identifier(schema()), sql.Identifier(SETTINGS_TABLE)),
                (key,),
            )
            row = cursor.fetchone()
            return row[0] if row else default
    finally:
        conn.close()


def set_setting(key, value):
    conn = psycopg2.connect(**main.get_db_config())
    try:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    sql.SQL("""
                        INSERT INTO {}.{} (setting_key, setting_value, updated_at)
                        VALUES (%s, %s, CURRENT_TIMESTAMP)
                        ON CONFLICT (setting_key) DO UPDATE
                        SET setting_value = EXCLUDED.setting_value,
                            updated_at = CURRENT_TIMESTAMP
                    """).format(sql.Identifier(schema()), sql.Identifier(SETTINGS_TABLE)),
                    (key, value),
                )
    finally:
        conn.close()


def auto_mode_enabled():
    with _state_lock:
        return bool(_state.get("auto_mode"))


def load_auto_mode():
    try:
        stored = get_setting(AUTO_MODE_SETTING_KEY, "false")
        enabled = str(stored).strip().lower() in {"1", "true", "yes", "on"}
    except Exception:
        app.logger.warning("Automatic mode setting could not be read; defaulting to disabled")
        enabled = False
    with _state_lock:
        _state["auto_mode"] = enabled
    return enabled


def _update_scheduler_state(**fields):
    with _state_lock:
        _state.update(fields)


def _try_advisory_lock(conn):
    with conn.cursor() as cursor:
        cursor.execute("SELECT pg_try_advisory_lock(%s)", (SCHEDULER_LOCK_KEY,))
        return bool(cursor.fetchone()[0])


def _release_advisory_lock(conn):
    with conn.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_unlock(%s)", (SCHEDULER_LOCK_KEY,))


def _run_scheduled_transfer():
    now = datetime.now(timezone.utc)
    lock_conn = None
    acquired = False
    try:
        lock_conn = psycopg2.connect(**main.get_db_config())
        lock_conn.autocommit = True
        acquired = _try_advisory_lock(lock_conn)

        if not acquired:
            record_log("Automatic check skipped: another instance is handling it", "warning")
            _update_scheduler_state(
                last_check=now.isoformat(timespec="seconds"),
                last_result="skipped (another instance)",
            )
            return "skipped"

        with _state_lock:
            busy = _state["running"] or _state["run_pending"]
        if busy:
            record_log("Automatic check skipped: a transfer is already running", "warning")
            _update_scheduler_state(
                last_check=now.isoformat(timespec="seconds"),
                last_result="skipped (busy)",
            )
            return "skipped"

        ran = run_cycle()
        with _state_lock:
            had_error = _state["last_error"] is not None
        if not ran:
            result = "skipped (busy)"
            level = "warning"
        elif had_error:
            result = "error"
            level = "error"
        else:
            result = "success"
            level = "success"
        record_log(f"Automatic check finished: {result}", level)
        _update_scheduler_state(
            last_check=now.isoformat(timespec="seconds"),
            last_result=result,
        )
        try:
            set_setting(AUTO_MODE_LAST_RUN_KEY, now.isoformat(timespec="seconds"))
        except Exception:
            app.logger.warning("Automatic mode last run could not be persisted")
        return "success" if result == "success" else result
    except Exception as error:
        record_log(f"Automatic check failed: {error}", "error")
        _update_scheduler_state(
            last_check=now.isoformat(timespec="seconds"),
            last_result="error",
        )
        return "error"
    finally:
        if acquired and lock_conn is not None:
            try:
                _release_advisory_lock(lock_conn)
            except Exception:
                app.logger.warning("Could not release the scheduler advisory lock")
        if lock_conn is not None:
            lock_conn.close()


def _scheduler_loop():
    while not _scheduler_stop.is_set():
        try:
            if not auto_mode_enabled():
                _update_scheduler_state(next_check=None)
                _scheduler_wake.wait()
                _scheduler_wake.clear()
                continue

            now = datetime.now(timezone.utc)
            interval = timedelta(minutes=auto_interval_minutes())
            try:
                last_run = parse_timestamp(get_setting(AUTO_MODE_LAST_RUN_KEY))
            except Exception:
                app.logger.warning("Automatic mode last run could not be read")
                last_run = None
            next_run = compute_next_check(last_run, now, interval)
            _update_scheduler_state(next_check=next_run.isoformat(timespec="seconds"))

            delay = max(0.0, (next_run - now).total_seconds())
            woke = _scheduler_wake.wait(timeout=delay)
            _scheduler_wake.clear()
            if _scheduler_stop.is_set():
                break
            if woke:
                continue
            if not auto_mode_enabled():
                continue
            result = _run_scheduled_transfer()
            if result != "success":
                # Back off so a losing instance does not immediately retry and
                # double-process, and so a database outage does not spin.
                backoff = min(60.0, max(1.0, interval.total_seconds()))
                _scheduler_wake.wait(timeout=backoff)
                _scheduler_wake.clear()
        except Exception:
            app.logger.exception("Automatic transfer scheduler loop failed")
            _scheduler_stop.wait(30)


def start_scheduler():
    global _scheduler_thread
    with _scheduler_lock:
        if _scheduler_thread is not None and _scheduler_thread.is_alive():
            return
        _scheduler_stop.clear()
        _scheduler_wake.clear()
        _scheduler_thread = threading.Thread(
            target=_scheduler_loop, name="auto-transfer-scheduler", daemon=True)
        _scheduler_thread.start()
    record_log("Automatic transfer scheduler started")


def stop_scheduler():
    global _scheduler_thread
    _scheduler_stop.set()
    _scheduler_wake.set()
    thread = _scheduler_thread
    if thread is not None and thread.is_alive():
        thread.join(timeout=5)
    _scheduler_thread = None


def _client_log_cleanup_loop():
    while not _client_log_cleanup_stop.is_set():
        try:
            now = datetime.now(timezone.utc)
            interval = client_log_cleanup_interval()
            try:
                last_run = parse_timestamp(get_setting(CLIENT_LOG_CLEANUP_LAST_RUN_KEY))
            except Exception:
                app.logger.warning("Client log cleanup schedule could not be read")
                last_run = None
            next_run = compute_next_client_log_cleanup(last_run, now, interval)
            _update_scheduler_state(
                client_log_next_cleanup=next_run.isoformat(timespec="seconds"))

            delay = max(0.0, (next_run - now).total_seconds())
            woke = _client_log_cleanup_wake.wait(timeout=delay)
            _client_log_cleanup_wake.clear()
            if _client_log_cleanup_stop.is_set():
                break
            if woke:
                continue
            run_client_log_cleanup()
        except Exception:
            app.logger.exception("Client log cleanup scheduler loop failed")
            _client_log_cleanup_stop.wait(30)


def start_client_log_cleanup():
    global _client_log_cleanup_thread
    with _client_log_cleanup_lock:
        if _client_log_cleanup_thread is not None and _client_log_cleanup_thread.is_alive():
            return
        _client_log_cleanup_stop.clear()
        _client_log_cleanup_wake.clear()
        _client_log_cleanup_thread = threading.Thread(
            target=_client_log_cleanup_loop, name="client-log-cleanup", daemon=True)
        _client_log_cleanup_thread.start()
    record_log("Client log cleanup scheduler started")


def stop_client_log_cleanup():
    global _client_log_cleanup_thread
    _client_log_cleanup_stop.set()
    _client_log_cleanup_wake.set()
    thread = _client_log_cleanup_thread
    if thread is not None and thread.is_alive():
        thread.join(timeout=5)
    _client_log_cleanup_thread = None


def run_cycle(client_id=None):
    if not _run_lock.acquire(blocking=False):
        with _state_lock:
            _state["run_pending"] = False
        return False
    with _state_lock:
        _state["running"] = True
        _state["run_pending"] = False
        _state["last_started"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        _state["last_error"] = None
        _state["current_client"] = client_id
    current_client_id = client_id
    try:
        log_stream = WorkerLogStream()
        with redirect_stdout(log_stream):
            if client_id is None:
                print("Checking database for active client_ids...")
                client_ids = main.get_client_ids()
            else:
                print(f"Running transfer for client_id: {client_id}")
                client_ids = [client_id]
            for active_client in client_ids:
                current_client_id = active_client
                log_stream.client_id = active_client
                with _state_lock:
                    _state["current_client"] = active_client
                print(f"Processing client_id: {active_client}")
                main.copy_files(active_client)
            log_stream.flush()
    except Exception as error:
        with _state_lock:
            _state["last_error"] = str(error)
        record_log(f"Worker error: {error}", "error", current_client_id)
    finally:
        with _state_lock:
            _state["running"] = False
            _state["current_client"] = None
            _state["last_finished"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        _run_lock.release()
    with _state_lock:
        return _state["last_error"] is None


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
    result["auto_mode"] = bool(result.get("auto_mode"))
    result["auto_interval_minutes"] = auto_interval_minutes()
    return jsonify(result)


@app.get("/api/system")
def system_status():
    try:
        return jsonify(system_metrics())
    except Exception as error:
        app.logger.exception("Unable to read system metrics")
        return jsonify({"available": False, "error": str(error)}), 503


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


@app.get("/api/client-logs")
def client_log_list():
    client_id = request.args.get("client_id")
    if client_id is None:
        return jsonify({"error": "client_id is required"}), 400
    return jsonify(get_client_logs(client_id))


@app.post("/api/client-logs/clear")
def client_log_clear():
    payload = request.get_json(silent=True)
    if payload is None:
        payload = {}
    if "client_id" not in payload:
        return jsonify({"error": "client_id is required"}), 400
    client_id = payload.get("client_id")
    removed = clear_client_logs("" if client_id is None else str(client_id))
    record_log(f"Client logs cleared manually ({removed} entrie(s))")
    return jsonify({"cleared": removed})


@app.post("/api/run")
def run_now():
    payload = request.get_json(silent=True) or {}
    raw_client_id = payload.get("client_id")
    client_id = None
    if raw_client_id is not None:
        client_id = str(raw_client_id).strip()
        if not client_id:
            return jsonify({"error": "client_id must not be empty"}), 400
        try:
            if not main.client_is_enabled(client_id):
                return jsonify({"error": "Unknown or disabled client"}), 404
        except Exception:
            app.logger.exception("Unable to validate the requested client")
            return jsonify({"error": "Unable to validate the requested client"}), 503

    with _state_lock:
        if _state["running"] or _state["run_pending"]:
            return jsonify({"error": "A sync is already running or queued"}), 409
        _state["run_pending"] = True
        _state["current_client"] = client_id
    try:
        threading.Thread(target=run_cycle, args=(client_id,),
                         name="manual-file-sync", daemon=True).start()
    except RuntimeError as error:
        with _state_lock:
            _state["run_pending"] = False
        return jsonify({"error": str(error)}), 500
    if client_id:
        record_log(f"Manual sync started for client {client_id}", client_id=client_id)
    else:
        record_log("Manual sync started for all clients")
    return jsonify({"message": "Manual sync started", "client_id": client_id}), 202


@app.post("/api/auto-mode")
def set_auto_mode():
    payload = request.get_json(silent=True) or {}
    enabled = payload.get("enabled")
    if not isinstance(enabled, bool):
        return jsonify({"error": "enabled must be a boolean"}), 400
    try:
        ensure_settings_table()
        set_setting(AUTO_MODE_SETTING_KEY, "true" if enabled else "false")
    except Exception:
        app.logger.exception("Automatic mode setting could not be saved")
        return jsonify({"error": "Unable to update automatic mode"}), 503
    with _state_lock:
        _state["auto_mode"] = enabled
        if not enabled:
            _state["next_check"] = None
    _scheduler_wake.set()
    record_log("Automatic mode enabled" if enabled else "Automatic mode disabled",
               "info" if enabled else "warning")
    return jsonify({"auto_mode": enabled, "interval_minutes": auto_interval_minutes()})


def _handle_shutdown(signum, frame):
    stop_scheduler()
    stop_client_log_cleanup()
    raise SystemExit(0)


if __name__ == "__main__":
    from waitress import serve

    try:
        ensure_settings_table()
    except Exception:
        app.logger.warning("Automatic mode storage is unavailable; it will be retried on demand")
    load_auto_mode()
    start_scheduler()
    start_client_log_cleanup()
    atexit.register(stop_scheduler)
    atexit.register(stop_client_log_cleanup)
    for handled_signal in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(handled_signal, _handle_shutdown)
        except (ValueError, OSError):
            pass

    serve(
        app,
        host="0.0.0.0",
        port=int(os.getenv("DASHBOARD_INTERNAL_PORT", "8080")),
        threads=8,
    )
