import os
import sys
import threading
from collections import deque
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_file
import psycopg2
from psycopg2 import sql

import main


app = Flask(__name__)
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


def record_log(message, level="info"):
    global _next_log_id
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _state_lock:
        _logs.append({"id": _next_log_id, "timestamp": timestamp, "level": level, "message": str(message)})
        _next_log_id += 1
    _console.write(f"[{timestamp}] {message}\n")
    _console.flush()


class WorkerLogStream:
    def __init__(self):
        self.pending = ""

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

    @staticmethod
    def _record(message):
        global _next_log_id
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with _state_lock:
            _logs.append({"id": _next_log_id, "timestamp": timestamp, "level": "info", "message": message})
            _next_log_id += 1


def run_cycle():
    if not _run_lock.acquire(blocking=False):
        return
    with _state_lock:
        _state["running"] = True
        _state["run_pending"] = False
        _state["last_started"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        _state["last_error"] = None
    try:
        log_stream = WorkerLogStream()
        with redirect_stdout(log_stream):
            print("Checking database for active client_ids...")
            for client_id in main.get_client_ids():
                print(f"Processing client_id: {client_id}")
                main.copy_files(client_id)
            log_stream.flush()
    except Exception as error:
        with _state_lock:
            _state["last_error"] = str(error)
        record_log(f"Worker error: {error}", "error")
    finally:
        with _state_lock:
            _state["running"] = False
            _state["last_finished"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        _run_lock.release()


def require_auth():
    username = os.getenv("DASHBOARD_USERNAME", "")
    password = os.getenv("DASHBOARD_PASSWORD", "")
    if not username or not password:
        return Response("Dashboard credentials are not configured.\n", status=503)
    credentials = request.authorization
    if credentials is None or credentials.username != username or credentials.password != password:
        return Response(
            "Authentication required\n", status=401,
            headers={"WWW-Authenticate": 'Basic realm="SFTP Dashboard"'},
        )
    return None


@app.before_request
def protect_dashboard():
    return require_auth()


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
    with _state_lock:
        return jsonify([entry for entry in _logs if entry["id"] > after_id])


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
    if not os.getenv("DASHBOARD_USERNAME") or not os.getenv("DASHBOARD_PASSWORD"):
        raise RuntimeError("Set DASHBOARD_USERNAME and DASHBOARD_PASSWORD before starting the dashboard")
    from waitress import serve

    serve(
        app,
        host="0.0.0.0",
        port=int(os.getenv("DASHBOARD_INTERNAL_PORT", "8080")),
        threads=8,
    )