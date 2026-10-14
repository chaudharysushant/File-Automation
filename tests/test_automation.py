import importlib
import os
import tempfile
import threading
import time
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

class FakeCursor:
    def __init__(self, rows):
        self._rows = rows

    def execute(self, *args, **kwargs):
        return None

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

class FakeConnection:
    def __init__(self, rows):
        self._rows = rows

    def cursor(self):
        return FakeCursor(self._rows)

    def close(self):
        return None

class ImmediateThread:
    def __init__(self, target=None, args=(), kwargs=None, **options):
        self.target = target
        self.args = args
        self.kwargs = kwargs or {}

    def start(self):
        self.target(*self.args, **self.kwargs)

    def is_alive(self):
        return False

class AutomationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("DASHBOARD_SECRET_KEY", "test-secret-key")
        import app as application
        cls.module = importlib.reload(application)

    def setUp(self):
        self.app = self.__class__.module
        self.app.app.config.update(TESTING=True)
        self.client = self.app.app.test_client()
        self.app._state.update({
            "running": False, "run_pending": False, "last_error": None,
            "auto_mode": False, "last_check": None, "next_check": None, "last_result": None,
        })
        self.app._scheduler_wake.clear()

    def authenticate(self):
        with self.client.session_transaction() as current_session:
            current_session["authenticated"] = True
            current_session["csrf_token"] = "test-csrf"
        return "test-csrf"

    def test_compute_next_check_handles_first_run_stale_and_recent(self):
        now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        interval = timedelta(minutes=60)

        self.assertEqual(self.app.compute_next_check(None, now, interval), now + interval)

        stale = now - timedelta(hours=5)
        self.assertEqual(self.app.compute_next_check(stale, now, interval), now)

        recent = now - timedelta(minutes=10)
        self.assertEqual(self.app.compute_next_check(recent, now, interval), recent + interval)

    def test_auto_interval_minutes_default_override_and_invalid(self):
        with patch.dict(os.environ, {"AUTO_TRANSFER_INTERVAL_MINUTES": "15"}):
            self.assertEqual(self.app.auto_interval_minutes(), 15)
        with patch.dict(os.environ, {"AUTO_TRANSFER_INTERVAL_MINUTES": "not-a-number"}):
            self.assertEqual(self.app.auto_interval_minutes(), self.app.DEFAULT_AUTO_INTERVAL_MINUTES)
        with patch.dict(os.environ, {"AUTO_TRANSFER_INTERVAL_MINUTES": "0"}):
            self.assertEqual(self.app.auto_interval_minutes(), 1)

    def test_parse_timestamp_accepts_iso_and_handles_garbage(self):
        parsed = self.app.parse_timestamp("2026-01-01T12:00:00")
        self.assertEqual(parsed.tzinfo, timezone.utc)
        self.assertIsNone(self.app.parse_timestamp("not-a-date"))
        self.assertIsNone(self.app.parse_timestamp(None))

    def test_get_routes_includes_carrier_and_resolves_paths(self):
        rows = [("FCM", "zph_chs/x", "zph_internal/y", "re", True, "CHS")]
        with patch.object(self.app.psycopg2, "connect", return_value=FakeConnection(rows)), \
             patch.object(self.app.main, "get_db_config", return_value={}), \
             patch.object(self.app.main, "resolve_route_path", side_effect=lambda value: "/base/" + value):
            routes = self.app.get_routes()
        self.assertEqual(routes[0]["carrier"], "CHS")
        self.assertEqual(routes[0]["source"], "/base/zph_chs/x")
        self.assertEqual(routes[0]["destination"], "/base/zph_internal/y")

    def test_resolve_stored_path_handles_missing_values(self):
        with patch.object(self.app.main, "resolve_route_path", side_effect=lambda value: "/base/" + value):
            self.assertIsNone(self.app.resolve_stored_path(None))
            self.assertIsNone(self.app.resolve_stored_path(""))
            self.assertEqual(self.app.resolve_stored_path("zph/x"), "/base/zph/x")

    def test_run_scopes_to_a_single_validated_client(self):
        self.authenticate()
        calls = {}
        fake_threading = types.SimpleNamespace(Thread=ImmediateThread)

        def fake_run_cycle(client_id=None):
            calls["client_id"] = client_id
            return True

        with patch.object(self.app.main, "client_is_enabled", return_value=True), \
             patch.object(self.app, "run_cycle", side_effect=fake_run_cycle), \
             patch.object(self.app, "threading", fake_threading):
            response = self.client.post(
                "/api/run", json={"client_id": "FCM"},
                headers={"X-CSRF-Token": "test-csrf"})

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.get_json()["client_id"], "FCM")
        self.assertEqual(calls["client_id"], "FCM")

    def test_run_rejects_unknown_client(self):
        self.authenticate()
        with patch.object(self.app.main, "client_is_enabled", return_value=False):
            response = self.client.post(
                "/api/run", json={"client_id": "GHOST"},
                headers={"X-CSRF-Token": "test-csrf"})
        self.assertEqual(response.status_code, 404)

    def test_run_rejects_when_a_transfer_is_active(self):
        self.authenticate()
        self.app._state["running"] = True
        response = self.client.post(
            "/api/run", json={"client_id": "FCM"},
            headers={"X-CSRF-Token": "test-csrf"})
        self.assertEqual(response.status_code, 409)

    def test_run_without_client_runs_overall(self):
        self.authenticate()
        calls = {}

        def fake_run_cycle(client_id=None):
            calls["client_id"] = client_id
            return True

        with patch.object(self.app, "run_cycle", side_effect=fake_run_cycle), \
             patch.object(self.app, "threading", types.SimpleNamespace(Thread=ImmediateThread)):
            response = self.client.post(
                "/api/run", json={}, headers={"X-CSRF-Token": "test-csrf"})

        self.assertEqual(response.status_code, 202)
        self.assertIsNone(calls["client_id"])

    def test_run_cycle_returns_false_when_lock_is_held(self):
        self.app._state["run_pending"] = True
        self.app._run_lock.acquire()
        try:
            result = self.app.run_cycle(None)
        finally:
            self.app._run_lock.release()
        self.assertFalse(result)
        self.assertFalse(self.app._state["run_pending"])

    def test_run_cycle_tracks_current_client_for_overall_and_single(self):
        for requested, expected in ((None, ["ABC", "FCM"]), ("FCM", ["FCM"])):
            seen = []

            def fake_copy(client_id):
                with self.app._state_lock:
                    seen.append(self.app._state["current_client"])

            with patch.object(self.app.main, "get_client_ids", return_value=["ABC", "FCM"]), \
                 patch.object(self.app.main, "copy_files", side_effect=fake_copy):
                result = self.app.run_cycle(requested)

            self.assertTrue(result)
            self.assertEqual(seen, expected)
            self.assertIsNone(self.app._state["current_client"])

    def test_auto_mode_toggle_persists_and_updates_state(self):
        self.authenticate()
        saved = {}
        with patch.object(self.app, "ensure_settings_table"), \
             patch.object(self.app, "set_setting", side_effect=lambda k, v: saved.update({k: v})):
            response = self.client.post(
                "/api/auto-mode", json={"enabled": True},
                headers={"X-CSRF-Token": "test-csrf"})

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["auto_mode"])
        self.assertEqual(saved[self.app.AUTO_MODE_SETTING_KEY], "true")
        self.assertTrue(self.app._state["auto_mode"])

    def test_auto_mode_toggle_rejects_non_boolean(self):
        self.authenticate()
        response = self.client.post(
            "/api/auto-mode", json={"enabled": "yes"},
            headers={"X-CSRF-Token": "test-csrf"})
        self.assertEqual(response.status_code, 400)

    def test_auto_mode_toggle_reports_storage_failure(self):
        self.authenticate()
        with patch.object(self.app, "ensure_settings_table"), \
             patch.object(self.app, "set_setting", side_effect=RuntimeError("db down")):
            response = self.client.post(
                "/api/auto-mode", json={"enabled": True},
                headers={"X-CSRF-Token": "test-csrf"})
        self.assertEqual(response.status_code, 503)

    def test_scheduled_run_skips_when_advisory_lock_not_acquired(self):
        with patch.object(self.app.psycopg2, "connect", return_value=FakeConnection([(False,)])), \
             patch.object(self.app, "run_cycle") as run_cycle:
            self.app._run_scheduled_transfer()
        run_cycle.assert_not_called()
        self.assertIn("another instance", self.app._state["last_result"])

    def test_scheduler_runs_overall_cycle_and_stops_cleanly(self):
        ran = threading.Event()
        calls = []

        def fake_run_cycle(client_id=None):
            calls.append(client_id)
            ran.set()
            return True

        self.app._state["auto_mode"] = True
        try:
            with patch.object(self.app, "auto_interval_minutes", return_value=0), \
                 patch.object(self.app, "get_setting", return_value=None), \
                 patch.object(self.app, "set_setting"), \
                 patch.object(self.app.psycopg2, "connect", return_value=FakeConnection([(True,)])), \
                 patch.object(self.app, "run_cycle", side_effect=fake_run_cycle):
                self.app.start_scheduler()
                self.assertTrue(ran.wait(timeout=5))
                self.app.stop_scheduler()
        finally:
            self.app._state["auto_mode"] = False

        self.assertGreaterEqual(len(calls), 1)
        self.assertEqual(set(calls), {None})
        self.assertIsNone(self.app._scheduler_thread)


class FileStabilityTests(unittest.TestCase):
    def setUp(self):
        import main
        self.main = main

    def test_recently_written_file_waits_until_stable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "upload.csv"
            path.write_text("data")
            started = time.monotonic()
            stable = self.main.wait_for_stable_file(
                path, required_seconds=1, poll_interval=0.1, timeout=10)
            self.assertTrue(stable)
            self.assertGreaterEqual(time.monotonic() - started, 0.9)

    def test_previously_written_file_is_immediately_stable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "upload.csv"
            path.write_text("data")
            old = time.time() - 120
            os.utime(path, (old, old))
            self.assertTrue(self.main.wait_for_stable_file(
                path, required_seconds=30, poll_interval=0.1, timeout=1))

    def test_missing_file_is_not_stable(self):
        self.assertFalse(self.main.wait_for_stable_file(
            Path("/nonexistent/never-here"), required_seconds=0,
            poll_interval=0.05, timeout=1))

    def test_stability_seconds_reads_env_and_clamps(self):
        with patch.dict(os.environ, {"FILE_STABILITY_SECONDS": "5"}):
            self.assertEqual(self.main.file_stability_seconds(), 5)
        with patch.dict(os.environ, {"FILE_STABILITY_SECONDS": "not-a-number"}):
            self.assertEqual(self.main.file_stability_seconds(), 30)
        with patch.dict(os.environ, {"FILE_STABILITY_SECONDS": "-4"}):
            self.assertEqual(self.main.file_stability_seconds(), 0)

    def test_file_that_keeps_growing_times_out(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "growing.csv"
            path.write_text("start")
            stop = threading.Event()

            def keep_writing():
                while not stop.is_set():
                    with open(path, "a", encoding="utf-8") as handle:
                        handle.write("more\n")
                    time.sleep(0.05)

            writer = threading.Thread(target=keep_writing, daemon=True)
            writer.start()
            try:
                self.assertFalse(self.main.wait_for_stable_file(
                    path, required_seconds=1, poll_interval=0.1, timeout=0.6))
            finally:
                stop.set()
                writer.join()

    def test_copy_files_copies_stable_and_wires_stability_check(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "src"
            destination = Path(root) / "dst"
            source.mkdir()
            destination.mkdir()
            complete = source / "report.csv"
            complete.write_text("complete")
            old = time.time() - 120
            os.utime(complete, (old, old))

            with patch.object(self.main, "get_route", return_value=[("src", "dst", r".*\.csv$")]), \
                 patch.object(self.main, "resolve_route_path", side_effect=lambda value: Path(root) / value), \
                 patch.dict(os.environ, {"FILE_STABILITY_SECONDS": "30"}):
                self.main.copy_files("CLIENT")

            copied = destination / "report.csv"
            self.assertTrue(copied.exists())
            self.assertEqual(copied.read_text(), "complete")


if __name__ == "__main__":
    unittest.main()
