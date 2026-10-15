import importlib
import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


class ClientLogCleanupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("DASHBOARD_SECRET_KEY", "test-secret-key")
        import app as application
        cls.module = importlib.reload(application)

    def setUp(self):
        self.app = self.__class__.module
        self.app.app.config.update(TESTING=True)
        self.client = self.app.app.test_client()
        with self.app._client_logs_lock:
            self.app._client_logs.clear()
            self.app._next_client_log_id = 1
        self.app._state.update({
            "running": False, "run_pending": False, "last_error": None,
            "auto_mode": False, "client_log_last_cleanup": None,
            "client_log_next_cleanup": None,
        })
        self.app._client_log_cleanup_wake.clear()

    def authenticate(self, csrf="test-csrf"):
        with self.client.session_transaction() as current_session:
            current_session["authenticated"] = True
            current_session["csrf_token"] = csrf
        return csrf

    def test_parse_copied_filename_extracts_name_and_ignores_noise(self):
        self.assertEqual(
            self.app.parse_copied_filename("COPIED: /data/in/report.csv -> /data/out/report.csv"),
            "report.csv",
        )
        self.assertIsNone(self.app.parse_copied_filename("SIZE CHANGE: report.csv vs previous"))
        self.assertIsNone(self.app.parse_copied_filename("Error copying file"))

    def test_recorded_logs_are_separated_by_client(self):
        self.app.record_client_log("FCM", "a.csv", "2026-01-01T00:00:00+00:00")
        self.app.record_client_log("FCM", "b.csv", "2026-01-02T00:00:00+00:00")
        self.app.record_client_log("ABC", "c.csv", "2026-01-03T00:00:00+00:00")

        fcm = self.app.get_client_logs("FCM")
        abc = self.app.get_client_logs("ABC")

        self.assertEqual([entry["filename"] for entry in fcm], ["a.csv", "b.csv"])
        self.assertEqual([entry["filename"] for entry in abc], ["c.csv"])
        self.assertTrue(all(entry["client_id"] == "FCM" for entry in fcm))

    def test_clear_client_logs_targets_only_one_client(self):
        self.app.record_client_log("FCM", "a.csv")
        self.app.record_client_log("ABC", "c.csv")

        removed = self.app.clear_client_logs("FCM")

        self.assertEqual(removed, 1)
        self.assertEqual(self.app.get_client_logs("FCM"), [])
        self.assertEqual(len(self.app.get_client_logs("ABC")), 1)

    def test_clear_all_client_logs(self):
        self.app.record_client_log("FCM", "a.csv")
        self.app.record_client_log("ABC", "c.csv")

        removed = self.app.clear_client_logs()

        self.assertEqual(removed, 2)
        self.assertEqual(self.app.get_client_logs("FCM"), [])
        self.assertEqual(self.app.get_client_logs("ABC"), [])

    def test_new_logs_are_recorded_after_cleanup(self):
        self.app.record_client_log("FCM", "before.csv")
        self.app.clear_client_logs()
        self.app.record_client_log("FCM", "after.csv")

        logs = self.app.get_client_logs("FCM")
        self.assertEqual([entry["filename"] for entry in logs], ["after.csv"])

    def test_cleanup_interval_defaults_to_seven_days(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLIENT_LOG_CLEANUP_DAYS", None)
            self.assertEqual(self.app.client_log_cleanup_interval(), timedelta(days=7))
        with patch.dict(os.environ, {"CLIENT_LOG_CLEANUP_DAYS": "3"}):
            self.assertEqual(self.app.client_log_cleanup_interval(), timedelta(days=3))
        with patch.dict(os.environ, {"CLIENT_LOG_CLEANUP_DAYS": "bad"}):
            self.assertEqual(self.app.client_log_cleanup_interval(), timedelta(days=7))

    def test_compute_next_client_log_cleanup_handles_first_stale_and_recent(self):
        now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        interval = timedelta(days=7)

        self.assertEqual(
            self.app.compute_next_client_log_cleanup(None, now, interval),
            now + interval,
        )
        self.assertEqual(
            self.app.compute_next_client_log_cleanup(now - timedelta(days=9), now, interval),
            now,
        )
        recent = now - timedelta(days=2)
        self.assertEqual(
            self.app.compute_next_client_log_cleanup(recent, now, interval),
            recent + interval,
        )

    def test_run_client_log_cleanup_clears_and_persists_schedule(self):
        self.app.record_client_log("FCM", "a.csv")
        self.app.record_client_log("ABC", "c.csv")
        saved = {}

        with patch.object(self.app, "set_setting", side_effect=lambda k, v: saved.update({k: v})):
            removed = self.app.run_client_log_cleanup()

        self.assertEqual(removed, 2)
        self.assertEqual(self.app.get_client_logs("FCM"), [])
        self.assertIn(self.app.CLIENT_LOG_CLEANUP_LAST_RUN_KEY, saved)
        self.assertIsNotNone(self.app._state["client_log_last_cleanup"])

    def test_cleanup_does_not_touch_copied_files(self):
        import main

        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "src"
            destination = Path(root) / "dst"
            source.mkdir()
            destination.mkdir()
            complete = source / "report.csv"
            complete.write_text("complete")
            old = time.time() - 120
            os.utime(complete, (old, old))

            with patch.object(main, "get_route", return_value=[("src", "dst", r".*\.csv$", False, False)]), \
                 patch.object(main, "resolve_route_path", side_effect=lambda value: Path(root) / value), \
                 patch.dict(os.environ, {"FILE_STABILITY_SECONDS": "30"}):
                main.copy_files("CLIENT")

            copied = destination / "report.csv"
            self.assertTrue(copied.exists())

            self.app.record_client_log("CLIENT", copied.name)
            with patch.object(self.app, "set_setting"):
                self.app.run_client_log_cleanup()

            self.assertEqual(self.app.get_client_logs("CLIENT"), [])
            self.assertTrue(copied.exists())
            self.assertEqual(copied.read_text(), "complete")

    def test_worker_log_stream_records_client_copy_events(self):
        stream = self.app.WorkerLogStream()
        stream.client_id = "FCM"
        stream.write("COPIED: /in/a.csv -> /out/a.csv\n")
        stream.write("SIZE CHANGE: nothing to compare\n")
        stream.flush()

        logs = self.app.get_client_logs("FCM")
        self.assertEqual([entry["filename"] for entry in logs], ["a.csv"])

    def test_client_logs_api_requires_authentication(self):
        response = self.client.get("/api/client-logs?client_id=FCM")
        self.assertEqual(response.status_code, 401)

    def test_client_logs_api_returns_entries_and_requires_client_id(self):
        self.authenticate()
        self.app.record_client_log("FCM", "a.csv")

        missing = self.client.get("/api/client-logs")
        self.assertEqual(missing.status_code, 400)

        response = self.client.get("/api/client-logs?client_id=FCM")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual([entry["filename"] for entry in payload], ["a.csv"])

    def test_manual_clear_endpoint_clears_only_requested_client(self):
        self.authenticate()
        self.app.record_client_log("FCM", "a.csv")
        self.app.record_client_log("ABC", "c.csv")

        response = self.client.post(
            "/api/client-logs/clear",
            json={"client_id": "FCM"},
            headers={"X-CSRF-Token": "test-csrf"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["cleared"], 1)
        self.assertEqual(self.app.get_client_logs("FCM"), [])
        self.assertEqual(len(self.app.get_client_logs("ABC")), 1)

    def test_manual_clear_endpoint_requires_csrf(self):
        self.authenticate()
        self.app.record_client_log("FCM", "a.csv")
        response = self.client.post("/api/client-logs/clear", json={"client_id": "FCM"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(self.app.get_client_logs("FCM")), 1)

    def test_cleanup_scheduler_runs_in_background_and_stops(self):
        ran = threading.Event()

        def fake_cleanup():
            ran.set()
            return 0

        try:
            with patch.object(self.app, "client_log_cleanup_interval", return_value=timedelta(0)), \
                 patch.object(self.app, "get_setting", return_value=None), \
                 patch.object(self.app, "run_client_log_cleanup", side_effect=fake_cleanup):
                self.app.start_client_log_cleanup()
                self.assertTrue(ran.wait(timeout=5))
                self.app.stop_client_log_cleanup()
        finally:
            self.app.stop_client_log_cleanup()

        self.assertIsNone(self.app._client_log_cleanup_thread)

    def test_run_cycle_records_copy_log_from_worker_output(self):
        def fake_copy(client_id):
            print("COPIED: /in/file.csv -> /out/file.csv")

        with patch.object(self.app.main, "get_client_ids", return_value=["FCM"]), \
             patch.object(self.app.main, "copy_files", side_effect=fake_copy):
            result = self.app.run_cycle(None)

        self.assertTrue(result)
        self.assertEqual(
            [entry["filename"] for entry in self.app.get_client_logs("FCM")],
            ["file.csv"],
        )


if __name__ == "__main__":
    unittest.main()
