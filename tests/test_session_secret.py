import importlib
import os
import tempfile
import unittest


class DashboardSecretTests(unittest.TestCase):
    def test_dashboard_secret_persists_between_restarts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            secret_file = os.path.join(temp_dir, ".dashboard_secret_key")
            os.environ.pop("DASHBOARD_SECRET_KEY", None)
            os.environ["DASHBOARD_SECRET_KEY_FILE"] = secret_file

            import app
            importlib.reload(app)

            first = app.app.secret_key
            self.assertTrue(first)
            self.assertTrue(os.path.exists(secret_file))
            with open(secret_file, encoding="utf-8") as handle:
                self.assertEqual(handle.read().strip(), first)

            app.app.secret_key = "changed"
            os.environ["DASHBOARD_SECRET_KEY"] = ""
            importlib.reload(app)
            self.assertEqual(app.app.secret_key, first)


if __name__ == "__main__":
    unittest.main()
