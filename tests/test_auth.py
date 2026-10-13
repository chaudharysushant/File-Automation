import importlib
import os
import unittest
from unittest.mock import patch


class DashboardAuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("DASHBOARD_SECRET_KEY", "test-secret-key")
        import app as application
        cls.module = importlib.reload(application)

    def setUp(self):
        self.module = self.__class__.module
        self.module.app.config.update(TESTING=True)
        self.client = self.module.app.test_client()
        self.module._login_attempts.clear()

    def csrf(self):
        with self.client.session_transaction() as current_session:
            return current_session.setdefault("csrf_token", "test-csrf")

    def test_registration_requires_csrf_and_password_minimum_is_six(self):
        with patch.object(self.module, "create_account", return_value=True) as create:
            missing_csrf = self.client.post("/register", data={
                "username": "operator", "email": "user@example.com",
                "password": "secret6", "confirmation": "secret6",
            })
            self.assertEqual(missing_csrf.status_code, 400)
            create.assert_not_called()

            token = self.csrf()
            too_short = self.client.post("/register", data={
                "csrf_token": token, "username": "operator", "email": "user@example.com",
                "password": "12345", "confirmation": "12345",
            })
            self.assertEqual(too_short.status_code, 400)
            create.assert_not_called()

            accepted = self.client.post("/register", data={
                "csrf_token": token, "username": "operator", "email": "user@example.com",
                "password": "123456", "confirmation": "123456",
            })
            self.assertEqual(accepted.status_code, 302)
            self.assertIn("registered=1", accepted.headers["Location"])
            create.assert_called_once()
            username, email, _ = create.call_args.args
            self.assertEqual(username, "operator")
            self.assertEqual(email, "user@example.com")

    def test_registration_stores_normalized_email_and_rejects_duplicates(self):
        with patch.object(self.module, "create_account", return_value=True) as create:
            token = self.csrf()
            response = self.client.post("/register", data={
                "csrf_token": token, "username": "operator", "email": "User@Example.COM",
                "password": "secret6", "confirmation": "secret6",
            })
            self.assertEqual(response.status_code, 302)
            self.assertEqual(create.call_args.args[1], "user@example.com")

        with patch.object(self.module, "create_account", return_value=False):
            token = self.csrf()
            duplicate = self.client.post("/register", data={
                "csrf_token": token, "username": "taken", "email": "taken@example.com",
                "password": "secret6", "confirmation": "secret6",
            })
            self.assertEqual(duplicate.status_code, 409)

    def test_forgot_password_uses_only_matching_registered_email(self):
        with patch.object(self.module, "password_reset_mail_configured", return_value=True), patch.object(
            self.module, "save_password_reset", return_value=False
        ) as save, patch.object(self.module, "send_password_reset_email") as send:
            token = self.csrf()
            response = self.client.post("/forgot-password", data={
                "csrf_token": token, "email": "unknown@example.com",
            })
            self.assertEqual(response.status_code, 200)
            self.assertIn("If an account exists", response.get_data(as_text=True))
            save.assert_called_once()
            self.assertEqual(save.call_args.args[0], "unknown@example.com")
            send.assert_not_called()

        with patch.object(self.module, "password_reset_mail_configured", return_value=True), patch.object(
            self.module, "save_password_reset", return_value=True
        ) as save, patch.object(self.module, "send_password_reset_email") as send:
            token = self.csrf()
            response = self.client.post("/forgot-password", data={
                "csrf_token": token, "email": "registered@example.com",
            })
            self.assertEqual(response.status_code, 200)
            save.assert_called_once()
            self.assertEqual(save.call_args.args[0], "registered@example.com")
            self.assertEqual(send.call_args.args[1], "registered@example.com")

    def test_login_rate_limit_records_failures(self):
        address = "198.51.100.20"
        for _ in range(10):
            self.module.record_login_failure(address)
        self.assertTrue(self.module.login_is_throttled(address))
        self.module.clear_login_failures(address)
        self.assertFalse(self.module.login_is_throttled(address))


if __name__ == "__main__":
    unittest.main()