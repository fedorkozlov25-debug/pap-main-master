import unittest
from unittest.mock import MagicMock, patch

import mysql.connector
from mysql.connector import errorcode
from werkzeug.security import check_password_hash, generate_password_hash

from src.app import PASSWORD_HASH_METHOD, app


class PasswordAuthenticationTests(unittest.TestCase):
    password = "Correct-password-42"

    @classmethod
    def setUpClass(cls):
        cls.stored_hash = generate_password_hash(
            cls.password, method=PASSWORD_HASH_METHOD, salt_length=16
        )

    def setUp(self):
        config_patch = patch.dict(
            app.config, {"TESTING": True, "SECRET_KEY": "test-only-secret"}
        )
        config_patch.start()
        self.addCleanup(config_patch.stop)
        self.client = app.test_client()

        self.connection = MagicMock()
        self.connection.__enter__.return_value = self.connection
        self.connection.__exit__.return_value = False
        self.cursor = self.connection.cursor.return_value
        self.cursor.__enter__.return_value = self.cursor
        self.cursor.__exit__.return_value = False
        self.cursor.fetchone.return_value = None
        connect_patch = patch("src.app.connect", return_value=self.connection)
        self.connect = connect_patch.start()
        self.addCleanup(connect_patch.stop)

        self.registration = {
            "name": "Test User",
            "email": "user@example.com",
            "phone": "+37120000000",
            "password": self.password,
        }

    def login(self, password=None, email="user@example.com"):
        return self.client.post(
            "/user_login",
            json={
                "email": email,
                "password": self.password if password is None else password,
            },
        )

    def set_database_user(self, password_hash=None):
        self.cursor.fetchone.return_value = {
            "id": 7,
            "password_hash": self.stored_hash if password_hash is None else password_hash,
        }

    def assert_no_authenticated_session(self):
        with self.client.session_transaction() as session:
            self.assertNotIn("user_id", session)

    def test_registration_saves_only_a_salted_hash(self):
        response = self.client.post("/user_register", json=self.registration)

        self.assertEqual(response.status_code, 201)
        query, values = self.cursor.execute.call_args.args
        self.assertIn("password_hash", query)
        self.assertEqual(query.count("%s"), 4)
        self.assertEqual(values[:3], ("Test User", "user@example.com", "+37120000000"))
        stored_hash = values[3]
        self.assertNotIn(self.password, query)
        self.assertNotIn(self.password, values)
        self.assertTrue(check_password_hash(stored_hash, self.password))
        self.assertFalse(check_password_hash(stored_hash, "wrong-password"))
        method, salt, _ = stored_hash.split("$")
        self.assertEqual(method, PASSWORD_HASH_METHOD)
        self.assertEqual(len(salt), 16)
        self.connection.commit.assert_called_once_with()
        self.cursor.__exit__.assert_called_once()
        self.connection.__exit__.assert_called_once()
        self.assertNotIn(self.password, response.get_data(as_text=True))
        self.assertNotIn(stored_hash, response.get_data(as_text=True))

    def test_equal_passwords_receive_different_salts(self):
        self.client.post("/user_register", json=self.registration)
        first_hash = self.cursor.execute.call_args.args[1][3]
        second_registration = dict(self.registration, email="other@example.com")
        self.client.post("/user_register", json=second_registration)
        second_hash = self.cursor.execute.call_args.args[1][3]

        self.assertNotEqual(first_hash, second_hash)
        self.assertNotEqual(first_hash.split("$")[1], second_hash.split("$")[1])
        self.assertTrue(check_password_hash(second_hash, self.password))

    def test_password_whitespace_is_preserved(self):
        password = "  Пароль с пробелами  "
        response = self.client.post(
            "/user_register", json=dict(self.registration, password=password)
        )
        self.assertEqual(response.status_code, 201)
        stored_hash = self.cursor.execute.call_args.args[1][3]
        self.assertTrue(check_password_hash(stored_hash, password))
        self.assertFalse(check_password_hash(stored_hash, password.strip()))

        self.set_database_user(stored_hash)
        self.assertEqual(self.login(password).status_code, 200)
        self.assertEqual(self.login(password.strip()).status_code, 401)

    def test_registration_normalizes_identity_but_binds_sql_parameters(self):
        name = "Robert'); DROP TABLE users;--"
        response = self.client.post(
            "/user_register",
            json=dict(self.registration, name=name, email="  USER@EXAMPLE.COM  "),
        )
        self.assertEqual(response.status_code, 201)
        query, values = self.cursor.execute.call_args.args
        self.assertNotIn(name, query)
        self.assertEqual(values[:2], (name, "user@example.com"))

    def test_registration_accepts_optional_phone(self):
        registration = dict(self.registration)
        del registration["phone"]
        response = self.client.post("/user_register", json=registration)
        self.assertEqual(response.status_code, 201)
        self.assertIsNone(self.cursor.execute.call_args.args[1][2])

    def test_registration_rejects_invalid_passwords_before_database_access(self):
        for password in (None, "", "short", 12345678, [], {}, "x" * 1025):
            with self.subTest(password_type=type(password).__name__):
                response = self.client.post(
                    "/user_register", json=dict(self.registration, password=password)
                )
                self.assertEqual(response.status_code, 400)
        registration = dict(self.registration)
        del registration["password"]
        self.assertEqual(
            self.client.post("/user_register", json=registration).status_code, 400
        )
        self.connect.assert_not_called()

    def test_registration_rejects_invalid_fields(self):
        for overrides in (
            {"name": None},
            {"name": " "},
            {"name": "x" * 256},
            {"email": None},
            {"email": "not-an-email"},
            {"email": "x" * 256 + "@example.com"},
            {"phone": []},
            {"phone": "1" * 51},
        ):
            with self.subTest(overrides=overrides):
                response = self.client.post(
                    "/user_register", json=dict(self.registration, **overrides)
                )
                self.assertEqual(response.status_code, 400)
        self.connect.assert_not_called()

    def test_auth_endpoints_reject_malformed_or_non_object_json(self):
        for endpoint in ("/user_register", "/user_login"):
            for payload in ("{", "null", "[]", '"text"', "42"):
                with self.subTest(endpoint=endpoint, payload=payload):
                    response = self.client.post(
                        endpoint, data=payload, content_type="application/json"
                    )
                    self.assertEqual(response.status_code, 400)
            self.assertEqual(self.client.post(endpoint).status_code, 400)
        self.connect.assert_not_called()

    def test_duplicate_email_is_a_conflict_and_not_committed(self):
        self.cursor.execute.side_effect = mysql.connector.IntegrityError(
            msg="Duplicate email", errno=errorcode.ER_DUP_ENTRY
        )
        response = self.client.post("/user_register", json=self.registration)
        self.assertEqual(response.status_code, 409)
        self.connection.commit.assert_not_called()
        self.connection.__exit__.assert_called_once()

    def test_registration_database_error_does_not_expose_details(self):
        self.connect.side_effect = mysql.connector.Error("private connection details")
        with self.assertLogs(app.logger, level="ERROR"):
            response = self.client.post("/user_register", json=self.registration)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("private connection details", response.get_data(as_text=True))
        self.assertNotIn(self.password, response.get_data(as_text=True))

    def test_registered_hash_can_be_used_for_login(self):
        registration_response = self.client.post(
            "/user_register", json=self.registration
        )
        self.assertEqual(registration_response.status_code, 201)
        stored_hash = self.cursor.execute.call_args.args[1][3]
        self.set_database_user(stored_hash)
        with self.client.session_transaction() as session:
            session["old_session_data"] = "discard"

        response = self.login(email="  USER@EXAMPLE.COM  ")
        self.assertEqual(response.status_code, 200)
        self.connection.cursor.assert_called_with(dictionary=True)
        query, values = self.cursor.execute.call_args.args
        self.assertIn("WHERE email = %s", query)
        self.assertEqual(values, ("user@example.com",))
        with self.client.session_transaction() as session:
            self.assertEqual(dict(session), {"user_id": 7})
        self.assertNotIn(self.password, response.get_data(as_text=True))
        self.assertNotIn(stored_hash, response.get_data(as_text=True))

    def test_wrong_password_and_unknown_email_return_the_same_error(self):
        self.set_database_user()
        wrong_password_response = self.login("incorrect-password")
        self.cursor.fetchone.return_value = None
        unknown_email_response = self.login(email="unknown@example.com")

        self.assertEqual(wrong_password_response.status_code, 401)
        self.assertEqual(unknown_email_response.status_code, 401)
        self.assertEqual(
            wrong_password_response.get_json(), unknown_email_response.get_json()
        )
        self.assert_no_authenticated_session()

    def test_password_hash_itself_is_not_a_valid_password(self):
        self.set_database_user()
        self.assertEqual(self.login(self.stored_hash).status_code, 401)
        self.assert_no_authenticated_session()

    def test_plaintext_database_value_is_not_accepted_as_a_hash(self):
        self.set_database_user(self.password)
        self.assertEqual(self.login().status_code, 401)
        self.assert_no_authenticated_session()

    def test_unsupported_or_corrupted_hash_does_not_authenticate(self):
        for stored_hash in ("unsupported$salt$hash", "pbkdf2:sha256:invalid$salt$hash"):
            with self.subTest(stored_hash=stored_hash):
                self.set_database_user(stored_hash)
                response = self.login()
                self.assertEqual(response.status_code, 401)
                self.assert_no_authenticated_session()

    def test_login_rejects_invalid_fields_before_database_access(self):
        for payload in (
            {},
            {"email": "user@example.com"},
            {"email": "user@example.com", "password": ""},
            {"email": "user@example.com", "password": 123},
            {"email": "user@example.com", "password": "x" * 1025},
            {"email": [], "password": self.password},
            {"email": "invalid", "password": self.password},
        ):
            with self.subTest(payload=payload):
                response = self.client.post("/user_login", json=payload)
                self.assertEqual(response.status_code, 400)
        self.connect.assert_not_called()
        self.assert_no_authenticated_session()

    def test_login_database_error_does_not_authenticate_or_expose_details(self):
        self.cursor.execute.side_effect = mysql.connector.Error("private DB details")
        with self.assertLogs(app.logger, level="ERROR"):
            response = self.login()
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("private DB details", response.get_data(as_text=True))
        self.assert_no_authenticated_session()
        self.connection.__exit__.assert_called_once()

    def test_pages_render_without_client_side_demo_passwords(self):
        registration_page = self.client.get("/")
        login_page = self.client.get("/login")
        self.assertEqual(registration_page.status_code, 200)
        self.assertEqual(login_page.status_code, 200)
        self.assertIn(b'action="/user_register"', registration_page.data)
        self.assertIn(b'action="/user_login"', login_page.data)
        self.assertNotIn(b"demoAccounts", login_page.data)
        self.assertNotIn(b"admin123", login_page.data)
        self.assertNotIn(b"user123", login_page.data)
        self.connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
