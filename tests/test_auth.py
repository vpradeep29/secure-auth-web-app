import os
import tempfile
import unittest
from app import create_app, db
from app.models import AuditLog, User

class TestConfig:
    SECRET_KEY = 'test-only-secret-key'
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = False

class AuthFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        TestConfig.SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(self.temp_dir.name, 'test.db')
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        with self.app.app_context():
            db.create_all()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
        self.temp_dir.cleanup()

    def register(self, email='person@example.com', password='StrongPassword123!'):
        return self.client.post('/register', data={'email': email, 'password': password, 'confirm_password': password})

    def login(self, email='person@example.com', password='StrongPassword123!'):
        return self.client.post('/login', data={'email': email, 'password': password})

    def test_register_hashes_password_and_logs_event(self):
        response = self.register()
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            user = User.query.filter_by(email='person@example.com').one()
            self.assertNotEqual(user.password_hash, 'StrongPassword123!')
            self.assertTrue(user.password_hash.startswith('$argon2'))
            self.assertEqual(AuditLog.query.filter_by(event_type='REGISTRATION').count(), 1)

    def test_login_dashboard_and_logout(self):
        self.register()
        self.assertEqual(self.login().status_code, 302)
        self.assertEqual(self.client.get('/dashboard').status_code, 200)
        self.assertEqual(self.client.post('/logout').status_code, 302)
        self.assertEqual(self.client.get('/dashboard').status_code, 302)
        with self.app.app_context():
            self.assertEqual(AuditLog.query.filter_by(event_type='LOGIN_SUCCESS').count(), 1)
            self.assertEqual(AuditLog.query.filter_by(event_type='LOGOUT').count(), 1)

    def test_wrong_password_fails(self):
        self.register()
        self.assertEqual(self.login(password='WrongPassword123!').status_code, 401)

    def test_admin_route_denies_regular_user(self):
        self.register()
        self.login()
        self.assertEqual(self.client.get('/admin').status_code, 403)

    def test_security_headers_present(self):
        response = self.client.get('/')
        self.assertEqual(response.headers.get('X-Frame-Options'), 'DENY')
        self.assertIn('Content-Security-Policy', response.headers)

if __name__ == '__main__':
    unittest.main()
