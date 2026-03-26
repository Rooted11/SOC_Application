import unittest
from contextlib import contextmanager

from fastapi.testclient import TestClient

from app.main import app
from app.services.config import settings
from app.services.rate_limit import InMemoryRateLimiter, login_rate_limiter
from app.services.security import (
    InvalidTokenError,
    create_access_token,
    generate_totp_code,
    verify_access_token,
    verify_totp_code,
)


@contextmanager
def override_settings(**overrides):
    original_values = {name: getattr(settings, name) for name in overrides}
    try:
        for name, value in overrides.items():
            object.__setattr__(settings, name, value)
        yield
    finally:
        for name, value in original_values.items():
            object.__setattr__(settings, name, value)


class SecurityTokenTests(unittest.TestCase):
    def test_access_token_round_trip(self):
        token = create_access_token("analyst", mfa_authenticated=True)
        user = verify_access_token(token)
        self.assertEqual(user.username, "analyst")
        self.assertTrue(user.mfa_authenticated)

    def test_tampered_token_is_rejected(self):
        token = create_access_token("analyst")
        tampered = f"{token}tamper"
        with self.assertRaises(InvalidTokenError):
            verify_access_token(tampered)

    def test_totp_code_round_trip(self):
        secret = "JBSWY3DPEHPK3PXP"
        code = generate_totp_code(secret, for_time=1_700_000_000)
        self.assertTrue(verify_totp_code(secret, code, now=1_700_000_000))
        self.assertFalse(verify_totp_code(secret, "000000", now=1_700_000_000))


class RateLimiterTests(unittest.TestCase):
    def test_rate_limiter_blocks_after_limit(self):
        limiter = InMemoryRateLimiter()

        allowed_one = limiter.check("client-a", limit=2, window_seconds=60)
        allowed_two = limiter.check("client-a", limit=2, window_seconds=60)
        blocked = limiter.check("client-a", limit=2, window_seconds=60)

        self.assertTrue(allowed_one.allowed)
        self.assertTrue(allowed_two.allowed)
        self.assertFalse(blocked.allowed)
        self.assertGreaterEqual(blocked.retry_after_seconds, 1)


class AuthRouteTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()

    def test_login_requires_totp_when_mfa_enabled(self):
        with override_settings(
            auth_enabled=True,
            auth_username="publicops",
            auth_password="StrongPass123!",
            auth_mfa_enabled=True,
            auth_totp_secret="JBSWY3DPEHPK3PXP",
            auth_token_secret="test-token-secret",
            rate_limit_enabled=False,
        ):
            without_code = self.client.post(
                "/api/auth/login",
                json={"username": "publicops", "password": "StrongPass123!"},
            )
            self.assertEqual(without_code.status_code, 401)

            otp_code = generate_totp_code("JBSWY3DPEHPK3PXP")
            with_code = self.client.post(
                "/api/auth/login",
                json={
                    "username": "publicops",
                    "password": "StrongPass123!",
                    "otp_code": otp_code,
                },
            )
            self.assertEqual(with_code.status_code, 200)
            self.assertTrue(with_code.json()["mfa_authenticated"])

    def test_login_rate_limit_returns_429(self):
        rate_limit_key = "testclient:rate-limit-user"
        login_rate_limiter.reset(rate_limit_key)

        with override_settings(
            auth_enabled=True,
            auth_username="rate-limit-user",
            auth_password="StrongPass123!",
            auth_mfa_enabled=False,
            auth_totp_secret=None,
            rate_limit_enabled=True,
            login_rate_limit_attempts=1,
            login_rate_limit_window_seconds=300,
        ):
            first = self.client.post(
                "/api/auth/login",
                json={"username": "rate-limit-user", "password": "wrong-password"},
            )
            second = self.client.post(
                "/api/auth/login",
                json={"username": "rate-limit-user", "password": "wrong-password"},
            )

            self.assertEqual(first.status_code, 401)
            self.assertEqual(second.status_code, 429)


if __name__ == "__main__":
    unittest.main()
