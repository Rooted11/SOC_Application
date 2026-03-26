import os
import tempfile
import unittest
from pathlib import Path


DB_FILE = Path(tempfile.gettempdir()) / "ai_soc_test.db"
if DB_FILE.exists():
    DB_FILE.unlink()

os.environ["DATABASE_URL"] = f"sqlite:///{DB_FILE.as_posix()}"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.services.database import SessionLocal, init_db  # noqa: E402
from app.services.threat_intel import ThreatIntelService  # noqa: E402


def setUpModule():
    init_db()


def tearDownModule():
    if DB_FILE.exists():
        DB_FILE.unlink()


class ApiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def test_health_endpoint(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")

    def test_assets_endpoint_returns_summary(self):
        response = self.client.get("/api/assets")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("summary", payload)
        self.assertIn("assets", payload)
        self.assertGreaterEqual(payload["summary"]["total"], 1)

    def test_overview_endpoint_returns_headline(self):
        response = self.client.get("/api/overview")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("headline", payload)
        self.assertIn("response", payload)
        self.assertIn("assets", payload)

    def test_ai_query_fallback(self):
        ingest = self.client.post(
            "/api/logs/ingest",
            json={
                "logs": [
                    {
                        "source": "auth",
                        "log_level": "critical",
                        "message": "Multiple failed logins from 203.0.113.88 for user admin",
                        "ip_src": "203.0.113.88",
                        "ip_dst": "10.0.1.5",
                        "user": "admin",
                        "event_type": "auth_failure",
                        "raw_data": {"dst_port": 22},
                    }
                ]
            },
        )
        self.assertEqual(ingest.status_code, 200)
        incident_id = ingest.json()["results"][0]["incident_id"]
        self.assertIsNotNone(incident_id)

        response = self.client.post(
            "/api/ai/query",
            json={"incident_id": incident_id, "query": "Give me a containment plan"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("response", response.json())


class ThreatIntelCacheTests(unittest.TestCase):
    def test_cached_indicator_survives_session_commit(self):
        service = ThreatIntelService()

        db = SessionLocal()
        try:
            service.load_from_file(db)
        finally:
            db.close()

        db = SessionLocal()
        try:
            matches = service.correlate_log(
                db,
                {
                    "ip_src": "203.0.113.88",
                    "ip_dst": "10.0.1.5",
                    "user": "admin",
                    "raw_data": {},
                },
            )
        finally:
            db.close()

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["value"], "203.0.113.88")
        self.assertEqual(matches[0]["ioc_type"], "ip")


if __name__ == "__main__":
    unittest.main()
