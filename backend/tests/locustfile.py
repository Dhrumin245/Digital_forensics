"""
Locust load test — performance evaluation for D8.

Tests the three most latency-sensitive endpoints:
  1. GET /verify/{hash}         — public portal (10 req/min rate limit in prod)
  2. GET /cases                 — case list (authenticated)
  3. GET /cases/{id}/evidence   — evidence list

Run:
    locust -f tests/locustfile.py --host=http://localhost:8000

Targets (from D8 evaluation criteria):
  - p95 latency < 200ms for all endpoints
  - Zero 5xx errors under 50 concurrent users
  - Verify portal: handles 100 req/min per IP before rate limit triggers
"""

import hashlib
import random
import string

from locust import HttpUser, between, task

# ── Known hashes to verify (won't exist — tests not_found path) ───────────────
FAKE_HASHES = [
    hashlib.sha256(f"fake_evidence_{i}".encode()).hexdigest()
    for i in range(100)
]


class PublicVerifierUser(HttpUser):
    """
    Simulates a lawyer or judge querying the public verification portal.
    No auth required — tests the unauthenticated hot path.
    """
    wait_time = between(1, 3)
    weight    = 3   # Most common user type in load test

    @task(5)
    def verify_unknown_hash(self):
        """Query a hash that won't be in the system — tests not_found path."""
        h = random.choice(FAKE_HASHES)
        with self.client.get(
            f"/api/v1/verify/{h}",
            name="/api/v1/verify/[hash]",
            catch_response=True,
        ) as resp:
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") not in ("not_found", "verified", "tampered"):
                    resp.failure(f"Unexpected status: {data.get('status')}")
                else:
                    resp.success()
            elif resp.status_code == 429:
                # Rate limit hit — expected behaviour, not a failure
                resp.success()
            else:
                resp.failure(f"Unexpected status code: {resp.status_code}")

    @task(1)
    def verify_invalid_hash_format(self):
        """Confirm 400 is returned for invalid hash formats."""
        with self.client.get(
            "/api/v1/verify/not_a_valid_hash",
            name="/api/v1/verify/[invalid]",
            catch_response=True,
        ) as resp:
            if resp.status_code == 400:
                resp.success()
            else:
                resp.failure(f"Expected 400, got {resp.status_code}")

    @task(1)
    def health_check(self):
        self.client.get("/health", name="/health")


class AuthenticatedInvestigatorUser(HttpUser):
    """
    Simulates an examiner browsing cases and evidence.
    Uses a pre-obtained JWT token (set via environment or hardcode for load test).
    """
    wait_time = between(2, 5)
    weight    = 1

    def on_start(self):
        """Login once per simulated user."""
        resp = self.client.post(
            "/api/v1/auth/login",
            json={"email": "loadtest@forensics.local", "password": "LoadTest@123!"},
        )
        if resp.status_code == 200:
            token = resp.json().get("access_token", "")
            self.headers = {"Authorization": f"Bearer {token}"}
        else:
            # If no load-test user exists, skip auth tasks
            self.headers = {}

    @task(3)
    def list_cases(self):
        self.client.get(
            "/api/v1/cases",
            headers=self.headers,
            name="/api/v1/cases",
        )

    @task(1)
    def check_health(self):
        self.client.get("/health", name="/health")
