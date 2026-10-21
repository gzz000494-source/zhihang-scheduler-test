"""Isolated scheduler-trigger contract model. NOT production authentication code."""

import hashlib
import hmac
import unittest


ALLOWED_TASKS = {"health_check"}


def signature_for(secret: str, timestamp: int, nonce: str, task: str) -> str:
    message = f"{timestamp}\n{nonce}\n{task}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def verify_request(
    *,
    secret: str,
    timestamp: int,
    nonce: str,
    task: str,
    signature: str,
    now: int,
    seen_nonces: set[str],
    max_skew_seconds: int = 300,
) -> bool:
    """Simulate a narrow allowlist, freshness, signature, and replay check."""
    if task not in ALLOWED_TASKS or not nonce:
        return False
    if abs(now - timestamp) > max_skew_seconds:
        return False
    expected = signature_for(secret, timestamp, nonce, task)
    if not hmac.compare_digest(expected, signature):
        return False
    if nonce in seen_nonces:
        return False
    seen_nonces.add(nonce)
    return True


class SchedulerContractTests(unittest.TestCase):
    def setUp(self):
        self.secret = "test-only-not-a-real-secret"
        self.now = 1_800_000_000
        self.nonce = "test-request-001"
        self.task = "health_check"
        self.seen = set()

    def call(self, *, timestamp=None, nonce=None, task=None, signature=None):
        timestamp = self.now if timestamp is None else timestamp
        nonce = self.nonce if nonce is None else nonce
        task = self.task if task is None else task
        signature = (
            signature_for(self.secret, timestamp, nonce, task)
            if signature is None
            else signature
        )
        return verify_request(
            secret=self.secret,
            timestamp=timestamp,
            nonce=nonce,
            task=task,
            signature=signature,
            now=self.now,
            seen_nonces=self.seen,
        )

    def test_valid_allowlisted_request_is_accepted_once(self):
        self.assertTrue(self.call())
        self.assertFalse(self.call())

    def test_bad_signature_is_rejected(self):
        self.assertFalse(self.call(signature="0" * 64))
        self.assertEqual(self.seen, set())

    def test_stale_timestamp_is_rejected(self):
        self.assertFalse(self.call(timestamp=self.now - 301))
        self.assertEqual(self.seen, set())

    def test_unapproved_task_is_rejected(self):
        self.assertFalse(self.call(task="run_production_scheduler"))
        self.assertEqual(self.seen, set())

    def test_replayed_nonce_is_rejected(self):
        self.assertTrue(self.call())
        self.assertFalse(self.call(nonce=self.nonce))


if __name__ == "__main__":
    unittest.main(verbosity=2)
