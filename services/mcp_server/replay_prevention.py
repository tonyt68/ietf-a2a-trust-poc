"""Replay attack prevention for IETF A2A Trust (timestamp + nonce validation)"""

import fcntl
import logging
import json
import uuid
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Tuple

log = logging.getLogger(__name__)


class ReplayPrevention:
    """Tracks nonces and validates timestamps to prevent replay attacks"""

    def __init__(self, nonce_tracker_path: str = "./certs/nonce_tracker.json"):
        self.tracker_path = Path(nonce_tracker_path)
        self.nonce_ttl_seconds = 300  # 5 minutes
        self.tracker = self._load_tracker()

    def _load_tracker(self) -> dict:
        """Load nonce tracker from disk. On failure, keep existing in-memory state."""
        if self.tracker_path.exists():
            try:
                with open(self.tracker_path, 'r') as f:
                    data = json.load(f)
                    # Validate structure before accepting
                    if isinstance(data, dict) and "used_nonces" in data:
                        return data
                    log.warning("Nonce tracker malformed — keeping in-memory state")
            except Exception as e:
                log.error("Failed to load nonce tracker — keeping in-memory state",
                          extra={"error": str(e)})
        # Return existing in-memory tracker if available, else empty
        return getattr(self, 'tracker', {"used_nonces": [], "last_cleaned": datetime.now(timezone.utc).isoformat()})

    def _save_tracker(self):
        """Persist nonce tracker to disk atomically."""
        try:
            with open(self.tracker_path, 'w') as f:
                json.dump(self.tracker, f, indent=2)
        except Exception as e:
            log.error("Failed to save nonce tracker", extra={"error": str(e)})

    def _cleanup_expired_nonces(self):
        """Remove expired nonces from tracker"""
        try:
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(seconds=self.nonce_ttl_seconds)

            original_count = len(self.tracker["used_nonces"])

            def is_recent(entry):
                ts = datetime.fromisoformat(entry["timestamp"])
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                return ts > cutoff

            self.tracker["used_nonces"] = [
                e for e in self.tracker["used_nonces"] if is_recent(e)
            ]

            removed = original_count - len(self.tracker["used_nonces"])
            if removed > 0:
                log.info("Expired nonces cleaned", extra={"removed": removed})
                self.tracker["last_cleaned"] = datetime.now(timezone.utc).isoformat()
                self._save_tracker()

        except Exception as e:
            log.error("Nonce cleanup error", extra={"error": str(e)})

    def generate_nonce(self) -> str:
        """Generate UUID v7 nonce for client to include in request"""
        # TODO: Update to UUID7 for sortable IDs
        return str(uuid.uuid4())

    def validate_request(self, request_nonce: str, request_timestamp: str) -> Tuple[bool, str]:
        """
        Validate request freshness and nonce uniqueness.
        File-locked to prevent race conditions (TOCTOU) under concurrent requests.
        Returns: (valid: bool, reason: str)
        """
        try:
            # Parse timestamp
            try:
                req_time = datetime.fromisoformat(request_timestamp)
                if req_time.tzinfo is None:
                    req_time = req_time.replace(tzinfo=timezone.utc)
            except Exception:
                return (False, "Invalid timestamp format")

            # Check timestamp freshness (must be within 5 minutes)
            now = datetime.now(timezone.utc)
            time_diff = abs((now - req_time).total_seconds())
            if time_diff > self.nonce_ttl_seconds:
                return (False, f"Timestamp out of window: {time_diff:.0f}s > {self.nonce_ttl_seconds}s")

            # Acquire exclusive file lock — prevents TOCTOU race between concurrent requests
            lock_path = self.tracker_path.with_suffix('.lock')
            with open(lock_path, 'a') as lock_file:
                fcntl.flock(lock_file, fcntl.LOCK_EX)
                try:
                    # Re-read from disk while holding lock to get latest state
                    self.tracker = self._load_tracker()
                    self._cleanup_expired_nonces()

                    # Check nonce uniqueness
                    for nonce_entry in self.tracker["used_nonces"]:
                        if nonce_entry["nonce"] == request_nonce:
                            return (False, "Nonce already used (replay attack detected)")

                    # Record nonce as used
                    self.tracker["used_nonces"].append({
                        "nonce": request_nonce,
                        "timestamp": request_timestamp,
                    })
                    self._save_tracker()
                finally:
                    fcntl.flock(lock_file, fcntl.LOCK_UN)

            log.info("Request validated", extra={"nonce": request_nonce[:8]})
            return (True, "Request valid")

        except Exception as e:
            log.error("Replay prevention error", extra={"error": str(e)})
            return (False, str(e))

    def mark_nonce_used(self, nonce: str, agent_id: str, timestamp: str):
        """Mark nonce as used for a specific agent"""
        try:
            for entry in self.tracker["used_nonces"]:
                if entry["nonce"] == nonce:
                    entry["agent_id"] = agent_id
                    self._save_tracker()
                    return
        except Exception as e:
            log.error("Failed to mark nonce used", extra={"error": str(e)})
