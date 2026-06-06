import hmac
import hashlib
import json
import logging
from typing import Optional

log = logging.getLogger(__name__)


class HMACVerifier:
    """Verifies HMAC-SHA256 message integrity (Agent A → Agent B)"""

    def __init__(self, hmac_secret: str):
        self.secret = hmac_secret.encode('utf-8')

    def compute(self, payload: str) -> str:
        """Compute HMAC-SHA256 for payload"""
        if isinstance(payload, dict):
            payload = json.dumps(payload, sort_keys=True)

        return hmac.new(
            self.secret,
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

    def verify(self, payload: str, provided_hmac: str) -> bool:
        """
        Verify HMAC signature.
        Returns: True if valid, False otherwise.
        Fail-closed: any mismatch = invalid
        """
        try:
            computed = self.compute(payload)

            # Constant-time comparison (prevent timing attacks)
            if hmac.compare_digest(computed, provided_hmac):
                log.info("HMAC verified")
                return True
            else:
                log.warning("HMAC mismatch")
                return False

        except Exception as e:
            log.error("HMAC verification error", extra={"error": str(e)})
            return False
