"""
Certificate Manager — IETF A2A Trust draft-tonyai-a2a-trust-00
Implements: Section 10 (Template Lifecycle), Section 12 (Revocation),
            Section 10.4 (DISABLED→DELETED waiting period), Section 12.3 (Automation)
"""
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

# Section 10.4: SHOULD enforce mandatory waiting period between DISABLED and DELETED
DISABLED_TO_DELETED_WAIT_SECONDS = 300  # 5 minutes for PoC (production: hours/days)


class CertManager:
    """Manages certificate state and CRL via filesystem (authoritative source of truth)"""

    def __init__(self, certs_dir: str = "./certs"):
        self.certs_dir = Path(certs_dir)
        self.certs_dir.mkdir(parents=True, exist_ok=True)
        self.crl_file = self.certs_dir / "revocation_list.json"
        self.crl = self._load_crl() or {}

    # ===== Certificate Revocation List (CRL) =====

    def _load_crl(self) -> dict:
        """Load CRL from disk. Returns None if file is corrupt — callers must treat None as DENY."""
        if self.crl_file.exists():
            try:
                with open(self.crl_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                log.error("CRL corrupt or unreadable — failing closed", extra={"error": str(e)})
                return None
        return {"revoked": [], "disabled": [], "disabled_at": {}, "last_updated": datetime.now(timezone.utc).isoformat()}

    def _save_crl(self):
        """Persist CRL atomically to disk."""
        try:
            self.crl["last_updated"] = datetime.now(timezone.utc).isoformat()
            tmp = self.crl_file.with_suffix(".tmp")
            with open(tmp, 'w') as f:
                json.dump(self.crl, f, indent=2)
            os.replace(tmp, self.crl_file)
        except Exception as e:
            log.error("Failed to save CRL", extra={"error": str(e)})

    def check_crl(self, agent_id: str) -> bool:
        """
        Full CRL check: revoked + disabled + TTL expiry.
        Section 12: all must be checked. Fail-closed: error = DENY.
        Section 12.3: TTL expiry MUST be fully automated.
        """
        crl = self._load_crl()
        if crl is None:
            log.error("CRL unreadable — failing closed", extra={"agent": agent_id})
            return False
        self.crl = crl

        if agent_id in self.crl.get("revoked", []):
            log.warning("CRL: agent REVOKED", extra={"agent": agent_id})
            return False

        if agent_id in self.crl.get("disabled", []):
            log.warning("CRL: agent DISABLED", extra={"agent": agent_id})
            return False

        meta_file = self.certs_dir / f"{agent_id}.json"
        if meta_file.exists():
            try:
                with open(meta_file, "r") as f:
                    meta = json.load(f)
                expires_at = meta.get("expires_at")
                if expires_at:
                    expiry = datetime.fromisoformat(expires_at)
                    if expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) > expiry:
                        log.warning("CRL: agent TTL EXPIRED", extra={"agent": agent_id})
                        if agent_id not in self.crl.get("revoked", []):
                            self.crl.setdefault("revoked", []).append(agent_id)
                            self._save_crl()
                        return False
            except Exception as e:
                log.error("TTL check error (fail-closed)", extra={"agent": agent_id, "error": str(e)})
                return False

        return True
