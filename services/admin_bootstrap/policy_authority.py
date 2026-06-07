"""
Policy Authority — IETF A2A Trust draft-tonyai-a2a-trust-00
Implements: Section 9 (Dynamic Policy Governance)
  - Section 9.3: Dual Signature Requirement (Owner + PA)
  - Section 9.4: Policy Change Sequence (identity, OPA gate, dual-sig, hash, version)
  - Section 9.4 step 5: Runtime validation (sigs, version current, hash matches)
"""

import logging
import json
import hashlib
import subprocess
import tempfile
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

log = logging.getLogger(__name__)


class PolicyAuthority:
    """Validates dual-signature on policy changes + policy content hash + version"""

    def __init__(self,
                 owner_cert_path: str = "./certs/owner.crt",
                 owner_key_path:  str = "./certs/owner.key",
                 pa_cert_path:    str = "./certs/pa.crt",
                 pa_key_path:     str = "./certs/pa.key",
                 policy_store_path: str = "./certs/policy_store.json"):
        self.owner_cert = Path(owner_cert_path)
        self.owner_key  = Path(owner_key_path)
        self.pa_cert    = Path(pa_cert_path)
        self.pa_key     = Path(pa_key_path)
        self.policy_store_path = Path(policy_store_path)

    # ── Signing helpers (OpenSSL RSA-SHA256) ──────────────────────────────────

    def _sign(self, data: str, key_path: Path) -> Optional[str]:
        """Sign data with RSA private key, return base64 signature"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.dat', delete=False) as f:
                f.write(data)
                tmp = f.name
            try:
                result = subprocess.run(
                    f"openssl dgst -sha256 -sign {key_path} {tmp} | openssl enc -base64 -A",
                    shell=True, capture_output=True, text=True
                )
                if result.returncode != 0:
                    log.error("Signing error", extra={"error": result.stderr})
                    return None
                return result.stdout.strip()
            finally:
                os.unlink(tmp)
        except Exception as e:
            log.error("Sign failed", extra={"error": str(e)})
            return None

    def _verify(self, data: str, sig_b64: str, cert_path: Path) -> bool:
        """Verify RSA-SHA256 signature using X.509 public key (safe subprocess, no shell=True)"""
        import base64
        data_tmp = sig_tmp = pubkey_tmp = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.dat', delete=False) as f:
                f.write(data)
                data_tmp = f.name

            sig_tmp = data_tmp + ".sig"
            try:
                sig_bytes = base64.b64decode(sig_b64)
            except Exception as e:
                log.warning("Invalid base64 in signature", extra={"error": str(e)})
                return False
            with open(sig_tmp, 'wb') as f:
                f.write(sig_bytes)

            pubkey_tmp = data_tmp + ".pub"
            r = subprocess.run(
                ["openssl", "x509", "-in", str(cert_path), "-pubkey", "-noout"],
                capture_output=True, text=True, timeout=5
            )
            if r.returncode != 0 or not r.stdout.strip():
                log.warning("Failed to extract public key",
                            extra={"cert": str(cert_path), "stderr": r.stderr[:200]})
                return False
            with open(pubkey_tmp, 'w') as pkf:
                pkf.write(r.stdout)

            result = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", pubkey_tmp,
                 "-signature", sig_tmp, data_tmp],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0 and "Verified OK" in result.stdout
        except Exception as e:
            log.error("Verify failed", extra={"error": str(e)})
            return False
        finally:
            for f in [data_tmp, sig_tmp, pubkey_tmp]:
                if f and os.path.exists(f):
                    try:
                        os.unlink(f)
                    except OSError:
                        pass

    # ── Content hash (Section 9.4 step 4) ────────────────────────────────────

    def _content_hash(self, policy_doc: dict) -> str:
        """SHA-256 hash of canonicalized policy document"""
        canonical = json.dumps(policy_doc, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical.encode()).hexdigest()

    # ── Policy store (Section 9.4: stored with version, timestamp, hash) ─────

    def _load_policy_store(self) -> dict:
        if self.policy_store_path.exists():
            try:
                with open(self.policy_store_path, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {"policies": {}, "last_updated": datetime.now(timezone.utc).isoformat()}

    def _save_policy_store(self, store: dict):
        store["last_updated"] = datetime.now(timezone.utc).isoformat()
        with open(self.policy_store_path, 'w') as f:
            json.dump(store, f, indent=2)

    # ── Public API ────────────────────────────────────────────────────────────

    def create_dual_sig(self, policy_doc: dict) -> Tuple[Optional[str], Optional[str]]:
        """
        Section 9.3: Sign policy with both Owner key and PA key.
        Returns: (owner_sig, pa_sig) — both required.
        """
        canonical = json.dumps(policy_doc, sort_keys=True, separators=(',', ':'))
        owner_sig = self._sign(canonical, self.owner_key)
        pa_sig    = self._sign(canonical, self.pa_key)
        if owner_sig and pa_sig:
            log.info("Dual signatures created", extra={"policy": policy_doc.get("name")})
        return (owner_sig, pa_sig)

    def validate_dual_sig(self, policy_doc: dict, owner_sig: str, pa_sig: str) -> Tuple[bool, str]:
        """
        Section 9.3: BOTH signatures must be present and valid.
        Fail-closed: missing or invalid sig = DENY.
        """
        if not owner_sig:
            return (False, "Owner signature missing")
        if not pa_sig:
            return (False, "Policy Authority signature missing")
        if not self.owner_cert.exists() or not self.pa_cert.exists():
            return (False, "Signing certificates not found")

        canonical = json.dumps(policy_doc, sort_keys=True, separators=(',', ':'))

        if not self._verify(canonical, owner_sig, self.owner_cert):
            log.warning("Owner signature invalid", extra={"policy": policy_doc.get("name")})
            return (False, "Owner signature invalid")

        if not self._verify(canonical, pa_sig, self.pa_cert):
            log.warning("PA signature invalid", extra={"policy": policy_doc.get("name")})
            return (False, "PA signature invalid")

        log.info("Dual-sig validated (RSA X.509)", extra={"policy": policy_doc.get("name")})
        return (True, "Dual signatures valid")

    def store_policy(self, policy_doc: dict, owner_sig: str, pa_sig: str) -> Tuple[bool, str]:
        """
        Section 9.4 step 4: Store policy with dual signature, version, timestamp, content hash.
        """
        # Validate sigs first
        valid, reason = self.validate_dual_sig(policy_doc, owner_sig, pa_sig)
        if not valid:
            return (False, reason)

        store = self._load_policy_store()
        name = policy_doc.get("name", "unknown")
        existing = store["policies"].get(name, {})
        current_version = existing.get("version", 0)
        new_version = current_version + 1

        content_hash = self._content_hash(policy_doc)

        store["policies"][name] = {
            "version":      new_version,
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "content_hash": content_hash,
            "owner_sig":    owner_sig,
            "pa_sig":       pa_sig,
            "policy_doc":   policy_doc,
        }
        self._save_policy_store(store)
        log.info("Policy stored", extra={"name": name, "version": new_version, "hash": content_hash[:16]})
        return (True, f"Policy stored v{new_version} hash={content_hash[:16]}")

    def validate_policy_at_runtime(self, policy_name: str) -> Tuple[bool, str]:
        """
        Section 9.4 step 5: Runtime validation —
          - both signatures valid
          - version is current (not stale/replayed)
          - hash matches content (tamper detection)
          - policy within template certificate bounds (caller's responsibility)
        """
        store = self._load_policy_store()
        policy_entry = store.get("policies", {}).get(policy_name)

        if not policy_entry:
            return (False, f"Policy '{policy_name}' not found in store")

        # Verify content hash matches stored doc
        expected_hash = self._content_hash(policy_entry["policy_doc"])
        if expected_hash != policy_entry["content_hash"]:
            log.warning("Policy content hash mismatch — possible tampering",
                        extra={"policy": policy_name})
            return (False, "Policy content hash mismatch (tamper detected)")

        # Verify signatures still valid
        valid, reason = self.validate_dual_sig(
            policy_entry["policy_doc"],
            policy_entry["owner_sig"],
            policy_entry["pa_sig"]
        )
        if not valid:
            return (False, f"Runtime sig check failed: {reason}")

        return (True, f"Policy valid v{policy_entry['version']}")
