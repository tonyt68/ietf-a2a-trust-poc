"""
Policy Authority Validation — IETF A2A Trust draft-tonyai-a2a-trust-00
Implements: Section 9.3 (Dual-Signature Requirement)
            Section 9.3: Chain of custody verification

Enforces that BOTH Owner and Policy Authority must cryptographically sign
any policy update before it can be applied. Single signature is insufficient.
Also validates that Owner and PA certificates are legitimate (not revoked, expired, etc).
"""

import logging
import json
import subprocess
import tempfile
import os
from typing import Tuple, Optional
from pathlib import Path
from policy_authority_chain import PolicyAuthorityChainValidator

log = logging.getLogger(__name__)


class PolicyValidator:
    """Validates policy updates with dual RSA-SHA256 signatures (Owner + PA)"""

    def __init__(self, owner_cert_path: str = "./certs/owner.crt",
                 pa_cert_path: str = "./certs/pa.crt",
                 ca_root_path: str = "./certs/ca-root.crt",
                 revocation_list_path: str = "./certs/revocation_list.json"):
        self.owner_cert_path = Path(owner_cert_path)
        self.pa_cert_path = Path(pa_cert_path)
        self.chain_validator = PolicyAuthorityChainValidator(ca_root_path, revocation_list_path)

    def _verify_rsa_signature(self, data: str, signature_b64: str, cert_path: Path) -> bool:
        """
        Verify RSA-SHA256 signature using OpenSSL.
        data: canonical JSON string
        signature_b64: base64-encoded signature
        cert_path: path to certificate file
        """
        import base64

        data_file = None
        sig_file = None
        pubkey_file = None

        try:
            # Write data to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.dat', delete=False) as f:
                f.write(data)
                data_file = f.name

            # Write signature to temp file (decode base64)
            sig_file = data_file + ".sig"
            try:
                sig_bytes = base64.b64decode(signature_b64)
            except Exception as e:
                log.warning("Invalid base64 encoding in signature", extra={"error": str(e)})
                return False
            with open(sig_file, 'wb') as f:
                f.write(sig_bytes)

            # Extract public key from certificate
            pubkey_file = data_file + ".pub"
            with open(pubkey_file, 'w') as pkf:
                result = subprocess.run(
                    ["openssl", "x509", "-in", str(cert_path), "-pubkey", "-noout"],
                    stdout=pkf,
                    capture_output=False,
                    text=True,
                    timeout=5
                )

            if result.returncode != 0:
                log.warning("Failed to extract public key", extra={"cert": str(cert_path)})
                return False

            # Verify using openssl
            result = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", pubkey_file, "-signature", sig_file, data_file],
                capture_output=True,
                text=True,
                timeout=5
            )

            verified = result.returncode == 0 and "Verified OK" in result.stdout

            if not verified:
                log.warning("RSA signature verification failed",
                           extra={"cert": str(cert_path), "output": result.stdout, "stderr": result.stderr})

            return verified

        except Exception as e:
            log.error("RSA verification error", extra={"error": str(e)})
            return False
        finally:
            # Cleanup temp files
            for f in [data_file, sig_file, pubkey_file]:
                if f and os.path.exists(f):
                    try:
                        os.unlink(f)
                    except OSError as e:
                        log.debug(f"Could not cleanup temp file {f}", extra={"error": str(e)})

    def validate_policy_update(self, event_data: dict) -> Tuple[bool, str]:
        """
        Validate policy update with dual signatures.
        Section 9.3: BOTH Owner and Policy Authority signatures required.

        Returns: (valid: bool, reason: str)
        """
        # Check if this is a policy update
        if "policy_update" not in event_data:
            # Not a policy update, skip validation
            return (True, "Not a policy update")

        policy_doc = event_data.get("policy_doc")
        owner_sig = event_data.get("owner_sig")
        pa_sig = event_data.get("pa_sig")

        # 1. Check both signatures present (fail-closed)
        if not policy_doc:
            return (False, "Policy document missing")

        if not owner_sig:
            log.warning("Policy update missing owner signature (Section 9.3)")
            return (False, "Owner signature missing (Section 9.3)")

        if not pa_sig:
            log.warning("Policy update missing PA signature (Section 9.3)")
            return (False, "PA signature missing (Section 9.3)")

        # 2. Create canonical JSON (deterministic)
        try:
            canonical = json.dumps(policy_doc, sort_keys=True, separators=(',', ':'))
        except Exception as e:
            log.error("Failed to serialize policy document", extra={"error": str(e)})
            return (False, "Policy document serialization error")

        # 2.5. CHAIN OF CUSTODY: Validate Owner and PA certificate integrity (fail-closed)
        owner_chain_valid, owner_chain_reason = self.chain_validator.validate_policy_authority_chain(
            self.owner_cert_path, "Owner Authority"
        )
        if not owner_chain_valid:
            log.warning("Owner certificate chain of custody check failed", extra={"reason": owner_chain_reason})
            return (False, owner_chain_reason)

        pa_chain_valid, pa_chain_reason = self.chain_validator.validate_policy_authority_chain(
            self.pa_cert_path, "Policy Authority"
        )
        if not pa_chain_valid:
            log.warning("PA certificate chain of custody check failed", extra={"reason": pa_chain_reason})
            return (False, pa_chain_reason)

        # 3. Verify Owner signature
        if not self.owner_cert_path.exists():
            log.error("Owner certificate not found", extra={"path": str(self.owner_cert_path)})
            return (False, "Owner certificate not found (fail-closed)")

        owner_valid = self._verify_rsa_signature(canonical, owner_sig, self.owner_cert_path)
        if not owner_valid:
            log.warning("Owner signature verification failed (Section 9.3)")
            return (False, "Owner signature invalid (Section 9.3)")

        # 4. Verify Policy Authority signature
        if not self.pa_cert_path.exists():
            log.error("PA certificate not found", extra={"path": str(self.pa_cert_path)})
            return (False, "PA certificate not found (fail-closed)")

        pa_valid = self._verify_rsa_signature(canonical, pa_sig, self.pa_cert_path)
        if not pa_valid:
            log.warning("PA signature verification failed (Section 9.3)")
            return (False, "PA signature invalid (Section 9.3)")

        # Both signatures valid
        log.info("Policy update authorized by both Owner and PA",
                extra={"policy": policy_doc.get("name")})
        return (True, "Dual-signature validation passed (Section 9.3)")
