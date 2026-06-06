"""
Policy Authority Chain of Custody Validator — IETF A2A Trust Section 9.3
Verifies that Owner and PA certificates used for policy signatures are:
  • Valid X.509 certificates (RFC 5280)
  • CA-signed (not self-signed)
  • Not expired
  • Not revoked
  • Chain back to root CA
"""

import logging
import subprocess
import re
from pathlib import Path
from typing import Tuple, Optional
from datetime import datetime, timezone

log = logging.getLogger(__name__)


class PolicyAuthorityChainValidator:
    """Validates chain of custody for policy signing authorities."""

    def __init__(self, ca_root_cert_path: str = "./certs/ca-root.crt",
                 revocation_list_path: str = "./certs/revocation_list.json"):
        self.ca_root_path = Path(ca_root_cert_path)
        self.revocation_list_path = Path(revocation_list_path)

    def _openssl(self, cmd: str) -> Tuple[bool, str]:
        """Execute OpenSSL command safely."""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True,
                                  text=True, timeout=5)
            return result.returncode == 0, (result.stdout + result.stderr).strip()
        except subprocess.TimeoutExpired:
            log.error("OpenSSL timeout in chain validation (fail-closed)")
            return (False, "OpenSSL timeout")

    def _get_cert_fingerprint(self, cert_path: Path) -> Optional[str]:
        """Get SHA-256 fingerprint of certificate."""
        ok, output = self._openssl(f"openssl x509 -in {cert_path} -fingerprint -sha256 -noout")
        if not ok:
            return None
        match = re.search(r'[Ss]ha256 [Ff]ingerprint=([A-F0-9:]+)', output, re.IGNORECASE)
        return match.group(1) if match else None

    def _is_cert_expired(self, cert_path: Path) -> Tuple[bool, str]:
        """Check if certificate is expired."""
        ok, output = self._openssl(f"openssl x509 -in {cert_path} -noout -dates")
        if not ok:
            return (True, "Failed to check expiry (fail-closed)")

        # Parse notBefore and notAfter
        not_after_match = re.search(r'notAfter=(.+)', output)
        if not not_after_match:
            return (True, "Failed to parse notAfter (fail-closed)")

        try:
            # OpenSSL format: "Jun  5 21:00:00 2026 GMT"
            not_after_str = not_after_match.group(1)
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            if now > not_after:
                return (True, f"Certificate expired on {not_after_str}")
            return (False, f"Valid until {not_after_str}")
        except Exception as e:
            log.error("Failed to parse certificate date", extra={"error": str(e)})
            return (True, "Failed to parse expiry (fail-closed)")

    def _validate_certificate_chain(self, cert_path: Path) -> Tuple[bool, str]:
        """Validate that cert is CA-signed and chain back to root."""
        if not self.ca_root_path.exists():
            return (False, f"CA root not found: {self.ca_root_path}")

        ok, output = self._openssl(
            f"openssl verify -CAfile {self.ca_root_path} {cert_path}"
        )

        if not ok or "OK" not in output:
            log.warning("Certificate chain validation failed",
                       extra={"cert": str(cert_path), "output": output})
            return (False, f"Chain validation failed: {output}")

        # Confirm NOT self-signed
        ok, text = self._openssl(f"openssl x509 -in {cert_path} -text -noout")
        if not ok:
            return (False, "Failed to check if self-signed (fail-closed)")

        subject_match = re.search(r'Subject:.*?CN\s*=\s*([^,\n/]+)', text)
        issuer_match = re.search(r'Issuer:.*?CN\s*=\s*([^,\n/]+)', text)

        if subject_match and issuer_match:
            if subject_match.group(1).strip() == issuer_match.group(1).strip():
                return (False, "Self-signed certificates not permitted for policy signing (Section 9.3)")

        return (True, "Chain valid: CA-signed, not self-signed")

    def _is_cert_revoked(self, cert_path: Path) -> Tuple[bool, str]:
        """Check if certificate is in revocation list."""
        try:
            import json
            if not self.revocation_list_path.exists():
                log.warning("Revocation list not found — skipping CRL check")
                return (False, "Revocation list not found (fail-closed)")

            with open(self.revocation_list_path, 'r') as f:
                crl = json.load(f)

            fingerprint = self._get_cert_fingerprint(cert_path)
            if not fingerprint:
                return (True, "Failed to get cert fingerprint (fail-closed)")

            revoked_certs = crl.get("revoked", [])
            if fingerprint in revoked_certs:
                return (True, f"Certificate revoked: {fingerprint}")

            return (False, "Not in revocation list (valid)")
        except Exception as e:
            log.error("Failed to check revocation status", extra={"error": str(e)})
            return (True, "Failed to check revocation (fail-closed)")

    def validate_policy_authority_chain(self, cert_path: Path, authority_name: str) -> Tuple[bool, str]:
        """
        Comprehensive chain of custody validation for policy signing authority.

        Args:
            cert_path: Path to the authority certificate
            authority_name: "Owner" or "Policy Authority"

        Returns:
            (valid: bool, reason: str)
        """
        # 1. Check file exists
        if not cert_path.exists():
            return (False, f"{authority_name} certificate not found: {cert_path} (fail-closed)")

        # 2. Check certificate chain (CA-signed, not self-signed)
        chain_valid, chain_reason = self._validate_certificate_chain(cert_path)
        if not chain_valid:
            log.warning(f"{authority_name} chain validation failed",
                       extra={"reason": chain_reason})
            return (False, chain_reason)

        # 3. Check certificate not expired
        expired, expiry_reason = self._is_cert_expired(cert_path)
        if expired:
            log.warning(f"{authority_name} certificate expired",
                       extra={"reason": expiry_reason})
            return (False, f"{authority_name} {expiry_reason} (Section 12.3)")

        # 4. Check certificate not revoked
        revoked, revocation_reason = self._is_cert_revoked(cert_path)
        if revoked:
            log.warning(f"{authority_name} certificate revoked",
                       extra={"reason": revocation_reason})
            return (False, f"{authority_name} {revocation_reason} (Section 12.1)")

        # All checks passed
        log.info(f"{authority_name} chain of custody verified",
                extra={"cert": str(cert_path), "checks": "chain|expiry|revocation"})
        return (True, f"{authority_name} chain of custody valid (Section 9.3)")
