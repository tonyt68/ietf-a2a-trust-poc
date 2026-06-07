"""
Policy Authority Validation — IETF A2A Trust draft-tonyai-a2a-trust-00
Implements: Section 9.3 (Dual-Signature Requirement)

TWO-PHASE SIGNATURE ARCHITECTURE:
  Phase 1 — Owner signature covers CERT IDENTITY fields only (immutable section).
             Proves the cert has not been tampered with.
  Phase 2 — If owner_sig(identity) is valid, Policy Authority signs POLICY fields only.
             Proves the policy update is authorized.
             Cert is then re-signed with updated policy section.

This means:
  - CA creates cert with identity + policy sections
  - owner_sig = RSA-SHA256(canonical(identity fields))
  - pa_sig    = RSA-SHA256(canonical(policy fields))
  - To update policy: verify owner_sig(identity unchanged) AND pa_sig(policy authorized)
  - Both valid → apply policy update, re-sign cert
  - Either invalid → DENIED, cert unchanged

Prevents:
  - Unauthorized identity modification (owner_sig must still verify)
  - Unauthorized policy modification (pa_sig required for any policy change)
  - Single-key compromise (both Owner and PA required)
"""

import logging
import json
import subprocess
import tempfile
import os
from typing import Tuple, Optional
from pathlib import Path
from policy_authority_chain import PolicyAuthorityChainValidator
from policy_field_guard import PolicyFieldGuard

log = logging.getLogger(__name__)

# Canonical field sets — mirrors PolicyFieldGuard
IDENTITY_FIELDS = {
    "agent_id", "agent_uuid", "org_id", "subject", "issuer",
    "owner", "cert_serial", "cert_subject", "cert_issuer",
    "cert_public_key", "cert_not_before", "cert_not_after",
    "cert_fingerprint", "cert_chain", "template_version",
    "can_spawn",        # Permitted child template UUIDs — immutable, new cert required (§8.1)
    "max_children",     # Structural spawn bound — immutable, new cert required
}

POLICY_FIELDS = {
    "allowed_scopes",   # Dynamic scope grants — updatable via dual-signed policy update
    "scope_inherit",    # Inheritance rules
    "policy_ref",       # Reference policy version
    "ttl_seconds",      # TTL override
    "owner",            # Policy owner — MUST match PolicyFieldGuard.MODIFIABLE_POLICY_FIELDS
    "created_at",       # Policy creation timestamp
    "updated_at",       # Policy update timestamp
    "description",      # Human-readable description
    "tags",             # Metadata tags
    "conditions",       # Dynamic conditions (Cedar evaluates)
}


class PolicyValidator:
    """
    Two-phase signature validation:
      Phase 1: owner_sig covers cert identity fields (proves identity unchanged)
      Phase 2: pa_sig covers policy fields (authorizes policy update)
    """

    def __init__(self, owner_cert_path: str = "./certs/owner.crt",
                 pa_cert_path: str = "./certs/pa.crt",
                 ca_root_path: str = "./certs/ca-root.crt",
                 revocation_list_path: str = "./certs/revocation_list.json"):
        self.owner_cert_path = Path(owner_cert_path)
        self.pa_cert_path = Path(pa_cert_path)
        self.chain_validator = PolicyAuthorityChainValidator(ca_root_path, revocation_list_path)
        self.field_guard = PolicyFieldGuard()

    def _canonical(self, fields: dict) -> str:
        """Deterministic JSON serialization for signing."""
        return json.dumps(fields, sort_keys=True, separators=(',', ':'))

    def _extract_identity_fields(self, cert_or_doc: dict) -> dict:
        """Extract only identity fields from a cert/doc for Phase 1 signing."""
        return {k: v for k, v in cert_or_doc.items() if k in IDENTITY_FIELDS}

    def _extract_policy_fields(self, cert_or_doc: dict) -> dict:
        """Extract only policy fields from a cert/doc for Phase 2 signing."""
        return {k: v for k, v in cert_or_doc.items() if k in POLICY_FIELDS}

    def _verify_rsa_signature(self, data: str, signature_b64: str, cert_path: Path) -> bool:
        """Verify RSA-SHA256 signature using OpenSSL."""
        import base64

        data_file = None
        sig_file = None
        pubkey_file = None

        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.dat', delete=False) as f:
                f.write(data)
                data_file = f.name

            sig_file = data_file + ".sig"
            try:
                sig_bytes = base64.b64decode(signature_b64)
            except Exception as e:
                log.warning("Invalid base64 encoding in signature", extra={"error": str(e)})
                return False
            with open(sig_file, 'wb') as f:
                f.write(sig_bytes)

            pubkey_file = data_file + ".pub"
            result = subprocess.run(
                ["openssl", "x509", "-in", str(cert_path), "-pubkey", "-noout"],
                capture_output=True, text=True, timeout=5
            )

            if result.returncode != 0 or not result.stdout.strip():
                log.warning("Failed to extract public key",
                            extra={"cert": str(cert_path), "stderr": result.stderr[:200]})
                return False

            with open(pubkey_file, 'w') as pkf:
                pkf.write(result.stdout)

            result = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", pubkey_file,
                 "-signature", sig_file, data_file],
                capture_output=True, text=True, timeout=5
            )

            verified = result.returncode == 0 and "Verified OK" in result.stdout
            if not verified:
                log.warning("RSA signature verification failed",
                            extra={"cert": str(cert_path), "stderr": result.stderr})
            return verified

        except Exception as e:
            log.error("RSA verification error", extra={"error": str(e)})
            return False
        finally:
            for f in [data_file, sig_file, pubkey_file]:
                if f and os.path.exists(f):
                    try:
                        os.unlink(f)
                    except OSError as e:
                        log.debug(f"Could not cleanup temp file {f}", extra={"error": str(e)})

    def validate_policy_update(self, event_data: dict) -> Tuple[bool, str]:
        """
        Two-phase signature validation for policy updates.

        Phase 1: owner_sig must verify against cert IDENTITY fields
                 → proves cert identity has not been tampered with
        Phase 2: pa_sig must verify against POLICY fields only
                 → authorizes the specific policy update
        Both must pass — fail-closed on any failure.
        """
        if "policy_update" not in event_data:
            return (True, "Not a policy update")

        policy_doc = event_data.get("policy_doc")
        owner_sig  = event_data.get("owner_sig")
        pa_sig     = event_data.get("pa_sig")

        # 1. Presence checks (fail-closed)
        if not policy_doc:
            return (False, "Policy document missing")
        if not owner_sig:
            log.warning("Owner signature missing — Phase 1 cannot proceed (Section 9.3)")
            return (False, "Owner signature missing — cert identity cannot be verified (Section 9.3)")
        if not pa_sig:
            log.warning("PA signature missing — Phase 2 cannot proceed (Section 9.3)")
            return (False, "Policy Authority signature missing — policy update not authorized (Section 9.3)")

        # 2. Field guard — policy_doc must contain ONLY policy fields, never identity fields
        guard_valid, guard_reason = self.field_guard.validate_policy_update({}, policy_doc)
        if not guard_valid:
            log.warning("Policy field guard rejected update", extra={"reason": guard_reason})
            return (False, guard_reason)

        # 3. Chain of custody — both signing authorities must be legitimate
        owner_chain_valid, owner_chain_reason = self.chain_validator.validate_policy_authority_chain(
            self.owner_cert_path, "Owner Authority"
        )
        if not owner_chain_valid:
            return (False, owner_chain_reason)

        pa_chain_valid, pa_chain_reason = self.chain_validator.validate_policy_authority_chain(
            self.pa_cert_path, "Policy Authority"
        )
        if not pa_chain_valid:
            return (False, pa_chain_reason)

        # 4. PHASE 1: Owner signature covers the IDENTITY fields from the existing cert
        #    This proves the cert identity has NOT been modified
        existing_cert = event_data.get("existing_cert", {})
        identity_section = self._extract_identity_fields(existing_cert)

        if not identity_section:
            log.warning("No existing cert identity provided for Phase 1 verification")
            return (False, "Existing cert identity required for Phase 1 owner signature verification")

        canonical_identity = self._canonical(identity_section)
        owner_valid = self._verify_rsa_signature(canonical_identity, owner_sig, self.owner_cert_path)
        if not owner_valid:
            log.warning("Phase 1 FAILED — owner signature does not match cert identity fields (Section 9.3)")
            return (False, "Phase 1 failed: owner signature invalid over cert identity fields (Section 9.3)")

        # 5. PHASE 2: PA signature covers the POLICY fields being updated
        #    This authorizes the specific policy changes
        policy_section = self._extract_policy_fields(policy_doc)
        canonical_policy = self._canonical(policy_section)
        pa_valid = self._verify_rsa_signature(canonical_policy, pa_sig, self.pa_cert_path)
        if not pa_valid:
            log.warning("Phase 2 FAILED — PA signature does not match policy fields (Section 9.3)")
            return (False, "Phase 2 failed: PA signature invalid over policy fields (Section 9.3)")

        log.info(
            "Two-phase signature validation passed — cert identity verified, policy update authorized",
            extra={"policy_fields": list(policy_section.keys())}
        )
        return (True, "Two-phase validation passed: identity verified (Phase 1) + policy authorized (Phase 2)")
