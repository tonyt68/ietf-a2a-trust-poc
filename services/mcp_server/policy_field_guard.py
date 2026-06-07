"""
Policy Field Guard — IETF A2A Trust Section 9.3
Enforces strict field boundaries: ONLY policy fields can be modified.
Certificate identity fields are IMMUTABLE (fail-closed design).
"""

import logging
from typing import Tuple, Set
from pathlib import Path
import json

log = logging.getLogger(__name__)


class PolicyFieldGuard:
    """
    Validates that policy updates ONLY modify policy fields,
    never certificate identity/structure fields.
    """

    # Certificate identity fields — IMMUTABLE, cannot be changed via policy update
    # To change any of these, a new certificate must be issued by the CA.
    IMMUTABLE_CERT_FIELDS = {
        "cert_serial",              # X.509 serial number
        "cert_issuer",              # CA issuer DN
        "cert_subject",             # Certificate subject
        "cert_public_key",          # Public key material
        "cert_not_before",          # Certificate validity start
        "cert_not_after",           # Certificate validity end
        "cert_fingerprint",         # SHA-256 cert fingerprint
        "cert_chain",               # CA chain
        "agent_id",                 # Agent identity (from cert CN)
        "agent_uuid",               # Agent UUID4 (cryptographic identity)
        "org_id",                   # Organization (from cert OU)
        "can_spawn",                # Permitted child template UUIDs — immutable, new cert required to change (§7.1, §8.1)
        "max_children",             # Max concurrent children — structural bound, new cert required
    }

    # Modifiable policy fields — updatable via dual-signed policy update (Owner + PA)
    MODIFIABLE_POLICY_FIELDS = {
        "allowed_scopes",           # Dynamic scope grants
        "scope_inherit",            # Inheritance rules
        "policy_ref",               # Reference policy version
        "ttl_seconds",              # TTL override
        "owner",                    # Policy owner
        "created_at",               # Policy creation timestamp
        "updated_at",               # Policy update timestamp
        "description",              # Human-readable description
        "tags",                     # Metadata tags
        "conditions",               # Dynamic conditions (Cedar evaluates)
    }

    def __init__(self):
        self.cert_fields = self.IMMUTABLE_CERT_FIELDS
        self.policy_fields = self.MODIFIABLE_POLICY_FIELDS

    def validate_policy_update(self, agent_cert_dict: dict, policy_update: dict) -> Tuple[bool, str]:
        """
        Validate that a policy update doesn't touch certificate identity fields.

        Args:
            agent_cert_dict: The original certificate dictionary (before update)
            policy_update: The proposed policy update

        Returns:
            (valid: bool, reason: str)
        """
        # 1. Scan for attempted cert field modifications
        illegal_fields = set()
        for key in policy_update.keys():
            if key in self.IMMUTABLE_CERT_FIELDS:
                illegal_fields.add(key)

        if illegal_fields:
            log.warning(
                "Policy update attempted to modify immutable cert fields",
                extra={
                    "illegal_fields": list(illegal_fields),
                    "reason": "Certificate identity is immutable"
                }
            )
            return (False, f"Cannot modify cert fields: {', '.join(sorted(illegal_fields))} (immutable)")

        # 2. Verify no unknown fields (whitelist approach)
        unknown_fields = set()
        for key in policy_update.keys():
            if key not in self.MODIFIABLE_POLICY_FIELDS and key != "policy_update":
                unknown_fields.add(key)

        if unknown_fields:
            log.warning(
                "Policy update contains unknown fields",
                extra={"unknown_fields": list(unknown_fields)}
            )
            return (False, f"Unknown policy fields: {', '.join(sorted(unknown_fields))}")

        # 3. Validate cert identity hasn't changed
        cert_id_before = {
            "agent_id": agent_cert_dict.get("agent_id"),
            "org_id": agent_cert_dict.get("org_id"),
            "cert_serial": agent_cert_dict.get("cert_serial"),
        }

        # The agent_id/org_id should NEVER appear in policy_update
        if "agent_id" in policy_update or "org_id" in policy_update:
            log.error("Policy update attempted to change agent identity (fail-closed)")
            return (False, "Cannot change agent identity via policy update")

        log.info(
            "Policy update validated — only policy fields modified",
            extra={"fields_modified": list(policy_update.keys())}
        )
        return (True, "Policy update: only policy fields modified (cert identity protected)")

    def get_allowed_policy_fields(self) -> Set[str]:
        """Return list of fields that CAN be modified in a policy update."""
        return self.MODIFIABLE_POLICY_FIELDS

    def get_protected_cert_fields(self) -> Set[str]:
        """Return list of fields that are protected from modification."""
        return self.IMMUTABLE_CERT_FIELDS
