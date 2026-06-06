"""
Cross-Organizational Grant Manager — IETF A2A Trust draft-tonyai-a2a-trust-00
Implements: Section 11 (Cross-Organizational Agent Interaction)
  - Section 11.1: Explicit grant requirement (no implicit trust)
  - Section 11.2: Grant structure (Grantor, Grantee, Template, AllowedScopes, TTL, MaxSpawns, dual-sig)
  - Section 11.4: Unilateral revocation
  - Section 11.5: Federated audit (each org maintains independent trail)
  - Section 10.5: Grants MUST NOT auto-roll-over on version upgrade
"""

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, List, Tuple

log = logging.getLogger(__name__)


class CrossOrgGrant:
    """Manages cross-organizational agent grants per IETF Section 11"""

    def __init__(self, grant_store_path: str = "./certs/cross_org_grants.json"):
        self.store_path = Path(grant_store_path)

    def _load(self) -> dict:
        if self.store_path.exists():
            try:
                with open(self.store_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                log.error("Failed to load grant store", extra={"error": str(e)})
        return {"grants": [], "revoked_grants": [], "last_updated": datetime.now(timezone.utc).isoformat()}

    def _save(self, store: dict):
        store["last_updated"] = datetime.now(timezone.utc).isoformat()
        with open(self.store_path, 'w') as f:
            json.dump(store, f, indent=2)

    def issue_grant(self,
                    grantor_org: str,
                    grantee_org: str,
                    template_id: str,
                    allowed_scopes: List[str],
                    ttl_seconds: int,
                    max_spawns: int,
                    owner_sig: str,
                    pa_sig: str) -> Tuple[bool, str, Optional[str]]:
        """
        Issue a cross-org grant. Section 11.2 required fields:
          Grantor, Grantee, Template, AllowedScopes, TTL, MaxSpawns, dual-sig.
        Section 11.1: No implicit trust — explicit grant required.
        Returns: (success, reason, grant_id)
        """
        if not owner_sig or not pa_sig:
            return (False, "Dual signature required for cross-org grant (Section 11.2)", None)

        # TODO: Update to UUID7 for sortable IDs
        grant_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)

        grant = {
            # Section 11.2 required fields (Table 3)
            "grant_id":      grant_id,
            "grantor":       grantor_org,
            "grantee":       grantee_org,
            "template":      template_id,
            "allowed_scopes": allowed_scopes,
            "ttl_seconds":   ttl_seconds,
            "max_spawns":    max_spawns,
            "owner_sig":     owner_sig,
            "pa_sig":        pa_sig,
            # Operational
            "issued_at":     now.isoformat(),
            "expires_at":    (now + timedelta(seconds=ttl_seconds)).isoformat(),
            "spawns_used":   0,
            "state":         "ACTIVE",
            # Section 10.5: version pinned — does NOT auto-roll on template upgrade
            "template_version_pinned": True,
        }

        store = self._load()
        store["grants"].append(grant)
        self._save(store)

        log.info("Cross-org grant issued",
                 extra={"grant_id": grant_id, "grantor": grantor_org,
                        "grantee": grantee_org, "template": template_id})
        return (True, "Grant issued", grant_id)

    def validate_grant(self, grant_id: str, grantee_org: str,
                       requested_scopes: List[str]) -> Tuple[bool, str]:
        """
        Validate a cross-org grant before allowing spawn.
        Checks: exists, not revoked, not expired, grantee matches,
                scopes subset, spawns within MaxSpawns.
        """
        store = self._load()

        # Check not in revoked list (Section 11.4 — unilateral revocation)
        revoked_ids = [g.get("grant_id") for g in store.get("revoked_grants", [])]
        if grant_id in revoked_ids:
            return (False, "Grant has been revoked (Section 11.4)")

        # Find active grant
        grant = next((g for g in store["grants"] if g["grant_id"] == grant_id), None)
        if not grant:
            return (False, f"Grant '{grant_id}' not found")

        # Grantee must match
        if grant["grantee"] != grantee_org:
            return (False, f"Grantee mismatch: expected '{grant['grantee']}', got '{grantee_org}'")

        # Check TTL
        expires = datetime.fromisoformat(grant["expires_at"])
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expires:
            return (False, "Cross-org grant expired (TTL exceeded)")

        # Check MaxSpawns
        if grant["spawns_used"] >= grant["max_spawns"]:
            return (False, f"MaxSpawns {grant['max_spawns']} exceeded")

        # Scopes must be subset of grant's AllowedScopes
        for scope in requested_scopes:
            if scope not in grant["allowed_scopes"]:
                return (False, f"Scope '{scope}' not in grant AllowedScopes {grant['allowed_scopes']}")

        return (True, "Grant valid")

    def record_spawn(self, grant_id: str) -> bool:
        """Increment spawns_used counter after successful cross-org spawn"""
        store = self._load()
        for grant in store["grants"]:
            if grant["grant_id"] == grant_id:
                grant["spawns_used"] += 1
                self._save(store)
                return True
        return False

    def revoke_grant(self, grant_id: str, grantor_org: str, reason: str = "") -> Tuple[bool, str]:
        """
        Unilateral revocation by grantor. Section 11.4:
        'The granting organization MAY revoke without cooperation of receiving org.'
        """
        store = self._load()
        grant = next((g for g in store["grants"] if g["grant_id"] == grant_id), None)

        if not grant:
            return (False, "Grant not found")
        if grant["grantor"] != grantor_org:
            return (False, "Only grantor may revoke (unilateral revocation, Section 11.4)")

        revocation = {
            "grant_id":   grant_id,
            "grantor":    grantor_org,
            "revoked_at": datetime.now(timezone.utc).isoformat(),
            "reason":     reason,
        }
        store.setdefault("revoked_grants", []).append(revocation)
        # Remove from active
        store["grants"] = [g for g in store["grants"] if g["grant_id"] != grant_id]
        self._save(store)

        log.warning("Cross-org grant REVOKED",
                    extra={"grant_id": grant_id, "grantor": grantor_org, "reason": reason})
        return (True, "Grant revoked")

    def list_grants(self, org: str = None) -> List[dict]:
        """List active grants (optionally filtered by org)"""
        store = self._load()
        grants = store.get("grants", [])
        if org:
            grants = [g for g in grants if g["grantor"] == org or g["grantee"] == org]
        return grants
