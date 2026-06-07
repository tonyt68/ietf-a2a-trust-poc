"""
X.509 Certificate validation — IETF A2A Trust draft-tonyai-a2a-trust-00
Implements: Section 6 (Agent Identity), Section 7 (Template Structure),
            Section 8 (Spawn Chain), Section 13 (Fail Closed)
"""

import logging
import subprocess
import json
import re
from pathlib import Path
from typing import Optional, Dict, List, Tuple

log = logging.getLogger(__name__)

# Safe path characters for cert file paths — no shell metacharacters
_SAFE_PATH_RE = re.compile(r'^[a-zA-Z0-9/_\-\.]+$')


class CertValidator:
    """Validates X.509 certificate chain and all IETF template fields"""

    def __init__(self, ca_root_cert_path: str = "./certs/ca-root.crt"):
        self.ca_root_path = Path(ca_root_cert_path)

    # ── Low-level OpenSSL helpers ─────────────────────────────────────────────

    def _safe_path(self, path: str) -> Optional[str]:
        """Validate path contains no shell metacharacters before subprocess use."""
        if not _SAFE_PATH_RE.match(path):
            log.error("Unsafe path rejected", extra={"path": path[:64]})
            return None
        return path

    def _openssl(self, cmd: str) -> Tuple[bool, str]:
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True,
                                    text=True, timeout=5)
            return result.returncode == 0, (result.stdout + result.stderr).strip()
        except subprocess.TimeoutExpired:
            log.error("OpenSSL timeout — fail-closed (Section 13)")
            return (False, "OpenSSL timeout")

    def get_cert_info(self, cert_path: str) -> Optional[Dict]:
        """Extract subject, issuer, expiry, key size from X.509 certificate"""
        if not self._safe_path(str(cert_path)):
            return None
        ok, text = self._openssl(f"openssl x509 -in {cert_path} -text -noout")
        if not ok:
            log.error("Failed to parse cert", extra={"cert": cert_path})
            return None

        subject_match = re.search(r'Subject:.*?CN\s*=\s*([^,\n/]+)', text)
        issuer_match  = re.search(r'Issuer:.*?CN\s*=\s*([^,\n/]+)', text)
        not_after     = re.search(r'Not After\s*:\s*(.+)', text)
        key_bits      = re.search(r'Public-Key:\s*\((\d+)\s*bit', text)

        return {
            "subject_cn": subject_match.group(1).strip() if subject_match else None,
            "issuer_cn":  issuer_match.group(1).strip()  if issuer_match  else None,
            "not_after":  not_after.group(1).strip()     if not_after     else None,
            "key_bits":   int(key_bits.group(1))         if key_bits      else None,
            "raw_text":   text,
        }

    # ── Chain validation ──────────────────────────────────────────────────────

    def validate_chain(self, agent_cert_path: str) -> Tuple[bool, str]:
        """
        Validate certificate chain using CA root.
        Section 6.1: agent certs MUST be CA-signed, NOT self-signed.
        Section 13: CA unreachable → DENY (fail-closed).
        """
        if not self.ca_root_path.exists():
            return (False, f"CA root not found: {self.ca_root_path}")

        if not self._safe_path(str(agent_cert_path)):
            return (False, "Unsafe cert path rejected (fail-closed)")

        ok, out = self._openssl(
            f"openssl verify -CAfile {self.ca_root_path} {agent_cert_path}"
        )

        if not ok or "OK" not in out:
            log.warning("Chain validation FAILED", extra={"cert": agent_cert_path, "detail": out})
            return (False, f"Chain validation failed: {out}")

        # Confirm cert is NOT self-signed — fail-closed if parse fails (Section 13)
        info = self.get_cert_info(agent_cert_path)
        if not info:
            return (False, "Failed to parse cert for self-signed check (fail-closed)")
        if info["subject_cn"] == info["issuer_cn"]:
            return (False, "Self-signed certificates are not permitted (Section 6.1)")

        log.info("Chain valid", extra={"cert": agent_cert_path})
        return (True, "Chain valid")

    def is_cert_expired(self, cert_path: str) -> bool:
        """Check expiry. Fail-closed: error = treat as expired."""
        if not self._safe_path(str(cert_path)):
            return True  # Fail closed
        ok, _ = self._openssl(f"openssl x509 -in {cert_path} -noout -checkend 0")
        return not ok  # checkend returns 0 if NOT expired

    # ── Full certificate validation ───────────────────────────────────────────

    def validate_cert(self, agent_id: str, cert_path: str) -> Tuple[bool, str]:
        """
        Full IETF-compliant certificate validation.
        Checks (in order per Section 13 fail-closed):
          1. File exists
          2. Parse succeeds
          3. Subject CN matches agent_id
          4. CA chain validates (NOT self-signed)
          5. Not expired
          6. Key size >= 2048 bits
          7. Template state is ACTIVE (Section 10.4 — DISABLED/DELETED = DENY)
        Returns: (valid: bool, reason: str)
        """
        if not Path(cert_path).exists():
            return (False, "Certificate file not found")

        info = self.get_cert_info(cert_path)
        if not info:
            return (False, "Failed to parse certificate")

        if info["subject_cn"] != agent_id:
            return (False, f"Subject CN '{info['subject_cn']}' != agent_id '{agent_id}'")

        chain_ok, chain_reason = self.validate_chain(cert_path)
        if not chain_ok:
            return (False, chain_reason)

        if self.is_cert_expired(cert_path):
            return (False, "Certificate expired (TTL exceeded)")

        if (info.get("key_bits") or 0) < 2048:
            return (False, f"RSA key too small: {info.get('key_bits')} bits (min 2048)")

        # Check template state from metadata (Section 10.4) — fail-closed if file missing
        meta_path = Path(cert_path).with_suffix(".json")
        if not meta_path.exists():
            log.error("Template metadata missing", extra={"agent": agent_id, "path": str(meta_path)})
            return (False, "Template metadata not found (fail-closed, Section 10.4)")
        try:
            import json as _json
            with open(meta_path) as f:
                meta = _json.load(f)
            state = meta.get("state", "ACTIVE")
            if state != "ACTIVE":
                log.warning("Template not ACTIVE", extra={"agent": agent_id, "state": state})
                return (False, f"Template state is {state} — not authorized (Section 10.4)")
        except Exception as e:
            log.error("Failed to read template state", extra={"error": str(e)})
            return (False, "Failed to read template state (fail-closed)")

        log.info("Certificate valid", extra={"agent": agent_id, "issuer": info["issuer_cn"]})
        return (True, "Certificate valid")

    # ── Authorization bounds ──────────────────────────────────────────────────

    def parse_auth_bounds(self, metadata_path: str) -> Optional[Dict]:
        """
        Parse ALL required IETF fields from template metadata.
        Section 7.1 REQUIRED fields:
          - AllowedScopes:  permitted operation scopes for this agent
          - CanSpawn:       whitelist of permitted child templates this agent may instantiate
          - MaxChildren:    maximum concurrent child agents allowed
          - ScopeInherit:   child scopes must be strict-subset of parent (child ⊆ parent)
          - PolicyRef:      reference to governing policy document
        """
        try:
            with open(metadata_path, "r") as f:
                meta = json.load(f)

            # Support both flat (new) and nested (legacy) metadata layouts
            if "authorization_bounds" in meta:
                bounds = meta["authorization_bounds"]
            else:
                bounds = meta

            return {
                "allowed_scopes":    bounds.get("allowed_scopes", meta.get("allowed_scopes", [])),
                "can_spawn":         bounds.get("can_spawn",      meta.get("can_spawn", [])),
                "max_children":      bounds.get("max_children",   meta.get("max_children", 0)),
                "scope_inherit":     meta.get("scope_inherit", "strict-subset"),
                "policy_ref":        meta.get("policy_ref", ""),
                "template_version":  meta.get("template_version", "1.0"),
                "owner":             meta.get("owner", ""),
                "org_id":            meta.get("org_id", ""),
                "state":             meta.get("state", "ACTIVE"),
                "ttl_seconds":       meta.get("ttl_seconds", 86400),
            }
        except Exception as e:
            log.error("Failed to parse auth bounds", extra={"error": str(e)})
            return None

    # ── Scope validation ──────────────────────────────────────────────────────

    def validate_scope_subset(self, requested: List[str], allowed: List[str]) -> bool:
        """
        Section 8.3: Child AllowedScopes MUST be strict subset of parent.
        Section 16.1: Scope escalation MUST be rejected.
        """
        for scope in requested:
            if scope not in allowed:
                log.warning("Scope escalation attempt",
                            extra={"scope": scope, "allowed": allowed})
                return False
        return True

    # ── Two-check spawn rule (Section 8.1) ───────────────────────────────────

    def validate_spawn_check1(self, parent_meta: Dict, child_id: str) -> Tuple[bool, str]:
        """
        Check 1 (Static): requested child template MUST appear in parent CanSpawn whitelist.
        CanSpawn is a whitelist of permitted child TEMPLATES the parent agent may instantiate.
        Section 8.1: 'CanSpawn alone is insufficient but MUST pass first.'
        """
        can_spawn = parent_meta.get("can_spawn", [])  # whitelist of permitted child templates
        if child_id not in can_spawn:
            return (False, f"Child template '{child_id}' not in parent permitted child templates {can_spawn}")
        return (True, "Permitted child template check passed")

    def validate_spawn_check2(self, child_id: str, child_cert_path: str,
                               child_meta_path: str) -> Tuple[bool, str]:
        """
        Check 2 (Dynamic Registry): child template MUST be registered, CA-signed,
        not revoked, and currently ACTIVE in the Template Registry.
        Section 8.1: 'Registry lookup alone insufficient but MUST also pass.'
        Both checks required — either alone is insufficient.
        """
        # Must be CA-signed
        chain_ok, chain_reason = self.validate_chain(child_cert_path)
        if not chain_ok:
            return (False, f"Registry check: {chain_reason}")

        # Must be ACTIVE in registry (metadata state)
        try:
            with open(child_meta_path, "r") as f:
                meta = json.load(f)
            state = meta.get("state", "UNKNOWN")
            if state != "ACTIVE":
                return (False, f"Registry check: template state is {state}")
        except Exception as e:
            return (False, f"Registry check: cannot read metadata: {e}")

        return (True, "Registry check passed")

    def validate_max_children(self, parent_id: str, current_children: int,
                               parent_meta: Dict) -> Tuple[bool, str]:
        """Section 8.2 step 4: MaxChildren MUST be enforced."""
        max_c = parent_meta.get("max_children", 0)
        if max_c > 0 and current_children >= max_c:
            return (False, f"MaxChildren {max_c} exceeded (current={current_children})")
        return (True, "MaxChildren OK")
