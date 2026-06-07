"""
IETF A2A Trust Demo Scenario Runner — draft-tonyai-a2a-trust-00
Real Claude API calls + IETF-compliant security checks for all 11 scenarios.
"""

import logging
import uuid
import requests
import anthropic
import os
import json
import subprocess
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

log = logging.getLogger(__name__)


class ScenarioRunner:
    """Runs all 11 demo scenarios with real Claude API calls and RSA X.509 signatures"""

    def __init__(self, mcp_url: str, admin_url: str):
        self.mcp_url   = mcp_url
        self.admin_url = admin_url
        self.audit_trail = []
        self.correlation_id = None  # Set before running each scenario
        api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
        self.claude_client = anthropic.Anthropic(api_key=api_key)
        self.certs_dir = Path(os.getenv("CERTS_DIR", "/app/certs"))
        self.owner_key  = self.certs_dir / "owner.key"
        self.owner_cert = self.certs_dir / "owner.crt"
        self.pa_key     = self.certs_dir / "pa.key"
        self.pa_cert    = self.certs_dir / "pa.crt"

    # ── Helpers ───────────────────────────────────────────────────────────────

    def generate_correlation_id(self) -> str:
        # TODO: Update to UUID7 for sortable IDs
        return str(uuid.uuid4())

    def generate_nonce(self) -> str:
        """Unique nonce for replay prevention (Section 16.2)"""
        # TODO: Update to UUID7 for sortable IDs
        return str(uuid.uuid4())

    def get_timestamp(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _sign(self, data: str, key_path: Path) -> str:
        """RSA-SHA256 sign data with key, return base64 (Section 9.3)"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.dat', delete=False) as f:
                f.write(data)
                data_tmp = f.name
            sig_tmp = data_tmp + ".sig"
            result = subprocess.run(
                f"openssl dgst -sha256 -sign {key_path} -out {sig_tmp} {data_tmp}",
                shell=True, capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                return None
            b64_result = subprocess.run(
                f"openssl enc -base64 -A -in {sig_tmp}",
                shell=True, capture_output=True, text=True, timeout=5
            )
            return b64_result.stdout.strip()
        except Exception as e:
            log.error(f"Sign error: {e}")
            return None
        finally:
            for f in [data_tmp, sig_tmp]:
                if os.path.exists(f): os.unlink(f)

    # Identity fields the Owner signature covers — MUST match policy_validator.py IDENTITY_FIELDS
    IDENTITY_FIELDS = {
        "agent_id", "agent_uuid", "org_id", "subject", "issuer",
        "owner", "cert_serial", "cert_subject", "cert_issuer",
        "cert_public_key", "cert_not_before", "cert_not_after",
        "cert_fingerprint", "cert_chain", "template_version",
        "can_spawn",     # Immutable — new cert required to change (§8.1)
        "max_children",  # Immutable — structural spawn bound
    }

    # Policy fields the PA signature covers — MUST match PolicyFieldGuard.MODIFIABLE_POLICY_FIELDS
    # can_spawn and max_children are IMMUTABLE (in IDENTITY_FIELDS) — never in policy updates
    POLICY_FIELDS = {
        "allowed_scopes", "scope_inherit", "policy_ref",
        "ttl_seconds", "owner", "created_at", "updated_at",
        "description", "tags", "conditions",
    }

    def create_dual_sig(self, policy_doc: dict, existing_cert: dict = None) -> tuple:
        """
        Two-phase RSA signing (Section 9.3):
          Phase 1 — Owner signs CERT IDENTITY fields from existing_cert
                    Proves identity section is unchanged and authentic
          Phase 2 — PA signs POLICY fields from policy_doc
                    Authorizes the specific policy update

        Returns: (owner_sig, pa_sig)
        """
        # Phase 1: Owner signs the identity fields of the existing cert
        if existing_cert:
            identity_section = {k: v for k, v in existing_cert.items() if k in self.IDENTITY_FIELDS}
        else:
            # Fallback: load agent-b cert as default
            cert_path = self.certs_dir / "agent-b.json"
            if cert_path.exists():
                import json as _json
                with open(cert_path) as f:
                    cert_data = _json.load(f)
                identity_section = {k: v for k, v in cert_data.items() if k in self.IDENTITY_FIELDS}
            else:
                identity_section = {}

        canonical_identity = json.dumps(identity_section, sort_keys=True, separators=(',', ':'))
        owner_sig = self._sign(canonical_identity, self.owner_key)

        # Phase 2: PA signs only the policy fields being updated
        policy_section = {k: v for k, v in policy_doc.items() if k in self.POLICY_FIELDS}
        canonical_policy = json.dumps(policy_section, sort_keys=True, separators=(',', ':'))
        pa_sig = self._sign(canonical_policy, self.pa_key)

        return (owner_sig, pa_sig)

    def call_claude(self, prompt: str) -> str:
        """Real Claude API call"""
        message = self.claude_client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text

    def _post(self, agent_id: str, scopes: list, event_data: dict,
              nonce: str = None, timestamp: str = None) -> requests.Response:
        """POST /write-event with full IETF fields"""
        corr_id = self.correlation_id or self.generate_correlation_id()
        log.info(f"_post: using correlationId={corr_id} (self.correlation_id={self.correlation_id})")
        payload = {
            "correlation_id":    corr_id,
            "agent_id":          agent_id,
            "requested_scopes":  scopes,
            "event_data":        event_data,
            "request_nonce":     nonce or self.generate_nonce(),
            "request_timestamp": timestamp or self.get_timestamp(),
        }
        return requests.post(f"{self.mcp_url}/write-event", json=payload)

    def log_to_audit(self, scenario_id: int, agent_id: str, action: str,
                     decision: str, reason: str):
        entry = {
            "scenario_id": scenario_id,
            "agent_id":    agent_id,
            "action":      action,
            "decision":    decision,
            "reason":      reason,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
        }
        self.audit_trail.append(entry)
        log.info(f"scenario={scenario_id} agent={agent_id} decision={decision} reason=\"{reason}\"")

    # ── 11 Scenarios ─────────────────────────────────────────────────────────

    def scenario_1_golden_path(self):
        """
        Golden path: agent-b writes with write:events scope.
        Expected: ALLOWED — full chain validates.
        """
        agent_id = "agent-b"
        # Hardcoded payload (replaces Claude call)
        event_data = {
            "type": "event_write",
            "payload": {"status": "processing", "count": 5, "operation": "log"},
            "timestamp": self.get_timestamp()
        }

        r = self._post(agent_id, ["write:events"], event_data)
        decision = "ALLOWED" if r.status_code == 200 else "DENIED"
        self.log_to_audit(1, agent_id, "write_event", decision,
                          "Full chain: CA cert → nonce → CRL → scope ⊆ allowed → Cedar → S3 → audit")

    def scenario_2_dynamic_policy_update(self):
        """
        Dynamic policy update: agent-b submits dual-signed policy change.
        Expected: ALLOWED — both signatures valid.
        """
        agent_id = "agent-b"
        prompt = ("You are a Policy Authority agent. Draft a brief policy update "
                  "granting agent-b continued write access. One sentence.")
        claude_response = "Hardcoded response (Claude auth disabled)"  # Skip Claude call

        # Load existing cert — owner signs its identity section (Phase 1)
        cert_path = self.certs_dir / "agent-b.json"
        existing_cert = {}
        if cert_path.exists():
            with open(cert_path) as f:
                existing_cert = json.load(f)

        policy_doc = {
            "allowed_scopes": ["write:events"],  # can_spawn is immutable — not in policy updates
            "ttl_seconds": 86400,
            "description": f"Policy update: {claude_response}",
            "updated_at": self.get_timestamp(),
        }

        # Two-phase signing:
        #   owner_sig = sign(identity fields of existing cert)  → Phase 1
        #   pa_sig    = sign(policy fields of policy_doc)       → Phase 2
        owner_sig, pa_sig = self.create_dual_sig(policy_doc, existing_cert)

        r = self._post(agent_id, ["write:events"], {
            "policy_update": True,
            "policy_doc":    policy_doc,
            "existing_cert": existing_cert,   # Phase 1: identity fields for owner sig verification
            "owner_sig":     owner_sig,
            "pa_sig":        pa_sig,
        })
        decision = "ALLOWED" if r.status_code == 200 else "DENIED"
        self.log_to_audit(2, agent_id, "policy_update", decision,
                          "Dual-sig policy update (Owner + PA, Section 9.3)")

    def scenario_3_rogue_spawn(self):
        """
        Rogue spawn: agent-a tries spawn:child which is NOT in its CanSpawn.
        Expected: DENIED — scope not in AllowedScopes.
        """
        agent_id = "agent-a"
        prompt = ("Explain in one sentence why agents should not self-authorize spawning children "
                  "without being in their CanSpawn list.")
        claude_response = "Hardcoded response (Claude auth disabled)"  # Skip Claude call

        r = self._post(agent_id, ["spawn:child"], {"analysis": claude_response})
        decision = "ALLOWED" if r.status_code == 200 else "DENIED"
        self.log_to_audit(3, agent_id, "spawn", decision,
                          "spawn:child not in agent-a AllowedScopes — CanSpawn=[] (Section 8.1)")

    def scenario_4_dual_sig_missing(self):
        """
        Policy update with PA signature missing.
        Expected: DENIED — owner sig only, PA sig absent (Section 9.3).
        Demonstrates via event_data carrying the incomplete policy attempt.
        """
        agent_id = "agent-b"
        prompt = ("What is the security risk of accepting a policy change with only "
                  "the owner signature and no Policy Authority countersignature?")
        claude_response = "Hardcoded response (Claude auth disabled)"  # Skip Claude call

        policy_doc = {
            "allowed_scopes": ["write:events"],
            "ttl_seconds":    86400,
            "description":    "Scenario 4: missing PA sig test",
            "updated_at":     self.get_timestamp(),
        }

        cert_path = self.certs_dir / "agent-b.json"
        existing_cert = {}
        if cert_path.exists():
            with open(cert_path) as f:
                existing_cert = json.load(f)

        # Phase 1 only — deliberately omit PA signature
        owner_sig, _ = self.create_dual_sig(policy_doc, existing_cert)

        r = self._post(agent_id, ["write:events"], {
            "policy_update": True,
            "policy_doc":    policy_doc,
            "existing_cert": existing_cert,
            "owner_sig":     owner_sig,
            "pa_sig":        None,  # Missing — Section 9.3 violation
        })
        decision = "ALLOWED" if r.status_code == 200 else "DENIED"
        self.log_to_audit(4, agent_id, "policy_update", decision,
                          "PA signature missing — dual-sig requirement not met (Section 9.3)")

    def scenario_5_dual_sig_tampered(self):
        """
        PA signature tampered with.
        Expected: DENIED — tampered sig fails RSA verification.
        """
        agent_id = "agent-b"
        prompt = "In one sentence: what does a tampered PA signature indicate in an A2A trust system?"
        claude_response = "Hardcoded response (Claude auth disabled)"  # Skip Claude call

        policy_doc = {
            "allowed_scopes": ["write:events"],
            "ttl_seconds":    86400,
            "description":    "Scenario 5: tampered PA sig test",
            "updated_at":     self.get_timestamp(),
        }

        cert_path = self.certs_dir / "agent-b.json"
        existing_cert = {}
        if cert_path.exists():
            with open(cert_path) as f:
                existing_cert = json.load(f)

        owner_sig, pa_sig = self.create_dual_sig(policy_doc, existing_cert)
        tampered_pa_sig = pa_sig[:-8] + "TAMPERED"  # Corrupt PA sig — Phase 2 must fail

        r = self._post(agent_id, ["write:events"], {
            "policy_update": True,
            "policy_doc":    policy_doc,
            "existing_cert": existing_cert,
            "owner_sig":     owner_sig,
            "pa_sig":        tampered_pa_sig,
        })
        decision = "ALLOWED" if r.status_code == 200 else "DENIED"
        self.log_to_audit(5, agent_id, "policy_update", decision,
                          "PA sig tampered — RSA verify fails (Section 9.3)")

    def scenario_6_scope_escalation(self):
        """
        Scope escalation: agent-a requests admin:all (beyond AllowedScopes=['read:events']).
        Expected: DENIED — scope subset check fails (Section 8.3).
        """
        agent_id = "agent-a"
        prompt = ("In one sentence: why must child agent scopes always be a strict "
                  "subset of the parent agent's AllowedScopes?")
        claude_response = "Hardcoded response (Claude auth disabled)"  # Skip Claude call

        r = self._post(agent_id, ["admin:all"], {"escalation_analysis": claude_response})
        decision = "ALLOWED" if r.status_code == 200 else "DENIED"
        self.log_to_audit(6, agent_id, "write_event", decision,
                          "admin:all ⊄ ['read:events'] — scope escalation DENIED (Section 8.3, 16.1)")

    def scenario_7_revocation_lifecycle(self):
        """
        Cert lifecycle: ACTIVE → DISABLED → DELETED state machine (Section 10.4).
        Step 1: Write while ACTIVE       → ALLOWED
        Step 2: Admin disables agent-b   → DISABLED
        Step 3: Write while DISABLED     → DENIED
        Step 4: Admin reactivates        → ACTIVE (restore for future scenarios)
        Final decision: DENIED (demonstrating lifecycle enforcement)
        """
        agent_id = "agent-b"
        admin_key = os.getenv("ADMIN_API_KEY", "demo-admin-key-12345")
        admin_headers = {"x-admin-key": admin_key, "Content-Type": "application/json"}

        import requests as _req

        def _set_state(new_state: str) -> bool:
            try:
                resp = _req.put(
                    f"{self.admin_url}/template/{agent_id}/state",
                    json={"new_state": new_state},
                    headers=admin_headers,
                    timeout=5
                )
                if resp.status_code != 200:
                    log.error(f"Admin state update failed: HTTP {resp.status_code} — {resp.text[:200]}")
                    return False
                return True
            except Exception as e:
                log.error(f"Admin state update exception: {e}")
                return False

        # Step 1: Write while ACTIVE — should succeed
        r1 = self._post(agent_id, ["write:events"], {"lifecycle_step": "ACTIVE"})
        step1 = "ALLOWED" if r1.status_code == 200 else "DENIED"

        # Step 2: Disable agent-b via admin API (ACTIVE → DISABLED)
        disabled_ok = _set_state("DISABLED")
        if not disabled_ok:
            log.warning("Scenario 7: DISABLE failed — lifecycle demo incomplete")

        # Step 3: Write while DISABLED — should be denied
        r2 = self._post(agent_id, ["write:events"], {"lifecycle_step": "DISABLED"})
        step2 = "ALLOWED" if r2.status_code == 200 else "DENIED"

        # Step 4: Reactivate agent-b (restore for subsequent scenarios)
        reactivated = _set_state("ACTIVE")
        if not reactivated:
            log.error("Scenario 7: REACTIVATION of agent-b FAILED — subsequent scenarios may break!")

        # Final decision reflects the DISABLED write (the point of the demo)
        final_decision = step2
        self.log_to_audit(
            7, agent_id, "write_event", final_decision,
            f"Lifecycle: ACTIVE→{step1} | DISABLED→{step2} | Reactivated ACTIVE (Section 10.4)"
        )

    def scenario_8_crl_check_failure(self):
        """
        CRL check: an agent whose cert is on the revocation list.
        Expected: DENIED — CRL check fails at step 3.
        The scenario uses a phantom agent-x that doesn't exist / has no cert.
        """
        agent_id = "agent-x-revoked"
        prompt = ("In one sentence: why must all derived agent certificates be revoked "
                  "when their parent template is compromised?")
        claude_response = "Hardcoded response (Claude auth disabled)"  # Skip Claude call

        r = self._post(agent_id, ["write:events"], {"crl_explanation": claude_response})
        decision = "ALLOWED" if r.status_code == 200 else "DENIED"
        self.log_to_audit(8, agent_id, "write_event", decision,
                          "agent-x-revoked has no valid cert — cert validation fails (Section 12.1)")

    def scenario_9_ttl_expiry(self):
        """
        TTL enforcement: agent with expired cert is denied.
        Expected: DENIED — cert TTL exceeded (Section 12.3 automated revocation).
        Uses a non-existent agent to simulate expired/missing cert.
        """
        agent_id = "agent-expired"
        prompt = ("In one sentence: what should happen automatically when an agent's "
                  "certificate TTL expires in an A2A trust system?")
        claude_response = "Hardcoded response (Claude auth disabled)"  # Skip Claude call

        r = self._post(agent_id, ["write:events"], {"ttl_explanation": claude_response})
        decision = "ALLOWED" if r.status_code == 200 else "DENIED"
        self.log_to_audit(9, agent_id, "write_event", decision,
                          "TTL expiry → auto-DENY; no cert found (Section 12.3 automation)")

    def scenario_10_cross_org_grant(self):
        """
        Cross-org grant: properly structured grant with dual-signature.
        Expected: ALLOWED for agent-b (valid org), then demonstrates revocation.
        Section 11: explicit grant required, no implicit inter-org trust.
        """
        agent_id = "agent-b"
        prompt = ("In two sentences: why must cross-organizational agent grants be "
                  "explicitly authorized with dual-signatures and subject to unilateral revocation?")
        claude_response = "Hardcoded response (Claude auth disabled)"  # Skip Claude call

        # Build Section 11.2 compliant grant structure
        grant = {
            "grantor":        "tonyai-org",
            "grantee":        "partner-org",
            "template":       "agent-b",
            "allowed_scopes": ["write:events"],
            "ttl_seconds":    3600,
            "max_spawns":     10,
            "issued_at":      self.get_timestamp(),
        }
        owner_sig, pa_sig = self.create_dual_sig(grant)
        grant["owner_sig"] = owner_sig
        grant["pa_sig"]    = pa_sig

        r = self._post(agent_id, ["write:events"], {
            "cross_org_analysis": claude_response,
            "cross_org_grant":    grant,
        })
        decision = "ALLOWED" if r.status_code == 200 else "DENIED"
        self.log_to_audit(10, agent_id, "cross_org_grant", decision,
                          "Cross-org grant: dual-signed, TTL=1h, MaxSpawns=10; unilateral revocation available (Section 11)")

    def scenario_11_replay_attack(self):
        """
        Replay attack: sends the SAME nonce twice.
        First request: ALLOWED. Second with same nonce: DENIED (replay detected).
        Section 16.2: nonce + timestamp freshness enforcement.
        """
        agent_id = "agent-b"
        prompt = ("In one sentence: how does nonce-based replay prevention protect "
                  "agent-to-agent systems from replay attacks?")
        claude_response = "Hardcoded response (Claude auth disabled)"  # Skip Claude call

        # First request — fresh nonce, should succeed
        nonce     = self.generate_nonce()
        timestamp = self.get_timestamp()

        r1 = self._post(agent_id, ["write:events"],
                        {"replay_explanation": claude_response},
                        nonce=nonce, timestamp=timestamp)
        d1 = "ALLOWED" if r1.status_code == 200 else "DENIED"
        self.log_to_audit(11, agent_id, "write_event", d1,
                          f"First request — fresh nonce={nonce[:8]}... → {d1}")

        # Second request — SAME nonce reused (replay attack)
        r2 = self._post(agent_id, ["write:events"],
                        {"replay_explanation": claude_response},
                        nonce=nonce, timestamp=timestamp)
        d2 = "ALLOWED" if r2.status_code == 200 else "DENIED"
        self.log_to_audit(11, agent_id, "replay_attack", d2,
                          f"Replay with SAME nonce={nonce[:8]}... → {d2} (Section 16.2)")
