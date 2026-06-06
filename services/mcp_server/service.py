"""Business logic service layer (IETF A2A Trust RFC 5280 compliance)"""

import logging
import uuid
import re
from typing import Dict, Optional, List
from pathlib import Path
from cert_validator import CertValidator
from replay_prevention import ReplayPrevention
from audit_chain import AuditChain
from policy_validator import PolicyValidator
from policy_field_guard import PolicyFieldGuard

log = logging.getLogger(__name__)

# Allowlist: agent IDs must be alphanumeric + hyphen only.
# Blocks shell injection, path traversal, null bytes, and long filenames.
_AGENT_ID_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$')


class EventService:
    """Handles event write/read with IETF A2A Trust compliance checks"""

    def __init__(self, jwt_validator, hmac_verifier, cedar_evaluator, s3_tools, audit_fn,
                 cert_manager=None, cert_validator=None, replay_prevention=None, audit_chain=None):
        self.jwt_validator = jwt_validator
        self.hmac_verifier = hmac_verifier
        self.cedar_evaluator = cedar_evaluator
        self.s3_tools = s3_tools
        self.audit_fn = audit_fn
        self.cert_manager = cert_manager
        self.cert_validator = cert_validator or CertValidator()
        self.replay_prevention = replay_prevention or ReplayPrevention()
        self.audit_chain = audit_chain or AuditChain()
        self.policy_validator = PolicyValidator()
        self.policy_field_guard = PolicyFieldGuard()
        import os
        self.certs_dir = Path(os.getenv("CERTS_DIR", "./certs"))

    def write_event(self, correlation_id: str, agent_id: str, requested_scopes: List[str],
                   event_data: Dict, request_nonce: Optional[str] = None,
                   request_timestamp: Optional[str] = None) -> tuple:
        """
        Write event with IETF A2A Trust compliance checks.
        Validation chain (per IETF draft-tonyai-a2a-trust-00):
        0. agent_id format → 1. cert validation (RFC 5280) → 1.5. policy authority dual-sig (Section 9.3)
        → 2. replay prevention (Section 16.2) → 3. CRL check → 4. scopes → 5. scopes subset → 6. S3 write → 7. audit chain
        Returns: (success: bool, s3_key: str, decision: str, reason: str)
        """
        # TODO: Update to UUID7 for sortable IDs
        span_id = str(uuid.uuid4())
        decision = "ALLOWED"
        reason = "Full chain validates"
        granted_scopes = []

        try:
            # 0. AGENT ID FORMAT VALIDATION (prevent shell injection + path traversal)
            if not _AGENT_ID_RE.match(agent_id):
                decision = "DENIED"
                reason = "Invalid agent_id format"
                self._log_audit({"correlationId": correlation_id, "spanId": span_id,
                                 "agent": agent_id, "action": "write_event",
                                 "decision": decision, "reason": reason,
                                 "stage": "input_validation"})
                return (False, None, decision, reason)

            # 1. CERTIFICATE VALIDATION (RFC 5280)
            cert_path = self.certs_dir / f"{agent_id}.crt"
            cert_valid, cert_reason = self.cert_validator.validate_cert(agent_id, str(cert_path))

            if not cert_valid:
                decision = "DENIED"
                reason = f"Certificate invalid: {cert_reason}"
                log.warning(f"Cert validation failed: {reason}")
                self._log_audit({
                    "correlationId": correlation_id,
                    "spanId": span_id,
                    "agent": agent_id,
                    "action": "write_event",
                    "decision": decision,
                    "reason": reason,
                    "stage": "certificate_validation"
                })
                return (False, None, decision, reason)

            # 1.5. POLICY AUTHORITY VALIDATION — DUAL-SIGNATURE (Section 9.3)
            # If this is a policy update, both Owner and PA signatures required
            policy_valid, policy_reason = self.policy_validator.validate_policy_update(event_data)
            if not policy_valid:
                decision = "DENIED"
                reason = policy_reason
                log.warning(f"Policy validation failed: {reason}")
                self._log_audit({
                    "correlationId": correlation_id,
                    "spanId": span_id,
                    "agent": agent_id,
                    "action": "write_event",
                    "decision": decision,
                    "reason": reason,
                    "stage": "policy_authority_validation"
                })
                return (False, None, decision, reason)

            # 1.6. POLICY FIELD GUARD — CERT IDENTITY PROTECTION (Section 9.3)
            # Prevent modifications to certificate identity fields (immutable)
            if "policy_update" in event_data and "policy_doc" in event_data:
                cert_dict = {"agent_id": agent_id, "org_id": "default"}
                fields_valid, fields_reason = self.policy_field_guard.validate_policy_update(
                    cert_dict, event_data.get("policy_doc", {})
                )
                if not fields_valid:
                    decision = "DENIED"
                    reason = fields_reason
                    log.warning(f"Policy field guard rejected update: {reason}")
                    self._log_audit({
                        "correlationId": correlation_id,
                        "spanId": span_id,
                        "agent": agent_id,
                        "action": "write_event",
                        "decision": decision,
                        "reason": reason,
                        "stage": "policy_field_guard"
                    })
                    return (False, None, decision, reason)

            # 2. REPLAY ATTACK PREVENTION — MANDATORY (Section 16.2)
            # Fail-closed: missing nonce or timestamp = DENY, no exceptions
            if not request_nonce or not request_timestamp:
                decision = "DENIED"
                reason = "Replay prevention: nonce and timestamp are required (Section 16.2)"
                self._log_audit({
                    "correlationId": correlation_id,
                    "spanId": span_id,
                    "agent": agent_id,
                    "action": "write_event",
                    "decision": decision,
                    "reason": reason,
                    "stage": "replay_prevention"
                })
                return (False, None, decision, reason)

            replay_valid, replay_reason = self.replay_prevention.validate_request(
                request_nonce, request_timestamp
            )
            if not replay_valid:
                decision = "DENIED"
                reason = f"Replay attack prevented: {replay_reason}"
                log.warning(f"Replay prevention: {reason}")
                self._log_audit({
                    "correlationId": correlation_id,
                    "spanId": span_id,
                    "agent": agent_id,
                    "action": "write_event",
                    "decision": decision,
                    "reason": reason,
                    "stage": "replay_prevention"
                })
                return (False, None, decision, reason)

            # 3. CRL CHECK — MANDATORY (Section 12, 13)
            # Fail-closed: no cert_manager = DENY (infrastructure failure = DENY)
            if not self.cert_manager:
                decision = "DENIED"
                reason = "CRL infrastructure unavailable (fail-closed, Section 13)"
                self._log_audit({
                    "correlationId": correlation_id,
                    "spanId": span_id,
                    "agent": agent_id,
                    "action": "write_event",
                    "decision": decision,
                    "reason": reason,
                    "stage": "crl_check"
                })
                return (False, None, decision, reason)

            if not self.cert_manager.check_crl(agent_id):
                decision = "DENIED"
                reason = "Agent revoked/disabled/expired (CRL)"
                self._log_audit({
                    "correlationId": correlation_id,
                    "spanId": span_id,
                    "agent": agent_id,
                    "action": "write_event",
                    "decision": decision,
                    "reason": reason,
                    "stage": "crl_check"
                })
                return (False, None, decision, reason)

            # 4. PARSE AUTHORIZATION BOUNDS FROM CERTIFICATE
            metadata_path = self.certs_dir / f"{agent_id}.json"
            auth_bounds = self.cert_validator.parse_auth_bounds(str(metadata_path))

            if not auth_bounds:
                decision = "DENIED"
                reason = "Failed to parse authorization bounds"
                self._log_audit({
                    "correlationId": correlation_id,
                    "spanId": span_id,
                    "agent": agent_id,
                    "action": "write_event",
                    "decision": decision,
                    "reason": reason,
                    "stage": "auth_bounds_parsing"
                })
                return (False, None, decision, reason)

            allowed_scopes = auth_bounds.get("allowed_scopes", [])

            # 5. SCOPE SUBSET VALIDATION (requested ⊆ allowed, IETF requirement)
            if not self.cert_validator.validate_scope_subset(requested_scopes, allowed_scopes):
                decision = "DENIED"
                reason = f"Scope escalation: {requested_scopes} not ⊆ {allowed_scopes}"
                self._log_audit({
                    "correlationId": correlation_id,
                    "spanId": span_id,
                    "agent": agent_id,
                    "action": "write_event",
                    "decision": decision,
                    "reason": reason,
                    "stage": "scope_subset_validation"
                })
                return (False, None, decision, reason)

            # 6. CEDAR POLICY EVALUATION (dynamic policy layer)
            granted_scopes = self.cedar_evaluator.evaluate(agent_id, requested_scopes)

            if not granted_scopes:
                decision = "DENIED"
                reason = "Cedar policy evaluation DENIED"
                self._log_audit({
                    "correlationId": correlation_id,
                    "spanId": span_id,
                    "agent": agent_id,
                    "action": "write_event",
                    "decision": decision,
                    "reason": reason,
                    "stage": "cedar_policy",
                    "grantedScopes": [],
                    "requestedScopes": requested_scopes
                })
                return (False, None, decision, reason)
            # Post-grant assertion: Cedar MUST NOT expand beyond cert AllowedScopes (Section 9.1)
            elif not all(s in allowed_scopes for s in granted_scopes):
                decision = "DENIED"
                reason = f"Cedar granted scopes exceed cert AllowedScopes — policy misconfiguration"
                log.error("Cedar policy exceeded cert bounds",
                          extra={"granted": granted_scopes, "allowed": allowed_scopes})
                granted_scopes = []
                self._log_audit({
                    "correlationId": correlation_id,
                    "spanId": span_id,
                    "agent": agent_id,
                    "action": "write_event",
                    "decision": decision,
                    "reason": reason,
                    "stage": "cedar_policy",
                    "grantedScopes": [],
                    "requestedScopes": requested_scopes
                })
                return (False, None, decision, reason)

            # 7. WRITE TO S3
            s3_key = self.s3_tools.write_event(correlation_id, event_data)

            if not s3_key:
                decision = "DENIED"
                reason = "S3 write failed"
                self._log_audit({
                    "correlationId": correlation_id,
                    "spanId": span_id,
                    "agent": agent_id,
                    "action": "write_event",
                    "decision": decision,
                    "reason": reason,
                    "stage": "s3_write"
                })
                return (False, None, decision, reason)

            # 8. APPEND TO AUDIT CHAIN (tamper-evident)
            audit_event = {
                "correlationId": correlation_id,
                "spanId": span_id,
                "agent": agent_id,
                "action": "write_event",
                "decision": decision,
                "reason": reason,
                "grantedScopes": granted_scopes,
                "requestedScopes": requested_scopes,
                "s3_key": s3_key,
                "stages_passed": [
                    "certificate_validation",
                    "replay_prevention",
                    "crl_check",
                    "scope_subset_validation",
                    "cedar_policy",
                    "s3_write"
                ]
            }

            self.audit_chain.append_event(audit_event)
            self.audit_fn(audit_event)

            log.info("Event written successfully", extra={
                "agent": agent_id,
                "scopes": granted_scopes,
                "s3_key": s3_key[:32]
            })

            return (True, s3_key, decision, reason)

        except Exception as e:
            log.error(f"write_event error: {str(e)}")
            self._log_audit({
                "correlationId": correlation_id,
                "spanId": span_id,
                "agent": agent_id,
                "action": "write_event",
                "decision": "DENIED",
                "reason": f"Exception: {str(e)}",
                "stage": "exception_handling"
            })
            return (False, None, "DENIED", str(e))

    def _log_audit(self, event: Dict):
        """Log to tamper-evident audit chain. Failure is logged but does not block the decision."""
        try:
            self.audit_chain.append_event(event)
            self.audit_fn(event)
        except Exception as e:
            # AUDIT INTEGRITY GAP: this DENY/ALLOW event was not persisted to the hash chain.
            # The decision itself stands (fail-closed), but the audit record is lost.
            log.warning("AUDIT INTEGRITY GAP — event not persisted to chain",
                        extra={"error": str(e),
                               "decision": event.get("decision"),
                               "agent": event.get("agent"),
                               "action": event.get("action")})

    def read_event(self, correlation_id: str, agent_id: str, s3_key: str,
                   request_nonce: Optional[str] = None,
                   request_timestamp: Optional[str] = None) -> tuple:
        """
        Read event with IETF compliance checks.
        Validation chain: cert → replay → CRL → scopes → S3 → audit chain
        Returns: (success: bool, content: str, decision: str, reason: str)
        """
        # TODO: Update to UUID7 for sortable IDs
        span_id = str(uuid.uuid4())
        decision = "ALLOWED"
        reason = "Full chain validates"

        try:
            # 0. AGENT ID FORMAT VALIDATION
            if not _AGENT_ID_RE.match(agent_id):
                decision = "DENIED"
                reason = "Invalid agent_id format"
                self._log_audit({"correlationId": correlation_id, "spanId": span_id,
                                 "agent": agent_id, "action": "read_event",
                                 "decision": decision, "reason": reason,
                                 "stage": "input_validation"})
                return (False, None, decision, reason)

            # 1. CERTIFICATE VALIDATION
            cert_path = self.certs_dir / f"{agent_id}.crt"
            cert_valid, cert_reason = self.cert_validator.validate_cert(agent_id, str(cert_path))

            if not cert_valid:
                decision = "DENIED"
                reason = f"Certificate invalid: {cert_reason}"
                self._log_audit({
                    "correlationId": correlation_id,
                    "spanId": span_id,
                    "agent": agent_id,
                    "action": "read_event",
                    "decision": decision,
                    "reason": reason,
                    "stage": "certificate_validation"
                })
                return (False, None, decision, reason)

            # 2. REPLAY PREVENTION — MANDATORY (Section 16.2)
            if not request_nonce or not request_timestamp:
                decision = "DENIED"
                reason = "Replay prevention: nonce and timestamp are required (Section 16.2)"
                self._log_audit({
                    "correlationId": correlation_id,
                    "spanId": span_id,
                    "agent": agent_id,
                    "action": "read_event",
                    "decision": decision,
                    "reason": reason,
                    "stage": "replay_prevention"
                })
                return (False, None, decision, reason)

            replay_valid, replay_reason = self.replay_prevention.validate_request(
                request_nonce, request_timestamp
            )
            if not replay_valid:
                decision = "DENIED"
                reason = f"Replay attack prevented: {replay_reason}"
                self._log_audit({
                    "correlationId": correlation_id,
                    "spanId": span_id,
                    "agent": agent_id,
                    "action": "read_event",
                    "decision": decision,
                    "reason": reason,
                    "stage": "replay_prevention"
                })
                return (False, None, decision, reason)

            # 3. CRL CHECK — MANDATORY (Section 12, 13)
            if not self.cert_manager:
                decision = "DENIED"
                reason = "CRL infrastructure unavailable (fail-closed, Section 13)"
                self._log_audit({
                    "correlationId": correlation_id,
                    "spanId": span_id,
                    "agent": agent_id,
                    "action": "read_event",
                    "decision": decision,
                    "reason": reason,
                    "stage": "crl_check"
                })
                return (False, None, decision, reason)

            if not self.cert_manager.check_crl(agent_id):
                decision = "DENIED"
                reason = "Agent revoked/disabled/expired (CRL)"
                self._log_audit({
                    "correlationId": correlation_id,
                    "spanId": span_id,
                    "agent": agent_id,
                    "action": "read_event",
                    "decision": decision,
                    "reason": reason,
                    "stage": "crl_check"
                })
                return (False, None, decision, reason)

            # 4. AUTHORIZE (read:events scope required)
            granted_scopes = self.cedar_evaluator.evaluate(agent_id, ["read:events"])

            if not granted_scopes:
                decision = "DENIED"
                reason = "Cedar policy DENY (read:events not granted)"
                self._log_audit({
                    "correlationId": correlation_id,
                    "spanId": span_id,
                    "agent": agent_id,
                    "action": "read_event",
                    "decision": decision,
                    "reason": reason,
                    "stage": "cedar_policy"
                })
                return (False, None, decision, reason)

            # 5. RETRIEVE FROM S3
            content = self.s3_tools.read_event(s3_key)

            if not content:
                decision = "DENIED"
                reason = "Event not found in S3"
                self._log_audit({
                    "correlationId": correlation_id,
                    "spanId": span_id,
                    "agent": agent_id,
                    "action": "read_event",
                    "decision": decision,
                    "reason": reason,
                    "stage": "s3_read"
                })
                return (False, None, decision, reason)

            # 6. AUDIT CHAIN
            audit_event = {
                "correlationId": correlation_id,
                "spanId": span_id,
                "agent": agent_id,
                "action": "read_event",
                "decision": decision,
                "reason": reason,
                "s3_key": s3_key,
                "stages_passed": [
                    "certificate_validation",
                    "replay_prevention",
                    "crl_check",
                    "cedar_policy",
                    "s3_read"
                ]
            }

            self.audit_chain.append_event(audit_event)
            self.audit_fn(audit_event)

            log.info("Event read successfully", extra={
                "agent": agent_id,
                "s3_key": s3_key[:32]
            })

            return (True, content, decision, reason)

        except Exception as e:
            log.error(f"read_event error: {str(e)}")
            self._log_audit({
                "correlationId": correlation_id,
                "spanId": span_id,
                "agent": agent_id,
                "action": "read_event",
                "decision": "DENIED",
                "reason": f"Exception: {str(e)}",
                "stage": "exception_handling"
            })
            return (False, None, "DENIED", str(e))
