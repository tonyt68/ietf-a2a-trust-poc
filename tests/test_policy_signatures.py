#!/usr/bin/env python3
"""
Policy Signature Validation Tests — IETF A2A Trust Section 9.3
Tests two-phase signature verification:
  Phase 1: Owner signs cert IDENTITY fields (proves cert not tampered)
  Phase 2: PA signs POLICY fields (authorizes specific policy update)
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "services" / "mcp_server"))

from policy_validator import PolicyValidator, IDENTITY_FIELDS, POLICY_FIELDS
from crypto_utils import sign_data_rsa_sha256

CERTS_DIR = Path(__file__).parent.parent / "certs"

# Load agent-b cert as the existing cert for Phase 1 identity signing
def load_existing_cert():
    with open(CERTS_DIR / "agent-b.json") as f:
        return json.load(f)

def make_identity_canonical(cert: dict) -> str:
    identity = {k: v for k, v in cert.items() if k in IDENTITY_FIELDS}
    return json.dumps(identity, sort_keys=True, separators=(',', ':'))

def make_policy_canonical(policy_doc: dict) -> str:
    policy = {k: v for k, v in policy_doc.items() if k in POLICY_FIELDS}
    return json.dumps(policy, sort_keys=True, separators=(',', ':'))

VALID_POLICY_DOC = {
    "allowed_scopes": ["write:events"],  # can_spawn is IMMUTABLE — not in policy updates
    "ttl_seconds": 86400,
    "description": "Test policy update",
    "updated_at": "2026-06-06T21:00:00Z",
}


def test_valid_two_phase_signature():
    """Test: Valid two-phase signatures — owner signs identity, PA signs policy"""
    print("\n[TEST 1] Valid two-phase signatures — owner covers identity, PA covers policy")

    validator = PolicyValidator(
        owner_cert_path=str(CERTS_DIR / "owner.crt"),
        pa_cert_path=str(CERTS_DIR / "pa.crt")
    )

    existing_cert = load_existing_cert()

    # Phase 1: owner signs the cert identity fields
    owner_sig = sign_data_rsa_sha256(make_identity_canonical(existing_cert), CERTS_DIR / "owner.key")
    # Phase 2: PA signs the policy fields being updated
    pa_sig = sign_data_rsa_sha256(make_policy_canonical(VALID_POLICY_DOC), CERTS_DIR / "pa.key")

    event_data = {
        "policy_update": True,
        "policy_doc":    VALID_POLICY_DOC,
        "existing_cert": existing_cert,
        "owner_sig":     owner_sig,
        "pa_sig":        pa_sig,
    }

    valid, reason = validator.validate_policy_update(event_data)
    assert valid, f"Expected valid, got: {reason}"
    assert "passed" in reason.lower(), f"Expected success message, got: {reason}"
    print(f"  ✅ PASS: {reason}")


def test_missing_owner_signature():
    """Test: Missing owner signature — Phase 1 cannot proceed"""
    print("\n[TEST 2] Missing owner signature — Phase 1 cannot proceed")

    validator = PolicyValidator(
        owner_cert_path=str(CERTS_DIR / "owner.crt"),
        pa_cert_path=str(CERTS_DIR / "pa.crt")
    )

    existing_cert = load_existing_cert()
    pa_sig = sign_data_rsa_sha256(make_policy_canonical(VALID_POLICY_DOC), CERTS_DIR / "pa.key")

    event_data = {
        "policy_update": True,
        "policy_doc":    VALID_POLICY_DOC,
        "existing_cert": existing_cert,
        "owner_sig":     None,
        "pa_sig":        pa_sig,
    }

    valid, reason = validator.validate_policy_update(event_data)
    assert not valid
    assert "owner" in reason.lower()
    print(f"  ✅ PASS: Correctly denied — {reason}")


def test_missing_pa_signature():
    """Test: Missing PA signature — Phase 2 cannot proceed"""
    print("\n[TEST 3] Missing PA signature — Phase 2 cannot proceed")

    validator = PolicyValidator(
        owner_cert_path=str(CERTS_DIR / "owner.crt"),
        pa_cert_path=str(CERTS_DIR / "pa.crt")
    )

    existing_cert = load_existing_cert()
    owner_sig = sign_data_rsa_sha256(make_identity_canonical(existing_cert), CERTS_DIR / "owner.key")

    event_data = {
        "policy_update": True,
        "policy_doc":    VALID_POLICY_DOC,
        "existing_cert": existing_cert,
        "owner_sig":     owner_sig,
        "pa_sig":        None,
    }

    valid, reason = validator.validate_policy_update(event_data)
    assert not valid
    assert "pa" in reason.lower() or "authority" in reason.lower()
    print(f"  ✅ PASS: Correctly denied — {reason}")


def test_tampered_owner_signature():
    """Test: Tampered owner signature — cert identity tampering detected"""
    print("\n[TEST 4] Tampered owner signature — Phase 1 detects cert identity tampering")

    validator = PolicyValidator(
        owner_cert_path=str(CERTS_DIR / "owner.crt"),
        pa_cert_path=str(CERTS_DIR / "pa.crt")
    )

    existing_cert = load_existing_cert()
    owner_sig = sign_data_rsa_sha256(make_identity_canonical(existing_cert), CERTS_DIR / "owner.key")
    pa_sig    = sign_data_rsa_sha256(make_policy_canonical(VALID_POLICY_DOC), CERTS_DIR / "pa.key")

    event_data = {
        "policy_update": True,
        "policy_doc":    VALID_POLICY_DOC,
        "existing_cert": existing_cert,
        "owner_sig":     owner_sig[:-8] + "TAMPERED",
        "pa_sig":        pa_sig,
    }

    valid, reason = validator.validate_policy_update(event_data)
    assert not valid
    assert "phase 1" in reason.lower() or "owner" in reason.lower() or "identity" in reason.lower()
    print(f"  ✅ PASS: Identity tampering detected — {reason}")


def test_tampered_pa_signature():
    """Test: Tampered PA signature — unauthorized policy change detected"""
    print("\n[TEST 5] Tampered PA signature — Phase 2 detects unauthorized policy change")

    validator = PolicyValidator(
        owner_cert_path=str(CERTS_DIR / "owner.crt"),
        pa_cert_path=str(CERTS_DIR / "pa.crt")
    )

    existing_cert = load_existing_cert()
    owner_sig = sign_data_rsa_sha256(make_identity_canonical(existing_cert), CERTS_DIR / "owner.key")
    pa_sig    = sign_data_rsa_sha256(make_policy_canonical(VALID_POLICY_DOC), CERTS_DIR / "pa.key")

    event_data = {
        "policy_update": True,
        "policy_doc":    VALID_POLICY_DOC,
        "existing_cert": existing_cert,
        "owner_sig":     owner_sig,
        "pa_sig":        pa_sig[:-8] + "TAMPERED",
    }

    valid, reason = validator.validate_policy_update(event_data)
    assert not valid
    assert "phase 2" in reason.lower() or "pa" in reason.lower() or "policy" in reason.lower()
    print(f"  ✅ PASS: Unauthorized policy change detected — {reason}")


def test_owner_signing_wrong_section():
    """Test: Owner signs policy fields instead of identity — Phase 1 fails"""
    print("\n[TEST 6] Owner signs policy fields (wrong section) — Phase 1 fails")

    validator = PolicyValidator(
        owner_cert_path=str(CERTS_DIR / "owner.crt"),
        pa_cert_path=str(CERTS_DIR / "pa.crt")
    )

    existing_cert = load_existing_cert()
    # BUG: owner signs policy fields instead of identity fields
    wrong_owner_sig = sign_data_rsa_sha256(make_policy_canonical(VALID_POLICY_DOC), CERTS_DIR / "owner.key")
    pa_sig          = sign_data_rsa_sha256(make_policy_canonical(VALID_POLICY_DOC), CERTS_DIR / "pa.key")

    event_data = {
        "policy_update": True,
        "policy_doc":    VALID_POLICY_DOC,
        "existing_cert": existing_cert,
        "owner_sig":     wrong_owner_sig,
        "pa_sig":        pa_sig,
    }

    valid, reason = validator.validate_policy_update(event_data)
    assert not valid
    assert "phase 1" in reason.lower() or "owner" in reason.lower() or "identity" in reason.lower()
    print(f"  ✅ PASS: Wrong signing section detected — {reason}")


def test_attempt_modify_cert_identity_via_policy():
    """Test: Policy doc contains cert identity fields — field guard blocks it"""
    print("\n[TEST 7] Policy doc contains identity fields — field guard blocks before sig check")

    validator = PolicyValidator(
        owner_cert_path=str(CERTS_DIR / "owner.crt"),
        pa_cert_path=str(CERTS_DIR / "pa.crt")
    )

    existing_cert = load_existing_cert()
    malicious_policy = {
        "allowed_scopes": ["admin:all"],
        "agent_id": "evil-agent",   # ILLEGAL: identity field
        "org_id": "evil-corp",      # ILLEGAL: identity field
    }

    owner_sig = sign_data_rsa_sha256(make_identity_canonical(existing_cert), CERTS_DIR / "owner.key")
    pa_sig    = sign_data_rsa_sha256(make_policy_canonical(malicious_policy), CERTS_DIR / "pa.key")

    event_data = {
        "policy_update": True,
        "policy_doc":    malicious_policy,
        "existing_cert": existing_cert,
        "owner_sig":     owner_sig,
        "pa_sig":        pa_sig,
    }

    valid, reason = validator.validate_policy_update(event_data)
    assert not valid
    assert "agent_id" in reason or "org_id" in reason or "cannot modify" in reason.lower()
    print(f"  ✅ PASS: Identity field modification blocked — {reason}")


def test_not_a_policy_update():
    """Test: Non-policy event skips validation"""
    print("\n[TEST 8] Non-policy event — should skip validation")

    validator = PolicyValidator(
        owner_cert_path=str(CERTS_DIR / "owner.crt"),
        pa_cert_path=str(CERTS_DIR / "pa.crt")
    )

    valid, reason = validator.validate_policy_update({"some_other_event": True})
    assert valid
    assert "not" in reason.lower()
    print(f"  ✅ PASS: Non-policy event skipped — {reason}")


if __name__ == "__main__":
    print("=" * 80)
    print("IETF A2A Trust — Two-Phase Policy Signature Tests (Section 9.3)")
    print("Phase 1: Owner signs cert identity | Phase 2: PA signs policy fields")
    print("=" * 80)

    try:
        test_valid_two_phase_signature()
        test_missing_owner_signature()
        test_missing_pa_signature()
        test_tampered_owner_signature()
        test_tampered_pa_signature()
        test_owner_signing_wrong_section()
        test_attempt_modify_cert_identity_via_policy()
        test_not_a_policy_update()

        print("\n" + "=" * 80)
        print("✅ ALL TWO-PHASE SIGNATURE TESTS PASSED (8/8)")
        print("=" * 80)

    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        sys.exit(1)
