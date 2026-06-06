#!/usr/bin/env python3
"""
Policy Signature Validation Tests — IETF A2A Trust Section 9.3
Tests dual-signature verification (Owner + Policy Authority)
"""

import sys
import json
from pathlib import Path

# Add services to path
sys.path.insert(0, str(Path(__file__).parent.parent / "services" / "mcp_server"))

from policy_validator import PolicyValidator
from crypto_utils import sign_data_rsa_sha256

CERTS_DIR = Path(__file__).parent.parent / "certs"


def test_valid_dual_signature():
    """Test: Valid signatures from both Owner and PA"""
    print("\n[TEST 1] Valid dual-signature — both Owner and PA signatures valid")

    validator = PolicyValidator(
        owner_cert_path=str(CERTS_DIR / "owner.crt"),
        pa_cert_path=str(CERTS_DIR / "pa.crt")
    )

    policy_doc = {
        "name": "policy-test-valid",
        "agent": "agent-b",
        "scopes": ["write:events"],
        "created_at": "2026-06-05T21:00:00Z"
    }

    # Create valid signatures
    canonical = json.dumps(policy_doc, sort_keys=True, separators=(',', ':'))
    owner_sig = sign_data_rsa_sha256(canonical, CERTS_DIR / "owner.key")
    pa_sig = sign_data_rsa_sha256(canonical, CERTS_DIR / "pa.key")

    event_data = {
        "policy_update": policy_doc,
        "policy_doc": policy_doc,
        "owner_sig": owner_sig,
        "pa_sig": pa_sig
    }

    valid, reason = validator.validate_policy_update(event_data)

    assert valid, f"Expected valid, got: {reason}"
    assert "passed" in reason.lower(), f"Expected success message, got: {reason}"
    print(f"  ✅ PASS: {reason}")


def test_missing_owner_signature():
    """Test: Missing Owner signature"""
    print("\n[TEST 2] Missing Owner signature — should DENY")

    validator = PolicyValidator(
        owner_cert_path=str(CERTS_DIR / "owner.crt"),
        pa_cert_path=str(CERTS_DIR / "pa.crt")
    )

    policy_doc = {
        "name": "policy-test-missing-owner",
        "agent": "agent-b",
        "scopes": ["write:events"]
    }

    canonical = json.dumps(policy_doc, sort_keys=True, separators=(',', ':'))
    pa_sig = sign_data_rsa_sha256(canonical, CERTS_DIR / "pa.key")

    event_data = {
        "policy_update": policy_doc,
        "policy_doc": policy_doc,
        "owner_sig": None,  # Missing
        "pa_sig": pa_sig
    }

    valid, reason = validator.validate_policy_update(event_data)

    assert not valid, f"Expected invalid, got valid: {reason}"
    assert "owner" in reason.lower(), f"Expected owner error, got: {reason}"
    print(f"  ✅ PASS: Correctly denied — {reason}")


def test_missing_pa_signature():
    """Test: Missing Policy Authority signature"""
    print("\n[TEST 3] Missing PA signature — should DENY")

    validator = PolicyValidator(
        owner_cert_path=str(CERTS_DIR / "owner.crt"),
        pa_cert_path=str(CERTS_DIR / "pa.crt")
    )

    policy_doc = {
        "name": "policy-test-missing-pa",
        "agent": "agent-b",
        "scopes": ["write:events"]
    }

    canonical = json.dumps(policy_doc, sort_keys=True, separators=(',', ':'))
    owner_sig = sign_data_rsa_sha256(canonical, CERTS_DIR / "owner.key")

    event_data = {
        "policy_update": policy_doc,
        "policy_doc": policy_doc,
        "owner_sig": owner_sig,
        "pa_sig": None  # Missing
    }

    valid, reason = validator.validate_policy_update(event_data)

    assert not valid, f"Expected invalid, got valid: {reason}"
    assert "pa" in reason.lower() or "authority" in reason.lower(), f"Expected PA error, got: {reason}"
    print(f"  ✅ PASS: Correctly denied — {reason}")


def test_tampered_owner_signature():
    """Test: Owner signature tampered with"""
    print("\n[TEST 4] Tampered Owner signature — should DENY")

    validator = PolicyValidator(
        owner_cert_path=str(CERTS_DIR / "owner.crt"),
        pa_cert_path=str(CERTS_DIR / "pa.crt")
    )

    policy_doc = {
        "name": "policy-test-tampered-owner",
        "agent": "agent-b",
        "scopes": ["write:events"]
    }

    canonical = json.dumps(policy_doc, sort_keys=True, separators=(',', ':'))
    owner_sig = sign_data_rsa_sha256(canonical, CERTS_DIR / "owner.key")
    pa_sig = sign_data_rsa_sha256(canonical, CERTS_DIR / "pa.key")

    # Tamper with owner signature
    tampered_owner_sig = owner_sig[:-8] + "CORRUPTED"

    event_data = {
        "policy_update": policy_doc,
        "policy_doc": policy_doc,
        "owner_sig": tampered_owner_sig,  # Tampered
        "pa_sig": pa_sig
    }

    valid, reason = validator.validate_policy_update(event_data)

    assert not valid, f"Expected invalid (tampered sig), got valid: {reason}"
    assert "owner" in reason.lower() or "invalid" in reason.lower(), f"Expected owner error, got: {reason}"
    print(f"  ✅ PASS: Tampered signature detected — {reason}")


def test_tampered_pa_signature():
    """Test: PA signature tampered with"""
    print("\n[TEST 5] Tampered PA signature — should DENY")

    validator = PolicyValidator(
        owner_cert_path=str(CERTS_DIR / "owner.crt"),
        pa_cert_path=str(CERTS_DIR / "pa.crt")
    )

    policy_doc = {
        "name": "policy-test-tampered-pa",
        "agent": "agent-b",
        "scopes": ["write:events"]
    }

    canonical = json.dumps(policy_doc, sort_keys=True, separators=(',', ':'))
    owner_sig = sign_data_rsa_sha256(canonical, CERTS_DIR / "owner.key")
    pa_sig = sign_data_rsa_sha256(canonical, CERTS_DIR / "pa.key")

    # Tamper with PA signature
    tampered_pa_sig = pa_sig[:-8] + "CORRUPTED"

    event_data = {
        "policy_update": policy_doc,
        "policy_doc": policy_doc,
        "owner_sig": owner_sig,
        "pa_sig": tampered_pa_sig  # Tampered
    }

    valid, reason = validator.validate_policy_update(event_data)

    assert not valid, f"Expected invalid (tampered sig), got valid: {reason}"
    assert "pa" in reason.lower() or "authority" in reason.lower() or "invalid" in reason.lower(), f"Expected PA error, got: {reason}"
    print(f"  ✅ PASS: Tampered signature detected — {reason}")


def test_not_a_policy_update():
    """Test: Non-policy event should skip validation"""
    print("\n[TEST 6] Non-policy event — should skip validation (not applicable)")

    validator = PolicyValidator(
        owner_cert_path=str(CERTS_DIR / "owner.crt"),
        pa_cert_path=str(CERTS_DIR / "pa.crt")
    )

    event_data = {
        "some_other_event": {"data": "value"}
        # No policy_update field
    }

    valid, reason = validator.validate_policy_update(event_data)

    assert valid, f"Expected valid (not a policy update), got invalid: {reason}"
    assert "not" in reason.lower() or "skip" in reason.lower(), f"Expected skip message, got: {reason}"
    print(f"  ✅ PASS: Non-policy event skipped — {reason}")


if __name__ == "__main__":
    print("=" * 80)
    print("IETF A2A Trust — Policy Signature Validation Tests (Section 9.3)")
    print("=" * 80)

    try:
        test_valid_dual_signature()
        test_missing_owner_signature()
        test_missing_pa_signature()
        test_tampered_owner_signature()
        test_tampered_pa_signature()
        test_not_a_policy_update()

        print("\n" + "=" * 80)
        print("✅ ALL POLICY SIGNATURE TESTS PASSED (6/6)")
        print("=" * 80)

    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        sys.exit(1)
