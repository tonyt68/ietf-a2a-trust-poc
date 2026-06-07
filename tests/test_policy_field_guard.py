#!/usr/bin/env python3
"""
Policy Field Guard Tests — IETF A2A Trust Section 9.3
Demonstrates that certificate identity fields cannot be modified via policy updates.
"""

import sys
from pathlib import Path

# Add services to path
sys.path.insert(0, str(Path(__file__).parent.parent / "services" / "mcp_server"))

from policy_field_guard import PolicyFieldGuard


def test_valid_policy_fields():
    """Test: Valid policy fields only (should PASS)"""
    print("\n[TEST 1] Valid policy fields only — allowed_scopes, can_spawn, etc.")

    guard = PolicyFieldGuard()
    agent_cert = {"agent_id": "agent-b", "org_id": "acme-corp"}

    policy_update = {
        "allowed_scopes": ["write:events"],  # can_spawn/max_children are immutable — not here
        "ttl_seconds": 3600,
        "description": "Updated policy"
    }

    valid, reason = guard.validate_policy_update(agent_cert, policy_update)

    assert valid, f"Expected valid, got: {reason}"
    assert "only policy fields modified" in reason.lower()
    print(f"  ✅ PASS: {reason}")


def test_attempt_modify_can_spawn():
    """Test: can_spawn is IMMUTABLE — new cert required to change spawn rights"""
    print("\n[TEST 2] Attempt to modify can_spawn — should DENY (new cert required)")

    guard = PolicyFieldGuard()
    agent_cert = {"agent_id": "agent-b", "org_id": "acme-corp"}

    policy_update = {
        "allowed_scopes": ["write:events"],
        "can_spawn": ["d9cdba8d-5ada-485a-bd09-7a392d1f9625", "some-other-uuid"],  # ILLEGAL
    }

    valid, reason = guard.validate_policy_update(agent_cert, policy_update)

    assert not valid, f"Expected DENY, got valid: {reason}"
    assert "can_spawn" in reason.lower() or "cannot modify" in reason.lower()
    print(f"  ✅ PASS: Correctly blocked — {reason}")
    print(f"         To change spawn rights, issue a new certificate.")


def test_attempt_modify_agent_id():
    """Test: Attempt to modify agent_id (IMMUTABLE) — should DENY"""
    print("\n[TEST 2] Attempt to modify agent_id (immutable cert field)")

    guard = PolicyFieldGuard()
    agent_cert = {"agent_id": "agent-b", "org_id": "acme-corp"}

    policy_update = {
        "agent_id": "agent-c",  # ILLEGAL: trying to change agent identity
        "allowed_scopes": ["write:events"]
    }

    valid, reason = guard.validate_policy_update(agent_cert, policy_update)

    assert not valid, f"Expected DENY, got valid: {reason}"
    assert "cannot modify cert fields" in reason.lower() or "agent_id" in reason.lower()
    print(f"  ✅ PASS: Correctly blocked — {reason}")


def test_attempt_modify_org_id():
    """Test: Attempt to modify org_id (IMMUTABLE) — should DENY"""
    print("\n[TEST 3] Attempt to modify org_id (immutable cert field)")

    guard = PolicyFieldGuard()
    agent_cert = {"agent_id": "agent-b", "org_id": "acme-corp"}

    policy_update = {
        "org_id": "evil-corp",  # ILLEGAL: trying to change organization
        "allowed_scopes": ["write:events"]
    }

    valid, reason = guard.validate_policy_update(agent_cert, policy_update)

    assert not valid, f"Expected DENY, got valid: {reason}"
    assert "cannot modify cert fields" in reason.lower() or "org_id" in reason.lower()
    print(f"  ✅ PASS: Correctly blocked — {reason}")


def test_attempt_modify_cert_serial():
    """Test: Attempt to modify cert_serial (IMMUTABLE) — should DENY"""
    print("\n[TEST 4] Attempt to modify cert_serial (immutable cert field)")

    guard = PolicyFieldGuard()
    agent_cert = {"agent_id": "agent-b", "org_id": "acme-corp"}

    policy_update = {
        "cert_serial": "999999",  # ILLEGAL: trying to change cert serial
        "allowed_scopes": ["write:events"]
    }

    valid, reason = guard.validate_policy_update(agent_cert, policy_update)

    assert not valid, f"Expected DENY, got valid: {reason}"
    assert "cannot modify cert fields" in reason.lower() or "cert_serial" in reason.lower()
    print(f"  ✅ PASS: Correctly blocked — {reason}")


def test_attempt_modify_public_key():
    """Test: Attempt to modify public key (IMMUTABLE) — should DENY"""
    print("\n[TEST 5] Attempt to modify public key (immutable cert field)")

    guard = PolicyFieldGuard()
    agent_cert = {"agent_id": "agent-b", "org_id": "acme-corp"}

    policy_update = {
        "cert_public_key": "-----BEGIN PUBLIC KEY-----\nFAKEKEY",
        "allowed_scopes": ["read:events"]
    }

    valid, reason = guard.validate_policy_update(agent_cert, policy_update)

    assert not valid, f"Expected DENY, got valid: {reason}"
    assert "cannot modify cert fields" in reason.lower() or "public_key" in reason.lower()
    print(f"  ✅ PASS: Correctly blocked — {reason}")


def test_unknown_fields_rejected():
    """Test: Unknown fields are rejected (whitelist enforcement)"""
    print("\n[TEST 6] Unknown fields rejected (whitelist enforcement)")

    guard = PolicyFieldGuard()
    agent_cert = {"agent_id": "agent-b", "org_id": "acme-corp"}

    policy_update = {
        "allowed_scopes": ["write:events"],
        "mysterious_field": "value",  # UNKNOWN: not in policy or cert fields
        "another_unknown": 123
    }

    valid, reason = guard.validate_policy_update(agent_cert, policy_update)

    assert not valid, f"Expected DENY, got valid: {reason}"
    assert "unknown" in reason.lower()
    print(f"  ✅ PASS: Correctly rejected — {reason}")


def test_empty_update():
    """Test: Empty policy update (no-op)"""
    print("\n[TEST 7] Empty policy update (valid no-op)")

    guard = PolicyFieldGuard()
    agent_cert = {"agent_id": "agent-b", "org_id": "acme-corp"}

    policy_update = {}

    valid, reason = guard.validate_policy_update(agent_cert, policy_update)

    assert valid, f"Expected valid, got: {reason}"
    print(f"  ✅ PASS: {reason}")


def test_list_modifiable_fields():
    """Test: Can list all modifiable policy fields"""
    print("\n[TEST 8] List modifiable policy fields")

    guard = PolicyFieldGuard()
    modifiable = guard.get_allowed_policy_fields()
    protected = guard.get_protected_cert_fields()

    print(f"  ✅ Modifiable policy fields ({len(modifiable)}):")
    for field in sorted(modifiable):
        print(f"     • {field}")

    print(f"  ✅ Protected cert fields ({len(protected)}):")
    for field in sorted(protected):
        print(f"     • {field}")

    assert len(modifiable) > 0
    assert len(protected) > 0
    assert not (modifiable & protected), "No field should be both modifiable and protected"
    print(f"  ✅ PASS: Field sets are disjoint (no overlap)")


if __name__ == "__main__":
    print("=" * 80)
    print("IETF A2A Trust — Policy Field Guard Tests (Section 9.3)")
    print("Certificate identity protection: ONLY policy fields can be modified")
    print("=" * 80)

    try:
        test_valid_policy_fields()
        test_attempt_modify_can_spawn()
        test_attempt_modify_agent_id()
        test_attempt_modify_org_id()
        test_attempt_modify_cert_serial()
        test_attempt_modify_public_key()
        test_unknown_fields_rejected()
        test_empty_update()
        test_list_modifiable_fields()

        print("\n" + "=" * 80)
        print("✅ ALL POLICY FIELD GUARD TESTS PASSED (9/9)")
        print("=" * 80)

    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        sys.exit(1)
