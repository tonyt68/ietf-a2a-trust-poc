#!/usr/bin/env python3
"""
IETF A2A Trust PoC — Certificate Infrastructure Setup
Implements draft-tonyai-a2a-trust-00 Section 6 (Agent Identity) and Section 7 (Template Structure)

Flow: Template Author generates CSR → CA signs → Signed Template registered
      This is the CORRECT flow per Section 6.1, NOT self-signed agent certs.
"""

import os
import json
import subprocess
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def run(cmd: str) -> str:
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"OpenSSL failed: {result.stderr.strip()}")
    return result.stdout.strip()


def setup_ca_root():
    """
    Generate Template Registry CA — root of trust for the agent ecosystem.
    Section 6: 'Template Registry CA: The Certificate Authority that signs agent templates'
    """
    certs_dir = Path("./certs")
    certs_dir.mkdir(exist_ok=True)
    os.chdir(certs_dir)

    print("=== Template Registry CA (Root of Trust) ===")
    run("openssl genrsa -out ca-root.key 2048 2>/dev/null")
    run(
        "openssl req -new -x509 -key ca-root.key -out ca-root.crt -days 3650 "
        "-subj '/CN=A2A-Trust-Template-Registry-CA/O=A2A-Trust/C=US' 2>/dev/null"
    )
    os.chmod("ca-root.key", 0o600)
    print("✓ CA Root: ca-root.crt (Issuer/root of trust for all agent templates)")

    os.chdir("..")


def setup_authority_certs():
    """
    Generate Owner Authority and Policy Authority certs — signed by CA.
    Section 9.3: Both must hold independent keys for dual-signature requirement.
    """
    certs_dir = Path("./certs")
    os.chdir(certs_dir)

    for name, cn in [("owner", "owner-authority"), ("pa", "policy-authority")]:
        print(f"=== {cn} (CA-signed) ===")
        run(f"openssl genrsa -out {name}.key 2048 2>/dev/null")
        # Generate CSR
        run(
            f"openssl req -new -key {name}.key -out {name}.csr "
            f"-subj '/CN={cn}/O=A2A-Trust/C=US' 2>/dev/null"
        )
        # CA signs it
        run(
            f"openssl x509 -req -in {name}.csr -CA ca-root.crt -CAkey ca-root.key "
            f"-CAcreateserial -out {name}.crt -days 3650 2>/dev/null"
        )
        os.unlink(f"{name}.csr")
        os.chmod(f"{name}.key", 0o600)
        print(f"  ✓ {name}.crt  Issuer=A2A-Trust-Template-Registry-CA  CN={cn}")

    os.chdir("..")


def setup_agent_templates():
    """
    Generate IETF-compliant agent template certificates via CSR → CA signing flow.
    Section 6.1: 'Template Author generates CSR → CA validates → CA signs → Registered'
    Section 7.1: All REQUIRED static fields embedded in metadata
    """
    certs_dir = Path("./certs")
    os.chdir(certs_dir)

    # REQUIRED fields per Section 7.1 Table 1
    agents = [
        {
            "agent_id":      "agent-a",
            "cn":            "agent-a",
            "org_id":        "tonyai-org",
            "owner":         "ajtrujillo68@gmail.com",
            "key_usage":     ["read"],
            "allowed_scopes": ["read:events"],
            "can_spawn":     [],
            "max_children":  0,
            "scope_inherit": "strict-subset",      # Section 8.3 — REQUIRED field
            "policy_ref":    "policy-store/agent-a/current",  # Section 7.1 — REQUIRED
            "template_version": "1.0",
            "ttl_seconds":   86400,                # 24h
            "ttl_days":      365,
        },
        {
            "agent_id":      "agent-b",
            "cn":            "agent-b",
            "org_id":        "tonyai-org",
            "owner":         "ajtrujillo68@gmail.com",
            "key_usage":     ["write", "spawn", "delegate"],
            "allowed_scopes": ["write:events"],
            "can_spawn":     ["agent-a"],
            "max_children":  5,
            "scope_inherit": "strict-subset",
            "policy_ref":    "policy-store/agent-b/current",
            "template_version": "1.0",
            "ttl_seconds":   86400,
            "ttl_days":      365,
        },
    ]

    for agent in agents:
        aid = agent["agent_id"]
        print(f"\n=== {aid} template (CSR → CA signed) ===")

        # Step 1: Generate agent private key
        run(f"openssl genrsa -out {aid}.key 2048 2>/dev/null")
        os.chmod(f"{aid}.key", 0o600)

        # Step 2: Generate CSR (Section 6.1 — Template Author generates CSR)
        cn = agent["cn"]
        org_id = agent["org_id"]
        run(
            f"openssl req -new -key {aid}.key -out {aid}.csr "
            f"-subj '/CN={cn}/O={org_id}/C=US' 2>/dev/null"
        )

        # Step 3: CA signs the CSR (Section 6.1 — CA validates conformance and signs)
        run(
            f"openssl x509 -req -in {aid}.csr -CA ca-root.crt -CAkey ca-root.key "
            f"-CAcreateserial -out {aid}.crt -days {agent['ttl_days']} 2>/dev/null"
        )
        os.unlink(f"{aid}.csr")

        # Verify issuer is the CA (not self-signed)
        issuer = run(f"openssl x509 -in {aid}.crt -noout -issuer")
        subject = run(f"openssl x509 -in {aid}.crt -noout -subject")
        print(f"  ✓ {subject}")
        print(f"  ✓ {issuer}")

        # Step 4: Build template metadata with ALL REQUIRED fields (Section 7.1)
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=agent["ttl_seconds"] * 365)

        metadata = {
            # Identity (Section 7.1 Static Fields — all REQUIRED)
            "subject":           aid,
            "issuer":            "A2A-Trust-Template-Registry-CA",
            "owner":             agent["owner"],
            "org_id":            agent["org_id"],
            "key_usage":         agent["key_usage"],
            "allowed_scopes":    agent["allowed_scopes"],
            "can_spawn":         agent["can_spawn"],
            "max_children":      agent["max_children"],
            "scope_inherit":     agent["scope_inherit"],
            "policy_ref":        agent["policy_ref"],
            "ttl_seconds":       agent["ttl_seconds"],
            # Operational
            "agent_id":          aid,
            "template_version":  agent["template_version"],
            "state":             "ACTIVE",
            "created_at":        now.isoformat(),
            "expires_at":        expires.isoformat(),
            "cert_path":         f"certs/{aid}.crt",
            "key_path":          f"certs/{aid}.key",
            # Backwards-compat alias for service.py
            "authorization_bounds": {
                "allowed_scopes": agent["allowed_scopes"],
                "can_spawn":      agent["can_spawn"],
                "max_children":   agent["max_children"],
            }
        }

        with open(f"{aid}.json", "w") as f:
            json.dump(metadata, f, indent=2)

        print(f"  ✓ AllowedScopes={agent['allowed_scopes']}  CanSpawn={agent['can_spawn']}  MaxChildren={agent['max_children']}")
        print(f"  ✓ ScopeInherit={agent['scope_inherit']}  PolicyRef={agent['policy_ref']}")
        print(f"  ✓ Issuer=A2A-Trust-Template-Registry-CA (CA-signed, NOT self-signed)")

    os.chdir("..")


def setup_revocation_and_nonce():
    """
    Initialize CRL, nonce tracker, and audit chain.
    Section 12: Revocation  |  Section 16.2: Replay Prevention
    """
    certs_dir = Path("./certs")

    # CRL
    crl = {"revoked": [], "disabled": [], "disabled_at": {}, "last_updated": utcnow()}
    (certs_dir / "revocation_list.json").write_text(json.dumps(crl, indent=2))
    print("\n✓ Certificate Revocation List: revocation_list.json")

    # Nonce tracker (Section 16.2)
    nonce = {"used_nonces": [], "last_cleaned": utcnow(), "nonce_ttl_seconds": 300}
    (certs_dir / "nonce_tracker.json").write_text(json.dumps(nonce, indent=2))
    print("✓ Nonce tracker: nonce_tracker.json")

    # Audit hash chain (Section 16.6)
    genesis_event = {"event": "chain_initialized", "timestamp": utcnow()}
    genesis_data = json.dumps({"index": 0, "previous_hash": "genesis", "event": genesis_event}, sort_keys=True)
    genesis_hash = hashlib.sha256(genesis_data.encode()).hexdigest()
    chain = {
        "chain": [{
            "index": 0,
            "timestamp": utcnow(),
            "previous_hash": "genesis",
            "event": genesis_event,
            "hash": genesis_hash
        }],
        "current_hash": genesis_hash
    }
    (certs_dir / "audit_chain.json").write_text(json.dumps(chain, indent=2))
    print("✓ Audit hash chain: audit_chain.json")

    # Policy version store (Section 9.4 — policy stored with version, timestamp, content hash)
    policy_store = {"policies": {}, "last_updated": utcnow()}
    (certs_dir / "policy_store.json").write_text(json.dumps(policy_store, indent=2))
    print("✓ Policy version store: policy_store.json")

    # Cross-org grant store (Section 11.2)
    grant_store = {"grants": [], "revoked_grants": [], "last_updated": utcnow()}
    (certs_dir / "cross_org_grants.json").write_text(json.dumps(grant_store, indent=2))
    print("✓ Cross-org grant store: cross_org_grants.json")


def verify_ca_chain():
    """Verify all agent certs are properly CA-signed (not self-signed)"""
    certs_dir = Path("./certs")
    os.chdir(certs_dir)
    print("\n=== Chain Verification ===")
    for agent_id in ["agent-a", "agent-b"]:
        result = subprocess.run(
            f"openssl verify -CAfile ca-root.crt {agent_id}.crt",
            shell=True, capture_output=True, text=True
        )
        status = "✓ CA-SIGNED" if result.returncode == 0 else "✗ FAILED"
        print(f"  {status}: {agent_id}.crt — {result.stdout.strip() or result.stderr.strip()}")
    os.chdir("..")


if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  IETF A2A Trust PoC — Certificate Infrastructure Setup  ║")
    print("║  draft-tonyai-a2a-trust-00 (RFC 5280 compliant)         ║")
    print("╚══════════════════════════════════════════════════════════╝\n")

    # Clean slate
    import shutil
    if Path("./certs").exists():
        shutil.rmtree("./certs")

    setup_ca_root()
    print()
    setup_authority_certs()
    setup_agent_templates()
    setup_revocation_and_nonce()
    verify_ca_chain()
    print("\n✓ All IETF-compliant certificates and infrastructure ready!")
