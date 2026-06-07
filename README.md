# A2A Trust — IETF Reference Implementation

Reference implementation of [draft-tonyai-a2a-trust-00](https://datatracker.ietf.org/doc/draft-tonyai-a2a-trust/) — Agent-to-Agent trust enforcement via X.509 cryptographic identity, least privilege, dual-signature policy governance, and fail-closed enforcement.

**Conformance:** 50/50 test vectors certified · 34/34 security attacks blocked · Full OWASP Top 10 coverage

---

## What This PoC Proves

Each of the 11 demo scenarios maps directly to a requirement in the IETF draft:

| # | Scenario | Expected | Section |
|---|---|---|---|
| 1 | Golden path — full auth chain validates | ALLOWED | §6, §8, §9 |
| 2 | Dynamic policy update (dual-signed) | ALLOWED | §9.3, §9.4 |
| 3 | Rogue spawn — not in CanSpawn list | DENIED | §8.1 |
| 4 | Dual-sig missing — PA sig absent | DENIED | §9.3 |
| 5 | Dual-sig tampered — PA sig corrupted | DENIED | §9.3 |
| 6 | Scope escalation — child requests beyond AllowedScopes | DENIED | §8.3, §16.1 |
| 7 | Cert lifecycle — ACTIVE → DISABLED → DELETED state machine | DENIED² | §10.4 |
| 8 | CRL check — agent with no registered cert (simulates revocation) | DENIED | §12.1 |
| 9 | TTL expiry — agent with no valid cert (simulates expiry) | DENIED | §12.3 |
| 10 | Cross-org grant — dual-signed, TTL-limited, unilateral revocation | ALLOWED | §11.2, §11.4 |
| 11 | Replay attack — same nonce sent twice | DENIED (2nd) | §16.2 |

² Scenario 7 demonstrates the lifecycle state machine: (1) Write while ACTIVE → ALLOWED (2) Admin API disables agent-b (3) Write while DISABLED → DENIED (final decision). This proves §10.4 enforcement: disabled certs cannot issue credentials.

---

## Quick Start

### Prerequisites
- Docker + Docker Compose
- Python 3.12+
- AWS credentials (S3)
- Anthropic API key

### 1. Configure

```bash
cp .env.example .env
# Edit .env: ANTHROPIC_API_KEY, AWS credentials, S3_BUCKET
```

### 2. Generate Certificates

```bash
python3 setup_keys.py
```

Generates IETF-compliant X.509 certificates via CSR → CA signing flow (Section 6.1).

### 3. Start with Full Test Gate

```bash
./demo/start.sh
```

Runs in five gated stages:
1. **IETF conformance** — 50 vectors (X.509, template fields, spawn chain, scope constraints, dual-sig)
2. **Policy signature tests** — 8 tests (Phase 1: owner signs identity, Phase 2: PA signs policy)
3. **Policy field guard tests** — 9 tests (cert identity immutability enforcement)
4. **Service startup** — Docker Compose with health-check polling
5. **Smoke tests** — 33 live checks (certs, env, services, end-to-end)

All stages must pass or startup fails with clear error message.

### 4. Run Security Tests

```bash
python3 tests/red_team_test.py
```

34 attacks across all IETF Section 16 threat vectors + OWASP Top 10.

---

## Services

| Service | Port | Role |
|---|---|---|
| `mcp_server` | 8001 | Authorization enforcement — 8-stage IETF validation chain |
| `admin_bootstrap` | 8002 | Template Registry CA, policy authority, cert lifecycle |
| `demo_web` | 8765 | 11 demo scenarios with real Claude Sonnet API calls |

---

## Validation Chain

Every request through the MCP server passes the following checks in order. Any failure → DENY.

```
[security]  agent_id format validation       (allowlist regex — blocks injection + path traversal)
[§6]        X.509 certificate validation     (RFC 5280 chain, CA-signed, not expired, state check)
[§16.2]     Replay prevention                (nonce uniqueness + timestamp freshness, file-locked)
[§12]       CRL + Chain of custody check     (revocation, disabled, TTL expiry, auth cert chain)
[§9.3]      Dual-signature validation (if policy_update)
            ├─ Phase 1: owner_sig verifies cert identity fields (unchanged proof)
            ├─ Phase 2: pa_sig verifies policy fields only (authorization)
            └─ Both must pass — single sig insufficient
[§9.3]      Policy field guard               (can_spawn, max_children immutable — cert change required)
[§9.3]      Required-field validation        (policy_doc must include owner, created_at)
[§7]        Authorization bounds             (AllowedScopes, CanSpawn, MaxChildren from cert)
[§8.3]      Scope subset validation          (requested ⊆ cert AllowedScopes — fail-closed)
[§9]        Cedar policy evaluation          (dynamic policy layer, post-grant subset re-check)
            S3 write
[§16.6]     Audit chain append               (SHA-256 hash chain, tamper-evident)
```

The agent_id format check is an implementation security measure. The remaining steps map directly to the IETF draft sections shown.

---

## Security Properties

- **No secrets in code** — all via `.env` (gitignored); no hardcoded keys/credentials
- **X.509 certificates** — generated via CSR → CA signing (not self-signed agents); state machine enforcement (ACTIVE → DISABLED → DELETED via §10.4)
- **Dual-signature enforcement** — Owner signs cert identity (proves unchanged), PA signs policy (authorizes update); both must verify
- **Certificate identity immutability** — can_spawn, max_children require new certificate to change (not policy-updatable)
- **Required-field validation** — policy_doc must include owner, created_at to prevent incomplete policies
- **Chain of custody validation** — Owner and PA certs validated for expiry, revocation, and CA chain (cached with 60s TTL for success, 5s for failures)
- **CRL with automatic invalidation** — revocation cache key includes CRL file size; same-mtime restore scenario handled
- **Fail-closed at every stage** — infrastructure unreachable → DENY; missing metadata → DENY
- **Tamper-evident audit trail** — SHA-256 hash chain (genesis block + linked entries); detects modifications
- **Replay prevention** — file-locked nonce tracker with fcntl.LOCK_EX; timestamp freshness window
- **Safe subprocess calls** — no shell=True; list-form subprocess with timeout; stderr captured for logging
- **Atomic metadata writes** — JSON metadata read before truncate to prevent corruption on crash

---

## Tests

```bash
# IETF conformance vectors (no server needed, ~3 seconds)
python3 tests/test_vectors.py                # 50/50 (cert, template structure, spawn, scope, dual-sig, CRL, audit)

# Dual-signature validation (no server, ~2 seconds)
python3 tests/test_policy_signatures.py      # 8/8 (Phase 1 identity, Phase 2 policy, tamper detection)

# Policy field guard (no server, ~1 second)
python3 tests/test_policy_field_guard.py     # 9/9 (immutable fields, unknown fields, required fields)

# Startup verification (server required, ~30 seconds)
python3 tests/smoke_test.py                  # 33/33 (certs, env, services, end-to-end)

# Security attack suite (server required, ~45 seconds)
python3 tests/red_team_test.py               # 34/34 (scope escalation, replay, cert attacks, dual-sig, OWASP)
```

**Total:** 134 test vectors + attack scenarios, 100% pass rate required for demo start

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                Docker Compose (local)               │
│                                                     │
│  demo_web ──▶ mcp_server                            │
│  (Claude)     (8-stage                              │
│               validation)                           │
│                   │                                 │
│          admin_bootstrap                            │
│          (CA · Policy Authority · CRL)              │
│                                                     │
│  Shared: certs/ volume (X.509 + CRL + audit chain) │
└─────────────────────────────────────────────────────┘
                        │
                   AWS S3 (events)
```

---

## Production Scale-Out

See [SCALE_OUT.md](SCALE_OUT.md) for the full production implementation guide including:
- PoC → Production gap analysis (CA, nonce store, audit, policy store, CRL)
- Production architecture diagram (ECS + Redis + OPA + DynamoDB Global Tables)
- Multi-organization federation (§11) with three trust anchor options
- RFC compliance checklist by section
- Path from Informational → Standards Track

---

## Repository Structure

```
ietf-a2a-trust-poc/
├── setup_keys.py                  # IETF-compliant cert generation (CSR → CA)
├── restart.sh                     # Gated start: static tests → services → smoke
├── SCALE_OUT.md                   # Production guide + RFC path
├── demo/
│   ├── start.sh                   # Demo day start (no rebuild)
│   ├── app.py                     # Demo web service
│   └── scenario_runner.py         # 11 scenarios with Claude Sonnet
├── services/
│   ├── mcp_server/
│   │   ├── service.py                     # Request validation pipeline (8+ stages)
│   │   ├── cert_validator.py              # RFC 5280 cert chain + state check (§6, §10.4)
│   │   ├── policy_validator.py            # Dual-signature validation (§9.3)
│   │   ├── policy_field_guard.py          # Cert identity immutability (§9.3, §7.1)
│   │   ├── policy_authority_chain.py      # Owner/PA cert validation + caching (§9.3, §12)
│   │   ├── replay_prevention.py           # Nonce + timestamp + file lock (§16.2)
│   │   └── audit_chain.py                 # Tamper-evident hash chain (§16.6)
│   └── admin_bootstrap/
│       ├── policy_authority.py            # Policy Authority signature operations (§9.3)
│       ├── cert_manager.py                # Template lifecycle + CRL (§10, §12)
│       └── cross_org_grant.py             # Cross-org grants (§11)
├── tests/
│   ├── test_vectors.py            # 50 conformance vectors (§14.3)
│   ├── smoke_test.py              # 33 startup checks
│   └── red_team_test.py           # 34 security attacks (§16)
├── policies/
│   ├── agent-a.cedar              # read:events
│   └── agent-b.cedar              # write:events
└── terraform/                     # AWS IaC (DynamoDB, S3, KMS, Secrets Manager)
```

---

## License

Reference implementation for [draft-tonyai-a2a-trust-00](https://datatracker.ietf.org/doc/draft-tonyai-a2a-trust/).
