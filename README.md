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
| 7 | Cert lifecycle — ACTIVE → DISABLED → DELETED state machine | ALLOWED¹ | §10.4 |
| 8 | CRL check — agent with no registered cert (simulates revocation) | DENIED | §12.1 |
| 9 | TTL expiry — agent with no valid cert (simulates expiry) | DENIED | §12.3 |
| 10 | Cross-org grant — dual-signed, TTL-limited, unilateral revocation | ALLOWED | §11.2, §11.4 |
| 11 | Replay attack — same nonce sent twice | DENIED (2nd) | §16.2 |

¹ Scenario 7 demonstrates the lifecycle state machine with a live agent-b (ACTIVE → write succeeds). A separate admin API call transitions the state; the demo narrates the concept per §10.4.

---

## Quick Start

### Prerequisites
- Docker + Docker Compose
- Python 3.12+
- AWS credentials (S3 + DynamoDB)
- Anthropic API key

### 1. Configure

```bash
cp .env.example .env
# Edit .env: ANTHROPIC_API_KEY, AWS credentials, S3_BUCKET, DYNAMODB_TABLE
```

### 2. Generate Certificates

```bash
python3 setup_keys.py
```

Generates IETF-compliant X.509 certificates via CSR → CA signing flow (Section 6.1).

### 3. Start with Full Test Gate

```bash
./restart.sh
```

Runs in three gated stages:
1. **Static tests** — 50 IETF conformance vectors (no server needed)
2. **Start services** — Docker Compose with health-check polling
3. **Smoke tests** — 33 live checks (certs, env, services, end-to-end)

Stops at the first failure with a clear error message.

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
| `dynamodb_local` | 8000 | Template Registry (local DynamoDB) |

---

## Validation Chain

Every request through the MCP server passes the following checks in order. Any failure → DENY.

```
[security]  agent_id format validation  (allowlist regex — blocks injection + path traversal)
[§6]        X.509 certificate validation (RFC 5280 chain, CA-signed, not expired)
[§16.2]     Replay prevention           (nonce uniqueness + timestamp freshness, file-locked)
[§12]       CRL check                   (revocation + disabled + TTL expiry — automated)
[§7]        Authorization bounds        (AllowedScopes, CanSpawn, MaxChildren from cert)
[§8.3]      Scope subset validation     (requested ⊆ cert AllowedScopes — fail-closed)
[§9]        Cedar policy evaluation     (dynamic policy layer, post-grant subset re-check)
            S3 write
[§8.4]      Audit chain append          (SHA-256 hash chain, tamper-evident)
```

The agent_id format check is an implementation security measure. The remaining steps map directly to the IETF draft sections shown.

---

## Security Properties

- No secrets in code, git, or containers — all via `.env` (gitignored)
- X.509 certificates generated via CSR → CA signing (not self-signed agents)
- Dual-signature enforcement on all policy changes (Owner + Policy Authority RSA)
- Fail-closed at every stage — infrastructure unreachable → DENY
- Tamper-evident audit trail (SHA-256 hash chain)
- Replay prevention with file-locked nonce tracker (fcntl.LOCK_EX)
- agent_id allowlist regex before any subprocess or filesystem use

---

## Tests

```bash
# IETF conformance (no server needed, runs in ~3 seconds)
python3 tests/test_vectors.py        # 50/50

# Startup verification (server required)
python3 tests/smoke_test.py          # 33/33

# Security attack suite (server required)
python3 tests/red_team_test.py       # 34/34
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                Docker Compose (local)               │
│                                                     │
│  demo_web ──▶ mcp_server ──▶ DynamoDB Local        │
│  (Claude)     (8-stage       (Template Registry)   │
│               validation)                          │
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
│   │   ├── service.py             # 8-stage validation chain
│   │   ├── cert_validator.py      # RFC 5280 chain validation
│   │   ├── replay_prevention.py   # Nonce + timestamp (§16.2)
│   │   └── audit_chain.py         # Tamper-evident hash chain (§16.6)
│   └── admin_bootstrap/
│       ├── policy_authority.py    # Dual-signature RSA (§9.3)
│       ├── cert_manager.py        # Template lifecycle + CRL (§10, §12)
│       └── cross_org_grant.py     # Cross-org grants (§11)
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
