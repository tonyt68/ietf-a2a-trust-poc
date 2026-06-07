# A2A Trust — Scale-Out and Production Implementation Guide

**Reference Implementation:** `draft-tonyai-a2a-trust-00`
**Repository:** https://github.com/tonyt68/ietf-a2a-trust-poc
**Status:** PoC → Production Scaling Guide

---

## 1. Purpose

This document accompanies the IETF draft `draft-tonyai-a2a-trust-00` and serves as the
**reference implementation guide** required by Section 14.5 of the draft. It demonstrates
that the protocol is implementable, security-tested, and scalable to production deployments.

It addresses three questions IETF reviewers ask of any draft seeking Standards Track:

1. **Can it be implemented?** — Yes. This PoC implements every MUST and SHOULD in the draft.
2. **Is it secure?** — Yes. 34 red team attacks blocked, 50/50 conformance vectors certified.
3. **Can it scale?** — Yes. This document describes the path from PoC to production.

---

## 2. Reference Implementation Summary

The PoC implements `draft-tonyai-a2a-trust-00` in full across four Docker services:

| Service | Role | Data Store | IETF Section |
|---|---|---|---|
| `mcp_server` | Authorization enforcement, CRL checks, audit chain | Reads from filesystem (certs/) | §6, §8, §12, §13 |
| `admin_bootstrap` | Template Registry CA, policy authority, cert lifecycle | Writes to filesystem + DynamoDB | §6.1, §9, §10 |
| `demo_web` | 11 scenario runner with real Claude API calls | No state store | §14.5 |
| `dynamodb_local` | **Write-only** — for prod architecture demo | Not read by MCP server in PoC | §7.1 (Template Registry) |

### 2.1 Conformance Certification

```
python3 tests/test_vectors.py

50/50 vectors passed — CONFORMANCE CERTIFIED
Sections covered: 6, 7, 8, 8.3, 9.3, 9.4, 11, 12, 13, 16.6
```

### 2.2 Security Test Results

```
python3 tests/red_team_test.py

34/34 attacks blocked — 0 findings
§16.1 Scope Escalation     6/6  blocked  (A01-A05 + A31 symmetric scope test)
§16.2 Replay Attacks       5/5  blocked  (A06-A10)
§16.3 Cert Attacks         6/6  blocked  (A11-A16)
§16.4 Dual-Sig Bypass      4/4  blocked  (A17-A20)
§16.5 Cross-Org Trust      2/2  blocked  (A21-A22)
§16.6 Audit Integrity      1/1  blocked  (A23)
OWASP General              7/7  blocked  (A24-A30: DoS, type confusion, injection, path traversal)
OWASP A06 Components       1/1  blocked  (A32: dependency version scan)
OWASP A10 SSRF             2/2  blocked  (A33-A34: embedded URL + Host header injection)
─────────────────────────────────────────
Total                     34/34 blocked  Full IETF §16 + OWASP Top 10 coverage
```

### 2.3 Startup Verification

```
python3 tests/smoke_test.py

33/33 checks passed — system ready for demo
Checks: certs, env vars, Cedar policies, service health,
        DynamoDB, S3, Anthropic API key, end-to-end write + deny
```

---

## 3. PoC Architecture (Current)

```
┌─────────────────────────────────────────────────────────────┐
│                     Docker Compose (local)                  │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  demo_web    │───▶│  mcp_server  │    │  DynamoDB    │  │
│  │  :8765       │    │  :8001       │    │  Local :8000 │  │
│  │              │    │              │    │  (write-only)│  │
│  │  Scenario    │    │  Cert Valid  │◀───│  not read    │  │
│  │  Runner      │    │  (reads JSON)│    └──────────────┘  │
│  │  (Claude)    │    │  Cedar Eval  │                       │
│  └──────────────┘    │  Replay Prev │    ┌──────────────┐  │
│       │              │  Audit Chain │───▶│  AWS S3      │  │
│       └──────────────▶└──────────────┘    │  (real)      │  │
│                           │               └──────────────┘  │
│  ┌──────────────┐         │ (reads/writes JSON)            │
│  │admin_        │◀────────┘ certs/ (mounted volume)        │
│  │bootstrap     │    ├── ca-root.{crt,key}                │
│  │:8002         │    ├── owner.{crt,key}                  │
│  │              │    ├── pa.{crt,key}                     │
│  │  CertManager │────├── agent-{a,b}.{crt,key,json}  ◀────┴─(reads state)
│  │  (writes     │    ├── revocation_list.json             │
│  │   JSON+DB)   │    ├── nonce_tracker.json               │
│  └──────────────┘    ├── audit_chain.json                 │
│                      └── cross_org_grants.json             │
└─────────────────────────────────────────────────────────────┘

KEY: PoC uses FILESYSTEM as source of truth
     └─ agent-{a,b}.json is read by cert_validator
     └─ DynamoDB writes are "best-effort, non-blocking"
     └─ if DynamoDB fails, PoC continues normally
```

---

## 4. PoC → Production Gap Analysis

Every gap between the PoC and a production deployment is documented here.
None represent protocol design flaws — they are operational hardening steps.

### 4.1 Certificate Authority

| PoC | Production |
|---|---|
| Self-signed CA root (`setup_keys.py`) | Enterprise CA (HashiCorp Vault PKI, AWS Private CA, or public CA) |
| Certs stored as files in `certs/` | Certs stored in AWS Secrets Manager or HashiCorp Vault |
| Manual cert generation | Automated CSR → CA signing via API |
| No OCSP | OCSP stapling for real-time revocation status |

**Why this does not affect the protocol:** The draft is CA-agnostic. Section 6 requires
X.509 certificate chains per RFC 5280, not a specific CA implementation.
Any RFC 5280-compliant CA works.

### 4.2 Template Registry and State Store

#### PoC Implementation (Filesystem Primary)

The PoC uses **filesystem as the source of truth** with DynamoDB as write-only secondary:

| Component | Storage | Read Path | Write Path |
|-----------|---------|-----------|-----------|
| Agent metadata | `certs/agent-{a,b}.json` | ✓ Read on every request | Write then DynamoDB |
| Certificate state | `certs/agent-{a,b}.json` | ✓ Read by cert_validator | Write then DynamoDB |
| DynamoDB table | `template_registry` | ✗ Never read in PoC | Write-only (best-effort) |

**Why filesystem in PoC:**
- Eliminates DynamoDB dependency for local testing
- Fast (~5ms filesystem I/O vs ~50ms network)
- Works completely offline
- Simplifies credential configuration

**Why DynamoDB writes exist:**
- Architecturally document the production path
- Enable smoke tests to verify DynamoDB integration (write-only)
- All writes are "best-effort, non-blocking" — if DynamoDB fails, PoC continues normally

#### Production Implementation (DynamoDB Primary)

| PoC | Production |
|---|---|
| Filesystem primary, DynamoDB write-only | DynamoDB primary (all reads/writes) |
| `certs/` local volume | DynamoDB replicated, multi-AZ, GSI indexes |
| No TTL index | DynamoDB TTL on `expires_at` for auto-expiry |
| No replication | DynamoDB Global Tables for multi-region |
| Single host, no distributed consistency | Multiple MCP servers, strong consistency |

**Production state flow (§10.4 lifecycle):**
```
Admin API: PUT /template/{agent_id}/state
  ↓
CertManager.update_state() writes to DynamoDB
  ↓
MCP Server: reads Template Registry from DynamoDB
  ↓
cert_validator checks: state == "ACTIVE" (block if DISABLED/DELETED)
```

**Scaling note:** The Template Registry is read-heavy, write-rare. DynamoDB on-demand
handles this efficiently. A 10,000-agent deployment at 1,000 reads/second costs ~$15/month.

#### Architectural Rationale: Why Filesystem in PoC?

This is a deliberate trade-off for PoC simplicity:

**PoC Constraints:**
- Single docker-compose, one host
- No distributed consistency issues
- No need to coordinate reads across multiple servers
- Local storage is always available

**Production Requirement:**
- Multiple MCP servers need authoritative shared state
- Distributed consistency is mandatory (§7.1 state checks must agree)
- Network latency acceptable (reads cached locally)
- Durability + replication required

**Migration path:**
```
PoC Phase 1 (current):
  Filesystem primary → write to both → DynamoDB catch-up

PoC Phase 2 (optional):
  Add DynamoDB reads for multi-server testing
  
Production Phase 1:
  Switch read path: filesystem → DynamoDB
  All state reads from DynamoDB
  All state writes to DynamoDB + S3 backup
  
Production Phase 2:
  DynamoDB Global Tables for multi-region
  Multi-region agents read local DynamoDB replica
```

### 4.3 Nonce Tracker (Replay Prevention)

| PoC | Production |
|---|---|
| File-based JSON with `fcntl.flock` | Amazon ElastiCache (Redis) `SET NX EX` |
| Single process, single host | Distributed (multiple MCP server replicas) |
| 5-minute TTL, manual cleanup | Redis TTL handles expiry automatically |

**Production nonce check (atomic, distributed-safe):**
```python
if not redis.set(f"nonce:{nonce}", "1", nx=True, ex=300):
    return (False, "Nonce already used (replay attack detected)")
```

### 4.4 Audit Chain (Tamper-Evident Log)

| PoC | Production |
|---|---|
| File-based SHA-256 hash chain | AWS CloudTrail + CloudWatch Logs (immutable) |
| Single file, local disk | Replicated, append-only, deletion-protected |
| Verified on-demand | CloudTrail integrity validation built-in |

**Cross-org audit (§11.5):** Each org maintains independent audit in its own
CloudWatch log group. Neither party can modify the other's audit trail.

### 4.5 Policy Store

| PoC | Production |
|---|---|
| `policy_store.json` (local file) | OPA server with S3-backed bundle API |
| File-based dual-sig storage | S3 bundles signed with owner + PA keys |
| Reload on file change | OPA bundle polling (5-minute interval) |

**Production policy change sequence (§9.4):**
```
1. Owner signs policy bundle → uploads to S3
2. PA validates → countersigns → uploads signed manifest
3. OPA servers poll S3, verify dual-sig before loading
4. Agents validate at runtime: sig + hash + version
```

### 4.6 CRL Distribution

| PoC | Production |
|---|---|
| `revocation_list.json` (local file) | CRL via HTTPS (RFC 5280 CRL Distribution Point) |
| Reloaded on each CRL check | Cached 5 min, served from CloudFront |
| No cascading revocation | DynamoDB Streams → Lambda → propagates to derived certs |

---

## 5. Production Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Production Deployment                        │
│                                                                     │
│  ┌─────────────┐    ┌──────────────────────────────────────────┐   │
│  │  Agent(s)   │───▶│           API Gateway + WAF              │   │
│  └─────────────┘    └──────────────┬───────────────────────────┘   │
│                         ┌──────────▼─────────┐                     │
│                         │  MCP Server Fleet   │                     │
│                         │  (ECS Fargate)      │                     │
│                         │  Auto-scaling       │                     │
│                         └──────────┬──────────┘                     │
│              ┌──────────┬──────────┼──────────┬──────────┐         │
│              ▼          ▼          ▼          ▼          ▼         │
│         ┌────────┐ ┌────────┐ ┌───────┐ ┌──────┐ ┌──────────┐    │
│         │  AWS   │ │ Redis  │ │  OPA  │ │  S3  │ │CloudWatch│    │
│         │Private │ │(Nonce) │ │(Policy│ │(Event│ │  Logs    │    │
│         │  CA    │ │        │ │Store) │ │Store)│ │(Audit)   │    │
│         └────────┘ └────────┘ └───────┘ └──────┘ └──────────┘    │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │            Admin Bootstrap (Lambda)                           │  │
│  │  CA operations  │  Policy Authority  │  CRL management        │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │         Template Registry (DynamoDB Global Tables)           │  │
│  │  Multi-region  │  TTL auto-expiry  │  Streams → Lambda       │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 6. Scaling Numbers

Mid-size enterprise: 10,000 agents, 5 organizations.

| Component | PoC | Production |
|---|---|---|
| MCP Server | 1 container, 1 CPU | 10 ECS tasks, auto-scale to 50 |
| Template Registry | DynamoDB Local | DynamoDB on-demand, ~$15/month |
| Nonce store | File + flock | Redis cluster, 3 nodes |
| CRL size | ~1KB | ~100KB for 10K agents |
| Cert issuance | Manual | <500ms via AWS Private CA API |
| Policy reload | File watch | OPA bundle poll, 5-min lag |
| Audit throughput | ~100 events/sec | Unlimited (CloudWatch) |
| Spawn validation latency | ~50ms (local) | ~10ms (DynamoDB + Redis) |

---

## 7. Multi-Organization Federation (Section 11)

### 7.1 Trust Anchor Options (§11.3)

**Option A — Shared Root CA (simplest):**
```
IETF A2A Trust Root CA
├── Org-A Template Registry CA
│   ├── agent-a (Org-A)
│   └── agent-b (Org-A)
└── Org-B Template Registry CA
    ├── agent-x (Org-B)
    └── agent-y (Org-B)
```

**Option B — Explicit CA Trust (bilateral):**
Org-A explicitly trusts Org-B's CA. No shared root required. Better for regulated
industries (healthcare, finance).

**Option C — Public CA:**
Both orgs use a public CA. Simplifies trust negotiation but requires the CA to
support agent template extensions.

### 7.2 Cross-Org Grant Lifecycle

```
1. Org-B requests access to Org-A's agent-template-v1

2. Org-A issues cross-org grant (§11.2):
   {
     grantor: "org-a", grantee: "org-b",
     template: "agent-template-v1",
     allowed_scopes: ["read:data"],     # MUST be subset of template scopes
     ttl_seconds: 86400, max_spawns: 100,
     owner_sig: <Org-A RSA signature>,
     pa_sig: <Org-A PA RSA signature>   # dual-sig required
   }

3. Org-B agents spawn from grant — scopes bounded by grant AllowedScopes

4. Org-A revokes unilaterally (§11.4) — Org-B agents denied on next validation

5. New template version → grant does NOT auto-roll-over (§10.5)
```

---

## 8. RFC Compliance Checklist

### Section 6 — Agent Identity
- [ ] Agent templates are X.509 certs signed by Template Registry CA (RFC 5280)
- [ ] Agents obtain identity via CSR → CA signing (not self-signed)
- [ ] Certificate chain validates to trusted CA root
- [ ] Key size minimum 2048-bit RSA

### Section 7 — Template Structure (all REQUIRED fields)
- [ ] Subject, Issuer, Owner, OrgID, KeyUsage present
- [ ] AllowedScopes — maximum scopes this agent may hold
- [ ] CanSpawn — whitelist of permitted child templates
- [ ] MaxChildren — enforced at spawn time
- [ ] ScopeInherit = strict-subset
- [ ] PolicyRef — points to current dynamic policy location
- [ ] TTL — maximum agent lifetime

### Section 8 — Spawn Chain Validation
- [ ] Check 1 (Static): child template in parent CanSpawn list
- [ ] Check 2 (Dynamic): child registered, CA-signed, not revoked, ACTIVE
- [ ] Child AllowedScopes ⊆ parent AllowedScopes (strict subset enforced)
- [ ] MaxChildren not exceeded before spawn
- [ ] Spawn request includes timestamp and nonce
- [ ] Every spawn event logged with all required fields (§8.4)

### Section 9 — Dynamic Policy Governance
- [ ] Dynamic policies bounded by static template AllowedScopes
- [ ] Policy changes require Owner + PA dual signature
- [ ] Policy stored with version, timestamp, content hash
- [ ] Agents validate at runtime: sigs valid + hash matches + version current
- [ ] Cedar/OPA-granted scopes re-validated against cert bounds post-evaluation

### Section 10 — Template Versioning
- [ ] New versions undergo full re-verification (no trust inheritance)
- [ ] Cross-org grants do not auto-roll-over on version upgrade
- [ ] DISABLED: no new spawns, existing agents run to TTL
- [ ] DELETED: irreversible, CRL updated, registry entry removed
- [ ] Waiting period enforced between DISABLED and DELETED

### Section 11 — Cross-Org
- [ ] Explicit grant required (no implicit inter-org trust)
- [ ] Grant contains all required fields (§11.2 Table 3)
- [ ] Grant requires dual signature (grantor owner + PA)
- [ ] Grantor can revoke unilaterally without grantee cooperation
- [ ] Each org maintains independent audit trail (§11.5)

### Section 12 — Revocation
- [ ] Template revocation adds cert to CA CRL
- [ ] All derived agents treated as untrusted on next CRL check
- [ ] TTL expiry revocation fully automated (no human required)
- [ ] CRL reachable within 5 minutes of revocation event

### Section 13 — Fail Closed
- [ ] CA, Registry, or CRL unreachable → DENY (no degraded mode)
- [ ] Certificate expired or revoked → DENY
- [ ] Scope escalation → DENY
- [ ] Policy invalid or unsigned → DENY
- [ ] Dual signature missing or invalid → DENY

---

## 9. Performance Optimizations

### 9.1 Certificate Validation Caching
```python
@lru_cache(maxsize=1000, ttl=300)
def validate_cert_cached(agent_id: str, cert_fingerprint: str) -> tuple:
    return cert_validator.validate_cert(agent_id, cert_path)
```
Cache keyed on cert fingerprint — invalidated when cert changes.

### 9.2 CRL Negative Caching
```python
crl_cache = TTLCache(maxsize=10000, ttl=300)

def check_crl_cached(agent_id: str) -> bool:
    if agent_id in crl_cache:
        return crl_cache[agent_id]
    result = check_crl_live(agent_id)
    crl_cache[agent_id] = result
    return result
```
Revocation pushes cache invalidation via DynamoDB Streams → Lambda → Redis pub/sub.

### 9.3 Atomic Nonce Check (Redis)
```python
def validate_nonce(nonce: str) -> bool:
    return redis.set(f"nonce:{nonce}", "1", nx=True, ex=300)
```

---

## 10. Observability

### 10.1 Required Metrics
```
a2a_trust_spawn_total{outcome="allowed|denied",reason="..."}
a2a_trust_cert_validation_duration_seconds
a2a_trust_crl_check_duration_seconds
a2a_trust_policy_eval_duration_seconds
a2a_trust_nonce_collisions_total
a2a_trust_audit_chain_blocks_total
```

### 10.2 Required Alerts
```
cert_validation_failures > 5/min  → likely revocation event
crl_unreachable                   → immediate page (fail-closed = outage)
nonce_collisions > 0              → replay attack attempt
audit_chain_integrity_failed      → tamper detected, investigate immediately
policy_dual_sig_failures > 0      → unauthorized policy change attempt
```

### 10.3 Required Audit Log Fields (§8.4)
```json
{
  "event_type": "spawn",
  "correlation_id": "<uuid-v4>",
  "span_id": "<uuid-v4>",
  "spawning_agent": "<agent-id>",
  "child_template": "<template-id>",
  "requested_scope": ["<scope>"],
  "granted_scope": ["<scope>"],
  "timestamp": "<iso-8601-utc>",
  "outcome": "ALLOWED | DENIED",
  "reason": "<string if DENIED>",
  "stages_passed": ["cert_validation", "replay_prevention", "crl_check",
                    "scope_subset", "cedar_policy"],
  "cert_fingerprint": "<sha256>",
  "policy_version": "<int>",
  "nonce": "<uuid-v4>"
}
```

---

## 11. Known PoC Limitations

These are documented scope limitations, not protocol deficiencies.

| Limitation | Production Solution | Protocol Impact |
|---|---|---|
| File-based nonce tracker | Redis `SET NX EX` | None — protocol is store-agnostic |
| File-based audit chain | CloudWatch + CloudTrail | None — protocol requires tamper-evidence, not a specific store |
| Self-signed CA root | AWS Private CA / Vault | None — protocol is CA-agnostic |
| Single-region | DynamoDB Global Tables | None — protocol is topology-agnostic |
| No OCSP | OCSP stapling via CA | Enhancement only |
| No cert management UI | Admin API exists | Out of scope for protocol spec |

---

## 12. Path to RFC

### Current Status (Informational Draft)
- ✅ Reference implementation (this PoC — §14.5)
- ✅ Conformance test suite (50/50 vectors — §14.3)
- ✅ Security analysis (34/34 attacks blocked, full OWASP Top 10)
- ✅ Implementation guide (this document)

### Required for Standards Track
- [ ] Two independent implementations (this PoC is #1)
- [ ] IETF Working Group adoption (recommend SACM or RATS WG)
- [ ] Security directorate review
- [ ] IANA considerations for OIDs (agent template X.509 extensions)
- [ ] Normative language review (RFC 2119 MUST/SHOULD audit)
- [ ] Interoperability test between two independent implementations

**Suggested WG:** RATS (Remote ATtestation procedureS) or a new A2A Trust WG
under the Security Area. The protocol reuses RATS attestation chain concepts
applied to AI agent identity.

---

## Appendix A: Quick Start

```bash
# 1. Clone
git clone https://github.com/tonyt68/ietf-a2a-trust-poc
cd ietf-a2a-trust-poc

# 2. Configure
cp .env.example .env
# Edit: ANTHROPIC_API_KEY, AWS credentials, S3 bucket, DynamoDB table

# 3. Generate IETF-compliant X.509 certificates
python3 setup_keys.py

# 4. Start with full test gate (static tests → services → smoke)
./restart.sh

# 5. Conformance (no server needed, runs in seconds)
python3 tests/test_vectors.py

# 6. Security (server required)
python3 tests/red_team_test.py

# 7. Demo
open http://localhost:8765
```

## Appendix B: File Map

```
ietf-a2a-trust-poc/
├── setup_keys.py                    # IETF-compliant cert generation (CSR → CA flow)
├── restart.sh                       # Gated start: tests → services → smoke
├── SCALE_OUT.md                     # This document
├── demo/
│   ├── start.sh                     # Demo day start script
│   ├── app.py                       # Demo web service
│   └── scenario_runner.py           # 11 scenarios with real Claude Sonnet API
├── services/
│   ├── mcp_server/
│   │   ├── service.py               # 8-stage IETF validation chain
│   │   ├── cert_validator.py        # RFC 5280 certificate validation
│   │   ├── replay_prevention.py     # §16.2 nonce + timestamp (fcntl locked)
│   │   ├── audit_chain.py           # §16.6 tamper-evident SHA-256 hash chain
│   │   └── cedar_policy_eval.py     # §9 dynamic policy evaluation
│   └── admin_bootstrap/
│       ├── policy_authority.py      # §9.3 dual-signature (RSA X.509)
│       ├── cert_manager.py          # §10 template lifecycle + CRL
│       └── cross_org_grant.py       # §11 cross-org grant management
├── tests/
│   ├── test_vectors.py              # §14.3 conformance vectors (50 tests, no server)
│   ├── smoke_test.py                # Startup verification (33 checks, server required)
│   └── red_team_test.py             # §16 security attack suite (34 attacks)
├── policies/
│   ├── agent-a.cedar                # Dynamic policy: read:events only
│   └── agent-b.cedar                # Dynamic policy: write:events only
└── certs/                           # Generated by setup_keys.py (gitignored)
    ├── ca-root.{crt,key}            # Template Registry CA (root of trust)
    ├── owner.{crt,key}              # Owner Authority (dual-sig)
    ├── pa.{crt,key}                 # Policy Authority (dual-sig)
    ├── agent-{a,b}.{crt,key,json}  # Agent templates (CA-signed via CSR)
    ├── revocation_list.json         # CRL (§12)
    ├── nonce_tracker.json           # Replay prevention (§16.2)
    ├── audit_chain.json             # Tamper-evident hash chain (§16.6)
    ├── policy_store.json            # Policy versions + hashes (§9.4)
    └── cross_org_grants.json        # Cross-org grants (§11.2)
```
- Two agents (Agent A, Agent B) as local FastAPI services
- Cedar SDK running in-process (local policy evaluation)
- Docker Compose for local multi-agent environment
- Self-signed certs for mTLS (OpenSSL)
- PostgreSQL + Google Cloud Logging + CloudWatch for audit
- Terraform for AWS + GCP infrastructure

---

## Scale Out Path

### Phase 1 — Cloud Native (Single Org)
- Deploy Agent A and Agent B to AWS ECS or GCP Cloud Run via Terraform
- Replace self-signed certs with HashiCorp Vault PKI or AWS ACM (managed CA)
- Replace Cedar SDK local with Amazon Verified Permissions (AVP) for managed policy evaluation
- PostgreSQL → AWS RDS or GCP Cloud SQL (managed, HA)
- Add horizontal scaling: multiple Agent B instances behind API Gateway

### Phase 2 — Multi-Org Federation
- Introduce Template Registry service — central CA that signs agent certificates
- Cross-org grant flow: Org A issues signed grant to Org B via Template Registry
- Each org maintains independent audit trail — no shared audit DB
- Federated CRL (Certificate Revocation List) — revoke across org boundaries
- mTLS with org-issued certs replacing self-signed

### Phase 3 — Enterprise / FedRAMP
- Replace AVP with OPA or Cedar + Styra (enterprise policy management)
- KMS-signed audit records (tamper-evident, S3 Object Lock COMPLIANCE mode)
- FIPS 140-3 compliant crypto throughout (AWS GovCloud or equivalent)
- SOC2 / FedRAMP High control mapping documented

---

## Trade-offs

### Cedar SDK Local vs Amazon Verified Permissions
| | Cedar SDK Local | Amazon Verified Permissions |
|---|---|---|
| Cost | Free | Pay per authorization request |
| Latency | In-process (~1ms) | API call (~10-50ms) |
| Audit | Manual | Built-in AVP audit trail |
| Scale | Single process | Managed, multi-tenant |
| PoC fit | Perfect | Overkill for demo |
| Prod fit | Limited | Recommended |

**Decision:** Cedar SDK local for PoC. Document AVP as the production path.

### Self-Signed Certs vs Managed CA
| | Self-Signed (OpenSSL) | HashiCorp Vault PKI / AWS ACM |
|---|---|---|
| Cost | Free | Vault: free OSS; ACM: free for AWS services |
| Setup | Minutes | Hours (Vault) / Minutes (ACM) |
| Rotation | Manual | Automatic |
| CRL | Manual | Automatic |
| PoC fit | Perfect | Overkill |
| Prod fit | Never | Required |

**Decision:** OpenSSL self-signed for PoC. Document Vault PKI as production path.

### Docker Compose vs Kubernetes
| | Docker Compose | Kubernetes (EKS/GKE) |
|---|---|---|
| Complexity | Low | High |
| Cost | Free (local) | $$$  |
| Demo portability | High | Low |
| Scale | Single host | Multi-node |
| PoC fit | Perfect | Overkill |

**Decision:** Docker Compose for PoC. Note EKS/GKE as production path.

### Single Correlation ID Strategy
- UUID v7 (time-ordered) generated at Agent A request initiation
- Stamped on every layer: JWT claims, HMAC payload, Cedar policy decision, audit log entry, GCP log, CloudWatch log
- Enables full end-to-end trace across both clouds from a single ID
- Trade-off: if correlation ID is lost at any layer, traceability breaks — every layer MUST propagate it

---

## Resume Keywords This PoC Adds
- Cedar (Policy as Code)
- Amazon Verified Permissions (scale-out path)
- Google Cloud Logging
- Vertex AI (GCP)
- Terraform (multi-cloud IaC)
- mTLS
- JWT chain validation
- HMAC-SHA256
- Federated audit
- IETF Internet-Draft reference implementation
- HashiCorp Vault PKI (scale-out path)
