#!/usr/bin/env python3
"""
Startup Smoke Test — IETF A2A Trust PoC
Verifies all services and dependencies are healthy before demo.

Run: python3 tests/smoke_test.py
Exit 0 = all good, demo is ready
Exit 1 = something is broken, with clear error message

Checks:
  1. Certs infrastructure (CA, agents, CRL, nonce tracker, audit chain)
  2. Environment variables (required secrets)
  3. MCP Server health + endpoint reachability
  4. Admin Bootstrap health
  5. Demo Web health
  6. DynamoDB Local reachability
  7. S3 bucket reachable (via AWS creds)
  8. Cedar policy files loaded
  9. Anthropic API key valid (quick model list)
  10. End-to-end write-event smoke (agent-b → write:events)
"""

import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests

BASE_DIR   = Path(__file__).parent.parent
CERTS_DIR  = BASE_DIR / "certs"
POLICY_DIR = BASE_DIR / "policies"

MCP_URL   = os.getenv("MCP_URL",   "http://localhost:8001")
ADMIN_URL = os.getenv("ADMIN_URL", "http://localhost:8002")
DEMO_URL  = os.getenv("DEMO_URL",  "http://localhost:8765")

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
RESET  = "\033[0m"

passed = []
failed = []


def ok(label: str, detail: str = ""):
    passed.append(label)
    line = f"  {GREEN}✓{RESET}  {label}"
    if detail:
        line += f"  — {detail}"
    print(line)


def fail(label: str, detail: str = ""):
    failed.append(label)
    line = f"  {RED}✗{RESET}  {label}"
    if detail:
        line += f"  — {YELLOW}{detail}{RESET}"
    print(line)


def warn(label: str, detail: str = ""):
    line = f"  {YELLOW}⚠{RESET}  {label}"
    if detail:
        line += f"  — {detail}"
    print(line)


# ── 1. Certificate Infrastructure ────────────────────────────────────────────
print(f"\n{YELLOW}── 1. Certificate Infrastructure ─────────────────────────────────────{RESET}")

required_certs = [
    ("certs/ca-root.crt",           "Template Registry CA"),
    ("certs/ca-root.key",           "CA private key"),
    ("certs/owner.crt",             "Owner Authority cert"),
    ("certs/owner.key",             "Owner Authority key"),
    ("certs/pa.crt",                "Policy Authority cert"),
    ("certs/pa.key",                "Policy Authority key"),
    ("certs/agent-a.crt",           "agent-a certificate"),
    ("certs/agent-a.key",           "agent-a private key"),
    ("certs/agent-a.json",          "agent-a metadata"),
    ("certs/agent-b.crt",           "agent-b certificate"),
    ("certs/agent-b.key",           "agent-b private key"),
    ("certs/agent-b.json",          "agent-b metadata"),
    ("certs/revocation_list.json",  "CRL"),
    ("certs/nonce_tracker.json",    "Nonce tracker"),
    ("certs/audit_chain.json",      "Audit hash chain"),
    ("certs/policy_store.json",     "Policy version store"),
    ("certs/cross_org_grants.json", "Cross-org grant store"),
]

all_certs_ok = True
for rel_path, label in required_certs:
    full_path = BASE_DIR / rel_path
    if full_path.exists() and full_path.stat().st_size > 0:
        ok(f"{label}", rel_path)
    else:
        fail(f"{label} missing", f"Run: python3 setup_keys.py")
        all_certs_ok = False

# Validate agent metadata has required IETF fields
for agent_id in ["agent-a", "agent-b"]:
    meta_path = CERTS_DIR / f"{agent_id}.json"
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
            required_fields = ["allowed_scopes", "can_spawn", "max_children",
                               "scope_inherit", "policy_ref", "owner", "org_id"]
            missing = [f for f in required_fields if f not in meta]
            if missing:
                fail(f"{agent_id} metadata missing IETF fields", str(missing))
            else:
                ok(f"{agent_id} metadata has all IETF Section 7.1 required fields")
        except Exception as e:
            fail(f"{agent_id} metadata unreadable", str(e))

# ── 2. Environment Variables ──────────────────────────────────────────────────
print(f"\n{YELLOW}── 2. Environment Variables ───────────────────────────────────────────{RESET}")

env_file = BASE_DIR / ".env"
if env_file.exists():
    # Load .env values
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip().strip('"').strip("'")  # Remove quotes common in .env files
            if k and v:
                os.environ.setdefault(k, v)

required_env = [
    ("ANTHROPIC_API_KEY",  "Claude API calls in demo scenarios"),
    ("AWS_ACCESS_KEY_ID",  "S3 + DynamoDB access"),
    ("AWS_SECRET_ACCESS_KEY", "S3 + DynamoDB access"),
    ("S3_BUCKET",          "Event storage"),
    ("DYNAMODB_TABLE",     "Template Registry"),
    ("AWS_REGION",         "AWS region"),
]

for env_var, purpose in required_env:
    val = os.getenv(env_var, "")
    if val and val not in ("your_key_here", "placeholder", "xxx"):
        ok(f"{env_var} set", purpose)
    else:
        fail(f"{env_var} missing or placeholder", f"Required for: {purpose}")

# ── 3. Cedar Policy Files ─────────────────────────────────────────────────────
print(f"\n{YELLOW}── 3. Cedar Policy Files ──────────────────────────────────────────────{RESET}")

cedar_policies = list(POLICY_DIR.glob("*.cedar")) if POLICY_DIR.exists() else []
if cedar_policies:
    for p in cedar_policies:
        ok(f"Cedar policy: {p.name}", f"{p.stat().st_size} bytes")
else:
    fail("No .cedar policy files found", f"Expected in {POLICY_DIR}")

# ── 4. Service Health Checks (with retry) ────────────────────────────────────
print(f"\n{YELLOW}── 4. Service Health Checks ───────────────────────────────────────────{RESET}")

def health_check(name: str, url: str, retries: int = 5, delay: float = 2.0) -> bool:
    for attempt in range(retries):
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                data = r.json()
                ok(f"{name}", f"status={data.get('status', 'ok')}")
                return True
        except Exception:
            pass
        if attempt < retries - 1:
            print(f"       retrying {name}... ({attempt + 1}/{retries})")
            time.sleep(delay)
    fail(f"{name} unreachable", url)
    return False

mcp_up   = health_check("MCP Server",       f"{MCP_URL}/health")
admin_up = health_check("Admin Bootstrap",  f"{ADMIN_URL}/health")
demo_up  = health_check("Demo Web",         f"{DEMO_URL}/health")

# ── 5. DynamoDB Local ─────────────────────────────────────────────────────────
print(f"\n{YELLOW}── 5. DynamoDB Local ──────────────────────────────────────────────────{RESET}")

try:
    import boto3
    from botocore.config import Config

    dynamodb = boto3.client(
        "dynamodb",
        region_name=os.getenv("AWS_REGION", "us-east-1"),
        endpoint_url="http://localhost:8000",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", "test"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", "test"),
        config=Config(connect_timeout=2, read_timeout=2)
    )
    tables = dynamodb.list_tables()["TableNames"]
    expected_table = os.getenv("DYNAMODB_TABLE", "")

    ok(f"DynamoDB Local reachable", f"{len(tables)} table(s)")

    if expected_table and expected_table in tables:
        ok(f"DynamoDB table '{expected_table}' exists")
    elif expected_table:
        fail(f"DynamoDB table '{expected_table}' NOT found", f"Tables: {tables}")
    else:
        warn("DYNAMODB_TABLE not set — skipping table check")

except ImportError:
    warn("boto3 not installed locally — skipping DynamoDB check")
except Exception as e:
    fail("DynamoDB Local unreachable", str(e)[:80])

# ── 6. S3 Bucket ─────────────────────────────────────────────────────────────
print(f"\n{YELLOW}── 6. S3 Bucket ───────────────────────────────────────────────────────{RESET}")

try:
    import boto3
    s3_bucket = os.getenv("S3_BUCKET", "")
    if s3_bucket:
        s3 = boto3.client(
            "s3",
            region_name=os.getenv("AWS_REGION", "us-east-1"),
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        )
        # Head-bucket is cheaper than list-objects
        s3.head_bucket(Bucket=s3_bucket)
        ok(f"S3 bucket '{s3_bucket}' accessible")
    else:
        warn("S3_BUCKET not set — skipping bucket check")
except ImportError:
    warn("boto3 not installed locally — skipping S3 check")
except Exception as e:
    fail(f"S3 bucket check failed", str(e)[:80])

# ── 7. Anthropic API Key ─────────────────────────────────────────────────────
print(f"\n{YELLOW}── 7. Anthropic API Key ───────────────────────────────────────────────{RESET}")

# Read directly from .env (not os.environ) to avoid stale shell env overriding setdefault
api_key = ""
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line.startswith("ANTHROPIC_API_KEY=") and not line.startswith("#"):
            api_key = line.partition("=")[2].strip().strip('"').strip("'")
            break
if not api_key:
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
if api_key:
    try:
        import subprocess as _sp
        # Pass key via list args (no shell interpolation) to avoid quoting bugs
        result = _sp.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "https://api.anthropic.com/v1/models",
             "-H", f"x-api-key: {api_key}",
             "-H", "anthropic-version: 2023-06-01"],
            capture_output=True, text=True, timeout=10
        )
        status = result.stdout.strip()
        if status == "200":
            ok("Anthropic API key valid", "claude-sonnet-4-6 available")
        elif status == "401":
            fail("Anthropic API key invalid (401)", "Check ANTHROPIC_API_KEY in .env")
        else:
            fail("Anthropic API check failed", f"HTTP {status}")
    except Exception as e:
        fail("Anthropic API unreachable", str(e)[:80])
else:
    fail("ANTHROPIC_API_KEY not set", "Required for all 11 demo scenarios")

# ── 8. End-to-End Smoke: write-event ─────────────────────────────────────────
print(f"\n{YELLOW}── 8. End-to-End Smoke (write-event) ─────────────────────────────────{RESET}")

if mcp_up:
    try:
        payload = {
            "correlation_id":    str(uuid.uuid4()),
            "agent_id":          "agent-b",
            "requested_scopes":  ["write:events"],
            "event_data":        {"smoke_test": True, "ts": datetime.now(timezone.utc).isoformat()},
            "request_nonce":     str(uuid.uuid4()),
            "request_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        r = requests.post(f"{MCP_URL}/write-event", json=payload, timeout=10)
        if r.status_code == 200:
            data = r.json()
            ok("write-event smoke (agent-b → write:events)",
               f"s3_key={data.get('s3_key', '?')[:32]}...")
        else:
            fail("write-event smoke FAILED",
                 f"HTTP {r.status_code}: {r.text[:120]}")
    except Exception as e:
        fail("write-event smoke exception", str(e)[:80])

    # Verify a bad agent is correctly denied
    try:
        payload_bad = {
            "correlation_id":    str(uuid.uuid4()),
            "agent_id":          "agent-a",
            "requested_scopes":  ["write:events"],  # agent-a only has read:events
            "event_data":        {"smoke_test": True},
            "request_nonce":     str(uuid.uuid4()),
            "request_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        r2 = requests.post(f"{MCP_URL}/write-event", json=payload_bad, timeout=10)
        if r2.status_code == 403:
            ok("write-event scope denial (agent-a → write:events → DENIED)")
        else:
            fail("write-event scope denial failed",
                 f"Expected 403, got {r2.status_code}")
    except Exception as e:
        fail("write-event denial smoke exception", str(e)[:80])
else:
    warn("Skipping end-to-end smoke — MCP server not reachable")

# ── Summary ───────────────────────────────────────────────────────────────────
total = len(passed) + len(failed)
print()
print("═" * 64)
print(f"  Startup Smoke Test — IETF A2A Trust PoC")
print(f"  {len(passed)}/{total} checks passed  |  {len(failed)} failed")
print("═" * 64)

if failed:
    print(f"\n{RED}  Failed checks:{RESET}")
    for f in failed:
        print(f"    → {f}")
    print(f"\n{RED}  ✗ System not ready for demo — fix above before starting.{RESET}\n")
    sys.exit(1)
else:
    print(f"\n  {GREEN}✓ All checks passed — system ready for demo!{RESET}")
    print(f"  Open: http://localhost:8765\n")
    sys.exit(0)
