#!/bin/bash
# A2A Trust PoC — Restart with full test gate
#
# Flow:
#   1. Static tests  (no server needed, runs in seconds)
#   2. docker compose down + up --build
#   3. Smoke tests   (server must be healthy)
#   4. Stop all + report on any failure

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

die() {
    echo -e "\n${RED}FAILED: $1${NC}"
    echo -e "${YELLOW}Stopping all services...${NC}"
    docker compose down 2>/dev/null || true
    echo -e "${RED}Fix the errors above, then run ./restart.sh again.${NC}\n"
    exit 1
}

# ── Step 1: Static tests (instant, no server) ─────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Step 1/5: IETF Conformance Vectors (50 vectors)"
echo "═══════════════════════════════════════════════════════════════"
python3 tests/test_vectors.py || die "Static tests failed. Fix before starting services."
echo -e "${GREEN}✓ Static tests passed${NC}"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Step 1.5/5: Two-Phase Policy Signature Tests (Section 9.3)"
echo "═══════════════════════════════════════════════════════════════"
python3 tests/test_policy_signatures.py || die "Policy signature tests failed. Dual-sig validation broken."
echo -e "${GREEN}✓ Policy signature tests passed${NC}"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Step 1.6/5: Policy Field Guard Tests (Cert Identity Protection)"
echo "═══════════════════════════════════════════════════════════════"
python3 tests/test_policy_field_guard.py || die "Policy field guard tests failed. Cert protection broken."
echo -e "${GREEN}✓ Policy field guard tests passed${NC}"

# ── Step 2: Start services ────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Step 2/5: Starting services (docker compose down + up --build)"
echo "═══════════════════════════════════════════════════════════════"
docker compose down 2>&1 | tail -3
docker compose up -d --build 2>&1 | tail -6

# Wait for services — health check loop instead of fixed sleep
echo ""
echo "Waiting for services to be ready..."
MAX_WAIT=30
ELAPSED=0
all_up=false
while [ $ELAPSED -lt $MAX_WAIT ]; do
    mcp=$(curl -sf http://localhost:8001/health -m 2 | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('status')=='healthy' else 1)" 2>/dev/null && echo "up" || echo "down")
    adm=$(curl -sf http://localhost:8002/health -m 2 | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('status')=='healthy' else 1)" 2>/dev/null && echo "up" || echo "down")
    web=$(curl -sf http://localhost:8765/health -m 2 | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('status')=='healthy' else 1)" 2>/dev/null && echo "up" || echo "down")

    if [ "$mcp" = "up" ] && [ "$adm" = "up" ] && [ "$web" = "up" ]; then
        all_up=true
        break
    fi
    echo "  mcp=$mcp admin=$adm demo=$web — waiting... (${ELAPSED}s/${MAX_WAIT}s)"
    sleep 3
    ELAPSED=$((ELAPSED + 3))
done

if [ "$all_up" != "true" ]; then
    echo ""
    echo "Service logs:"
    docker compose logs mcp_server --tail=15 2>&1 | grep -v "^time="
    docker compose logs admin_bootstrap --tail=10 2>&1 | grep -v "^time="
    docker compose logs demo_web --tail=10 2>&1 | grep -v "^time="
    die "Services did not become healthy within ${MAX_WAIT}s"
fi
echo -e "${GREEN}✓ All services healthy${NC}"

# ── Step 3: Smoke tests (live server) ────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Step 3/5: Smoke tests (live server verification)"
echo "═══════════════════════════════════════════════════════════════"
python3 tests/smoke_test.py || die "Smoke tests failed. Services stopped."
echo -e "${GREEN}✓ Smoke tests passed${NC}"

# ── Step 4: Red team security tests ──────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Step 4/5: Red Team Security Tests (IETF §16 + OWASP Top 10)"
echo "═══════════════════════════════════════════════════════════════"
python3 tests/red_team_test.py || die "Red team tests failed. Security regression detected."
echo -e "${GREEN}✓ Red team tests passed${NC}"

# ── All good ──────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo -e " ${GREEN}✓ ALL TESTS PASSED — Demo is ready${NC}"
echo "═══════════════════════════════════════════════════════════════"
echo "  Demo UI:          http://localhost:8765"
echo "  MCP Server:       http://localhost:8001"
echo "  Admin Bootstrap:  http://localhost:8002"
echo ""
