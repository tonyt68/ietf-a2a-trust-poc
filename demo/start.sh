#!/bin/bash
# A2A Trust PoC — Start with full test gate
# Same flow as restart.sh but without --build (faster for demo day)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

die() {
    echo -e "\n${RED}FAILED: $1${NC}"
    echo -e "${YELLOW}Stopping all services...${NC}"
    docker compose down 2>/dev/null || true
    echo -e "${RED}Fix the errors above, then run ./demo/start.sh again.${NC}\n"
    exit 1
}

# Check .env
if [ ! -f .env ]; then
    echo -e "${RED}ERROR: .env not found. Copy .env.example and fill in values.${NC}"
    exit 1
fi

# Auto-generate certs if missing
if [ ! -f certs/ca-root.crt ]; then
    echo -e "${YELLOW}Certs not found — generating now...${NC}"
    python3 setup_keys.py || die "setup_keys.py failed"
fi

# ── Step 1: Static tests ──────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Step 1/5: IETF Conformance Vectors (50 vectors)"
echo "═══════════════════════════════════════════════════════════════"
python3 tests/test_vectors.py || die "Static tests failed. Fix before starting."
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

# ── Step 3: Start services ────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Step 3/4: Starting services"
echo "═══════════════════════════════════════════════════════════════"
docker compose up -d 2>&1 | tail -6

# Create DynamoDB table if it doesn't exist
sleep 4
aws dynamodb create-table \
  --table-name template_registry \
  --attribute-definitions AttributeName=template_id,AttributeType=S \
  --key-schema AttributeName=template_id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --endpoint-url http://localhost:8000 \
  --region us-east-1 2>&1 | grep -v ResourceInUseException || true

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
    docker compose logs --tail=10 2>&1 | grep -v "^time="
    die "Services did not become healthy within ${MAX_WAIT}s"
fi
echo -e "${GREEN}✓ All services healthy${NC}"

# ── Step 4: Smoke tests ───────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Step 4/5: Smoke tests (live server verification)"
echo "═══════════════════════════════════════════════════════════════"
python3 tests/smoke_test.py || die "Smoke tests failed. Services stopped."
echo -e "${GREEN}✓ Smoke tests passed${NC}"

# ── Step 5: Red team security tests ──────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Step 5/5: Red Team Security Tests (IETF §16 + OWASP Top 10)"
echo "═══════════════════════════════════════════════════════════════"
python3 tests/red_team_test.py || die "Red team tests failed. Security regression detected."
echo -e "${GREEN}✓ Red team tests passed${NC}"

# ── Open browser ──────────────────────────────────────────────────────────
if command -v open &>/dev/null; then
    open "http://localhost:8765"
elif command -v xdg-open &>/dev/null; then
    xdg-open "http://localhost:8765"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo -e " ${GREEN}✓ ALL TESTS PASSED — Demo is ready${NC}"
echo "═══════════════════════════════════════════════════════════════"
echo "  Demo UI:          http://localhost:8765"
echo "  MCP Server:       http://localhost:8001"
echo "  Admin Bootstrap:  http://localhost:8002"
echo ""
echo "  Red team:         python3 tests/red_team_test.py"
echo "  Stop:             docker compose down"
echo ""
