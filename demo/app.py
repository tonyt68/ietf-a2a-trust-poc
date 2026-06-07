import os
import logging
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import json
import uuid
import boto3
from scenario_runner import ScenarioRunner

logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'))
log = logging.getLogger(__name__)

app = FastAPI(title="A2A Trust PoC Demo", version="0.1.0")

# Serve static files (CSS, JS)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize scenario runner
runner = ScenarioRunner(
    mcp_url=os.getenv("MCP_URL", "http://localhost:8001"),
    admin_url=os.getenv("ADMIN_URL", "http://localhost:8002")
)

# Map scenario ID to handler
SCENARIO_HANDLERS = {
    1: runner.scenario_1_golden_path,
    2: runner.scenario_2_dynamic_policy_update,
    3: runner.scenario_3_rogue_spawn,
    4: runner.scenario_4_dual_sig_missing,
    5: runner.scenario_5_dual_sig_tampered,
    6: runner.scenario_6_scope_escalation,
    7: runner.scenario_7_revocation_lifecycle,
    8: runner.scenario_8_crl_check_failure,
    9: runner.scenario_9_ttl_expiry,
    10: runner.scenario_10_cross_org_grant,
    11: runner.scenario_11_replay_attack,
}


@app.get("/health")
async def health_check():
    """Health check"""
    return {"status": "healthy", "service": "demo_web"}


@app.get("/")
async def index():
    """Serve demo.html"""
    return FileResponse("demo.html", media_type="text/html")


@app.get("/prep")
async def prep():
    """Serve prep.html"""
    return FileResponse("prep.html", media_type="text/html")


@app.get("/api/config")
async def get_config():
    """Get demo configuration"""
    return {
        "mcp_url": os.getenv("MCP_URL", "http://localhost:8001"),
        "admin_url": os.getenv("ADMIN_URL", "http://localhost:8002"),
        "demo_port": os.getenv("DEMO_PORT", 8765),
        "scenarios": 11
    }


@app.post("/api/scenario/run")
async def run_scenario(scenario: dict):
    """Run a demo scenario with real Claude calls"""
    try:
        scenario_id = scenario.get("id")
        # Server ALWAYS generates correlationId — client cannot override
        # TODO: Update to UUID7 for sortable IDs
        correlation_id = str(uuid.uuid4())
        log.info(f"Running scenario {scenario_id} with real Claude (correlationId={correlation_id})")

        # Get and run scenario handler
        handler = SCENARIO_HANDLERS.get(scenario_id)
        if not handler:
            return {"status": "error", "message": f"Unknown scenario {scenario_id}"}

        # Set correlationId on runner so all requests use the same one
        runner.correlation_id = correlation_id
        log.info(f"SET runner.correlation_id = {runner.correlation_id}")
        handler()
        log.info(f"After handler: runner.correlation_id = {runner.correlation_id}")

        # Return audit trail entry with correlationId
        if runner.audit_trail:
            entry = runner.audit_trail[-1]
            return {
                "status": "success",
                "scenario_id": scenario_id,
                "correlationId": correlation_id,
                "decision": entry["decision"],
                "reason": entry["reason"],
                "agent": entry.get("agent_id", entry.get("agent", "")),
                "timestamp": entry["timestamp"]
            }

        return {"status": "success", "scenario_id": scenario_id, "correlationId": correlation_id}

    except Exception as e:
        log.error(f"Scenario error: {e}")
        return {"status": "error", "message": str(e)}


@app.get("/api/certs")
async def get_certs():
    """Return agent cert metadata for display in UI."""
    try:
        import pathlib
        certs_dir = pathlib.Path(os.getenv("CERTS_DIR", "./certs"))
        result = {}
        for agent in ["agent-a", "agent-b"]:
            meta_path = certs_dir / f"{agent}.json"
            if meta_path.exists():
                with open(meta_path) as f:
                    result[agent] = json.load(f)
        return {"status": "success", "certs": result}
    except Exception as e:
        log.error(f"Cert fetch failed: {e}")
        return {"status": "error", "message": str(e)}


@app.get("/api/audit/recent")
async def get_recent_audit():
    """Fetch last 10 audit entries from CloudWatch Logs (last 1 hour)."""
    import asyncio
    import time as _time

    try:
        cw = boto3.client(
            "logs",
            region_name=os.getenv("AWS_REGION", "us-east-1"),
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        )
        log_group = os.getenv("CLOUDWATCH_LOG_GROUP", "/a2a-trust-poc/audit")
        loop = asyncio.get_running_loop()

        resp = await loop.run_in_executor(None, lambda: cw.start_query(
            logGroupName=log_group,
            startTime=int(_time.time()) - 3600,
            endTime=int(_time.time()),
            queryString="fields @timestamp, correlationId, agent, action, decision, reason, stage | sort @timestamp desc | limit 10",
        ))
        query_id = resp["queryId"]

        # Poll until complete (max 10s) — use asyncio.sleep to avoid blocking event loop
        result = None
        for _ in range(20):
            await asyncio.sleep(0.5)
            result = await loop.run_in_executor(None, lambda: cw.get_query_results(queryId=query_id))
            if result["status"] in ("Complete", "Failed", "Cancelled"):
                break

        if result is None:
            return {"status": "timeout", "entries": [], "count": 0,
                    "message": "CloudWatch query did not complete in 10s — retry in a moment"}
        if result["status"] == "Failed":
            return {"status": "error", "entries": [], "count": 0,
                    "message": f"CloudWatch query failed — check log group name and permissions"}
        if result["status"] == "Cancelled":
            return {"status": "error", "entries": [], "count": 0,
                    "message": "CloudWatch query was cancelled"}
        if result["status"] != "Complete":
            return {"status": "timeout", "entries": [], "count": 0,
                    "message": "CloudWatch query did not complete in 10s — retry in a moment"}

        entries = []
        for row in result.get("results", []):
            entry = {r["field"]: r["value"] for r in row}
            entries.append(entry)

        return {"status": "success", "entries": entries, "count": len(entries)}

    except Exception as e:
        log.error(f"CloudWatch audit fetch failed: {e}")
        return {"status": "error", "message": str(e), "entries": []}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8765)
