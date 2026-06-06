import os
import logging
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import json
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
        correlation_id = scenario.get("correlationId")
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
                "timestamp": entry["timestamp"]
            }

        return {"status": "success", "scenario_id": scenario_id, "correlationId": correlation_id}

    except Exception as e:
        log.error(f"Scenario error: {e}")
        return {"status": "error", "message": str(e)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8765)
