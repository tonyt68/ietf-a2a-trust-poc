import os
import logging
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import Optional

from config import settings
from cert_generator import CertGenerator
from cert_manager import CertManager
from policy_authority import PolicyAuthority
from crl_manager import CRLManager

# Setup logging
logging.basicConfig(level=settings.log_level)
log = logging.getLogger(__name__)

app = FastAPI(title="A2A Trust Admin Bootstrap", version="0.1.0")

# Initialize components
cert_gen = CertGenerator("/app/ca")
cert_mgr = CertManager()
policy_auth = PolicyAuthority()
crl_mgr = CRLManager()


class GenerateCertRequest(BaseModel):
    agent_id: str


class UpdateStateRequest(BaseModel):
    new_state: str


def verify_admin_key(x_admin_key: str = Header(None)) -> bool:
    """Verify admin API key (mTLS + API key auth)"""
    if x_admin_key != settings.admin_api_key:
        return False
    return True


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "admin_bootstrap"}


@app.post("/bootstrap/generate-ca")
async def bootstrap_ca(x_admin_key: str = Header(None)):
    """Generate CA certificate (admin only)"""
    if not verify_admin_key(x_admin_key):
        log.warning("Unauthorized CA generation attempt")
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        success = cert_gen.generate_ca()

        if not success:
            raise HTTPException(status_code=500, detail="CA generation failed")

        log.info("CA bootstrap completed")
        return {"status": "success", "message": "CA generated"}

    except Exception as e:
        log.error("CA bootstrap error", extra={"error": str(e)})
        raise HTTPException(status_code=500, detail="Internal error")


@app.post("/bootstrap/generate-agent-cert")
async def generate_agent_cert(request: GenerateCertRequest, x_admin_key: str = Header(None)):
    """Generate agent certificate (admin only)"""
    if not verify_admin_key(x_admin_key):
        log.warning("Unauthorized cert generation attempt", extra={"agent": request.agent_id})
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        success = cert_gen.generate_agent_cert(request.agent_id)

        if not success:
            raise HTTPException(status_code=500, detail="Cert generation failed")

        return {"status": "success", "agent": request.agent_id, "message": "Certificate generated"}

    except Exception as e:
        log.error("Agent cert generation error", extra={"error": str(e)})
        raise HTTPException(status_code=500, detail="Internal error")


@app.put("/template/{agent_id}/state")
async def update_template_state(agent_id: str, request: UpdateStateRequest, x_admin_key: str = Header(None)):
    """Update template state (admin only)"""
    if not verify_admin_key(x_admin_key):
        log.warning("Unauthorized state update", extra={"template": agent_id})
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        success = cert_mgr.update_state(agent_id, request.new_state)

        if not success:
            raise HTTPException(status_code=400, detail="Invalid state")

        return {"status": "success", "template": agent_id, "new_state": request.new_state}

    except Exception as e:
        log.error("State update error", extra={"error": str(e)})
        raise HTTPException(status_code=500, detail="Internal error")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
