import os
import logging
import boto3
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
from botocore.exceptions import ClientError

from config import settings
from cert_generator import CertGenerator
from cert_manager import CertManager
from policy_authority import PolicyAuthority
from crl_manager import CRLManager

# Setup logging
logging.basicConfig(level=settings.log_level)
log = logging.getLogger(__name__)


def _ensure_dynamodb_table():
    """Create DynamoDB table if it doesn't exist"""
    dynamodb = boto3.resource('dynamodb', region_name=settings.aws_region)
    try:
        table = dynamodb.Table(settings.dynamodb_table)
        table.load()
        log.info(f"DynamoDB table '{settings.dynamodb_table}' exists")
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            log.info(f"Creating DynamoDB table '{settings.dynamodb_table}'...")
            try:
                dynamodb.create_table(
                    TableName=settings.dynamodb_table,
                    KeySchema=[
                        {'AttributeName': 'template_id', 'KeyType': 'HASH'}
                    ],
                    AttributeDefinitions=[
                        {'AttributeName': 'template_id', 'AttributeType': 'S'}
                    ],
                    BillingMode='PAY_PER_REQUEST'
                )
                log.info(f"DynamoDB table '{settings.dynamodb_table}' created")
                return True
            except Exception as create_err:
                log.error(f"Failed to create table: {create_err}")
                return False
        else:
            log.error(f"DynamoDB error: {e}")
            return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: ensure DynamoDB table exists"""
    _ensure_dynamodb_table()
    yield


app = FastAPI(title="A2A Trust Admin Bootstrap", version="0.1.0", lifespan=lifespan)

# Initialize components
cert_gen = CertGenerator("/app/ca")
cert_mgr = CertManager(settings.dynamodb_table, settings.aws_region)
policy_auth = PolicyAuthority()
crl_mgr = CRLManager()


class GenerateCertRequest(BaseModel):
    agent_id: str


class RegisterTemplateRequest(BaseModel):
    agent_id: str
    allowed_scopes: list
    can_spawn: list
    ttl_seconds: int = 3600


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


@app.post("/template/register")
async def register_template(request: RegisterTemplateRequest, x_admin_key: str = Header(None)):
    """Register agent template in Template Registry (admin only)"""
    if not verify_admin_key(x_admin_key):
        log.warning("Unauthorized template registration", extra={"template": request.agent_id})
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        success = cert_mgr.register_template(
            request.agent_id,
            request.allowed_scopes,
            request.can_spawn,
            request.ttl_seconds
        )

        if not success:
            raise HTTPException(status_code=500, detail="Registration failed")

        return {"status": "success", "template": request.agent_id}

    except Exception as e:
        log.error("Template registration error", extra={"error": str(e)})
        raise HTTPException(status_code=500, detail="Internal error")


@app.get("/template/{agent_id}")
async def get_template(agent_id: str):
    """Get template from Registry (public read)"""
    try:
        template = cert_mgr.get_template(agent_id)

        if not template:
            raise HTTPException(status_code=404, detail="Template not found")

        return {"status": "success", "template": template}

    except Exception as e:
        log.error("Template retrieval error", extra={"error": str(e)})
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
