import logging
from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

from config import settings
from jwt_validator import JWTValidator
from hmac_verifier import HMACVerifier
from cedar_policy_eval import CedarPolicyEvaluator
from s3_tools import S3Tools
from audit import audit
from service import EventService
from cert_validator import CertValidator
from replay_prevention import ReplayPrevention
from audit_chain import AuditChain
from cert_manager import CertManager

# Setup logging
logging.basicConfig(level=settings.log_level)
log = logging.getLogger(__name__)

app = FastAPI(title="A2A Trust MCP Server", version="0.1.0")


# Dependency injection: initialize components
def get_event_service() -> EventService:
    """Factory: creates EventService with all IETF-compliant dependencies"""
    import os
    certs_dir = os.getenv("CERTS_DIR", "./certs")

    jwt_validator = JWTValidator(settings.jwt_secret)
    hmac_verifier = HMACVerifier(settings.hmac_secret)
    cedar_evaluator = CedarPolicyEvaluator(settings.cedar_policy_path)
    s3_tools = S3Tools(settings.s3_bucket, settings.aws_region)
    cert_manager = CertManager(settings.dynamodb_table, settings.aws_region, certs_dir=certs_dir)

    # IETF compliance validators
    cert_validator = CertValidator(ca_root_cert_path=f"{certs_dir}/ca-root.crt")
    replay_prevention = ReplayPrevention(nonce_tracker_path=f"{certs_dir}/nonce_tracker.json")
    audit_chain = AuditChain(chain_path=f"{certs_dir}/audit_chain.json")

    return EventService(
        jwt_validator=jwt_validator,
        hmac_verifier=hmac_verifier,
        cedar_evaluator=cedar_evaluator,
        s3_tools=s3_tools,
        audit_fn=audit,
        cert_manager=cert_manager,
        cert_validator=cert_validator,
        replay_prevention=replay_prevention,
        audit_chain=audit_chain
    )


# Global service instance (initialized once at startup)
_event_service = None


@app.on_event("startup")
async def startup():
    """Initialize service on app startup"""
    global _event_service
    _event_service = get_event_service()
    log.info("EventService initialized")


class WriteEventRequest(BaseModel):
    model_config = ConfigDict(max_json_schema_depth=10)

    correlation_id: str
    event_data: dict
    agent_id: str
    requested_scopes: list
    request_nonce: Optional[str] = None
    request_timestamp: Optional[str] = None

    def __init__(self, **data):
        super().__init__(**data)
        # Validate event_data size (max 5MB for LLM context)
        import json
        data_size = len(json.dumps(self.event_data).encode())
        if data_size > 5 * 1024 * 1024:  # 5MB
            raise ValueError("event_data exceeds 5MB limit")


class ReadEventRequest(BaseModel):
    s3_key: str
    correlation_id: str
    request_nonce: Optional[str] = None
    request_timestamp: Optional[str] = None


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "mcp_server"}


@app.post("/write-event")
async def write_event(request: WriteEventRequest):
    """MCP tool: Write event to S3 with IETF compliance checks."""
    success, s3_key, decision, reason = _event_service.write_event(
        request.correlation_id,
        request.agent_id,
        request.requested_scopes,
        request.event_data,
        request_nonce=request.request_nonce,
        request_timestamp=request.request_timestamp
    )

    if not success:
        raise HTTPException(status_code=403 if decision == "DENIED" else 500, detail=reason)

    return {
        "status": "success",
        "s3_key": s3_key,
        "correlation_id": request.correlation_id,
        "decision": decision
    }


@app.post("/read-event")
async def read_event(request: ReadEventRequest):
    """MCP tool: Read event from S3 with IETF compliance checks."""
    success, content, decision, reason = _event_service.read_event(
        request.correlation_id,
        "agent-a",
        request.s3_key,
        request_nonce=request.request_nonce,
        request_timestamp=request.request_timestamp
    )

    if not success:
        raise HTTPException(status_code=403 if decision == "DENIED" else 404, detail=reason)

    return {
        "status": "success",
        "content": content,
        "correlation_id": request.correlation_id,
        "decision": decision
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
