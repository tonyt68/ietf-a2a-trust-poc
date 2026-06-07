import os
import json
import logging
from functools import lru_cache
from pydantic_settings import BaseSettings
import boto3

log = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def load_secrets() -> dict:
    """
    Load all secrets from AWS Secrets Manager or environment variables.
    Cached in memory (single fetch, reused for all requests).
    Audit logged to CloudTrail.
    """
    aws_region = os.getenv('AWS_REGION', 'us-east-1')
    secret_name = os.getenv('AWS_SECRETS_NAME', 'a2a-trust-poc/secrets')

    # Try to load from environment first (for local dev/demo)
    jwt_secret = os.getenv('JWT_SECRET')
    hmac_secret = os.getenv('HMAC_SECRET')
    if jwt_secret and hmac_secret:
        log.info("Secrets loaded from environment variables")
        return {'jwt_secret': jwt_secret, 'hmac_secret': hmac_secret}

    # Otherwise try AWS Secrets Manager
    try:
        client = boto3.client('secretsmanager', region_name=aws_region)
        response = client.get_secret_value(SecretId=secret_name)
        secrets = json.loads(response['SecretString'])

        log.info("Secrets loaded from AWS Secrets Manager",
                 extra={"secret_name": secret_name, "keys": list(secrets.keys())})

        return secrets

    except Exception as e:
        log.warning("Failed to load secrets from AWS, using demo values",
                    extra={"error": str(e), "secret_name": secret_name})
        # Fallback for demo: use insecure defaults
        return {'jwt_secret': 'demo-jwt-secret-key-12345', 'hmac_secret': 'demo-hmac-secret-key-12345'}


@lru_cache(maxsize=1)
def get_settings():
    """Get all configuration (secrets + non-secrets)"""
    secrets = load_secrets()

    class Settings(BaseSettings):
        # Secrets (from AWS Secrets Manager)
        jwt_secret: str = secrets.get('jwt_secret', '')
        hmac_secret: str = secrets.get('hmac_secret', '')

        # Non-secret config (from .env)
        aws_region: str = os.getenv('AWS_REGION', 'us-east-1')
        s3_bucket: str = os.getenv('S3_BUCKET', 'a2a-trust-poc-events')
        cedar_policy_path: str = os.getenv('CEDAR_POLICY_PATH', './policies')
        log_level: str = os.getenv('LOG_LEVEL', 'INFO')
        mcp_port: int = int(os.getenv('MCP_PORT', 8001))

        class Config:
            env_file = ".env"

    return Settings()


settings = get_settings()
