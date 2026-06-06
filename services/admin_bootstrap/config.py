import os
import json
import logging
from functools import lru_cache
from pydantic_settings import BaseSettings
import boto3

log = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def load_secrets() -> dict:
    """Load all secrets from AWS Secrets Manager or environment variables"""
    aws_region = os.getenv('AWS_REGION', 'us-east-1')
    secret_name = os.getenv('AWS_SECRETS_NAME', 'a2a-trust-poc/secrets')

    # Try to load from environment first (for local dev/demo)
    admin_key = os.getenv('ADMIN_API_KEY')
    if admin_key:
        log.info("Secrets loaded from environment variables")
        return {'admin_api_key': admin_key}

    # Otherwise try AWS Secrets Manager
    try:
        client = boto3.client('secretsmanager', region_name=aws_region)
        response = client.get_secret_value(SecretId=secret_name)
        secrets = json.loads(response['SecretString'])

        log.info("Secrets loaded from AWS Secrets Manager",
                 extra={"secret_name": secret_name})

        return secrets

    except Exception as e:
        log.warning("Failed to load secrets from AWS, using default demo values",
                    extra={"error": str(e)})
        # Fallback for demo: use insecure default
        return {'admin_api_key': 'demo-admin-key-12345'}


@lru_cache(maxsize=1)
def get_settings():
    """Get all configuration"""
    secrets = load_secrets()

    class Settings(BaseSettings):
        # Secrets
        admin_api_key: str = secrets.get('admin_api_key', '')

        # Config
        aws_region: str = os.getenv('AWS_REGION', 'us-east-1')
        aws_dynamodb_endpoint: str = os.getenv('AWS_DYNAMODB_ENDPOINT', '')
        dynamodb_table: str = os.getenv('DYNAMODB_TABLE', 'template_registry')
        log_level: str = os.getenv('LOG_LEVEL', 'INFO')
        admin_port: int = int(os.getenv('ADMIN_PORT', 8002))

        class Config:
            env_file = ".env"

    return Settings()


settings = get_settings()
