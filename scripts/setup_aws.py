#!/usr/bin/env python3
"""Setup AWS resources for A2A Trust PoC"""

import boto3
import os
from botocore.exceptions import ClientError

AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
LOG_GROUP_NAME = '/a2a-trust-poc/audit'

def create_log_group():
    """Create CloudWatch log group"""
    client = boto3.client('logs', region_name=AWS_REGION)

    try:
        client.create_log_group(logGroupName=LOG_GROUP_NAME)
        print(f"✅ Created log group: {LOG_GROUP_NAME}")
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceAlreadyExistsException':
            print(f"✅ Log group already exists: {LOG_GROUP_NAME}")
        else:
            print(f"❌ Error: {e}")
            return False

    # Set retention
    try:
        client.put_retention_policy(
            logGroupName=LOG_GROUP_NAME,
            retentionInDays=30
        )
        print(f"✅ Set retention: 30 days")
    except ClientError as e:
        print(f"⚠️  Warning: {e}")

    return True

if __name__ == '__main__':
    create_log_group()
