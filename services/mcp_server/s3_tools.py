import boto3
import json
import logging
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)


class S3Tools:
    """MCP tools for reading/writing events to S3"""

    def __init__(self, bucket: str, region: str):
        self.bucket = bucket
        self.s3 = boto3.client('s3', region_name=region)

    def write_event(self, correlation_id: str, event_data: dict) -> Optional[str]:
        """
        Write event to S3 (markdown format).
        Returns: S3 object key if successful, None if failed.
        Fail-closed: S3 error = no write
        """
        try:
            timestamp = datetime.now(timezone.utc).isoformat()
            key = f"events/{correlation_id}_{timestamp}.md"

            # Format as markdown
            content = f"""# Event Log Entry

**Correlation ID:** {correlation_id}
**Timestamp:** {timestamp}

## Event Data

```json
{json.dumps(event_data, indent=2)}
```
"""

            self.s3.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=content.encode('utf-8'),
                ContentType='text/markdown'
            )

            log.info("Event written to S3",
                    extra={"key": key, "correlation_id": correlation_id})

            return key

        except Exception as e:
            log.error("S3 write error",
                     extra={"bucket": self.bucket, "error": str(e)})
            return None

    def read_event(self, s3_key: str) -> Optional[str]:
        """
        Read event from S3.
        Returns: event content if successful, None if failed.
        Fail-closed: S3 error = no read
        """
        try:
            response = self.s3.get_object(Bucket=self.bucket, Key=s3_key)
            content = response['Body'].read().decode('utf-8')

            log.info("Event read from S3",
                    extra={"key": s3_key})

            return content

        except self.s3.exceptions.NoSuchKey:
            log.warning("S3 key not found", extra={"key": s3_key})
            return None
        except Exception as e:
            log.error("S3 read error",
                     extra={"bucket": self.bucket, "key": s3_key, "error": str(e)})
            return None
