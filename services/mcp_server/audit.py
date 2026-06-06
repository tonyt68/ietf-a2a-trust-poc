"""Audit logging — CloudWatch Logs with sequence token handling"""

import json
import logging
import time
import os
import boto3
from botocore.exceptions import ClientError

log = logging.getLogger("audit")

AWS_REGION  = os.getenv('AWS_REGION', 'us-east-1')
LOG_GROUP   = os.getenv('CLOUDWATCH_LOG_GROUP', '/a2a-trust-poc/audit')
LOG_STREAM  = os.getenv('SERVICE_NAME', 'mcp-server')

_cw_client      = boto3.client('logs', region_name=AWS_REGION)
_stream_ready   = False
_sequence_token = None   # Required by CloudWatch after first put_log_events


def _ensure_stream():
    """Create log group and stream if they don't exist."""
    global _stream_ready
    if _stream_ready:
        return

    try:
        _cw_client.create_log_group(logGroupName=LOG_GROUP)
        log.info(f"CloudWatch log group created: {LOG_GROUP}")
    except _cw_client.exceptions.ResourceAlreadyExistsException:
        pass
    except Exception as e:
        log.warning(f"CloudWatch log group setup: {e}")

    try:
        _cw_client.create_log_stream(
            logGroupName=LOG_GROUP,
            logStreamName=LOG_STREAM
        )
        log.info(f"CloudWatch log stream created: {LOG_STREAM}")
    except _cw_client.exceptions.ResourceAlreadyExistsException:
        pass
    except Exception as e:
        log.warning(f"CloudWatch log stream setup: {e}")

    _stream_ready = True


def _get_sequence_token() -> str:
    """Fetch the current sequence token for the stream (required after first write)."""
    try:
        resp = _cw_client.describe_log_streams(
            logGroupName=LOG_GROUP,
            logStreamNamePrefix=LOG_STREAM,
            limit=1
        )
        streams = resp.get('logStreams', [])
        if streams:
            return streams[0].get('uploadSequenceToken')
    except Exception as e:
        log.warning(f"Could not fetch sequence token: {e}")
    return None


def audit(entry: dict) -> None:
    """
    Write audit entry to CloudWatch Logs.
    Handles sequence token correctly — required after the first put_log_events call,
    otherwise CloudWatch rejects with InvalidSequenceTokenException.
    Falls back to console log on failure so audit trail is never silently dropped.
    """
    global _sequence_token

    _ensure_stream()

    message = json.dumps(entry, default=str)
    event   = [{'timestamp': int(time.time() * 1000), 'message': message}]

    kwargs = {
        'logGroupName':  LOG_GROUP,
        'logStreamName': LOG_STREAM,
        'logEvents':     event,
    }
    if _sequence_token:
        kwargs['sequenceToken'] = _sequence_token

    try:
        resp = _cw_client.put_log_events(**kwargs)
        _sequence_token = resp.get('nextSequenceToken')
        log.info(f"Audit → CloudWatch: decision={entry.get('decision')} agent={entry.get('agent')}")

    except ClientError as e:
        code = e.response['Error']['Code']

        # Token stale or missing — fetch the current one and retry once
        if code in ('InvalidSequenceTokenException', 'DataAlreadyAcceptedException'):
            _sequence_token = _get_sequence_token()
            if _sequence_token:
                kwargs['sequenceToken'] = _sequence_token
            else:
                kwargs.pop('sequenceToken', None)
            try:
                resp = _cw_client.put_log_events(**kwargs)
                _sequence_token = resp.get('nextSequenceToken')
                return
            except Exception as retry_err:
                log.error(f"CloudWatch retry failed: {retry_err} | entry: {message[:200]}")
        else:
            log.error(f"CloudWatch write failed ({code}): {e} | entry: {message[:200]}")

    except Exception as e:
        log.error(f"CloudWatch write failed: {e} | entry: {message[:200]}")
