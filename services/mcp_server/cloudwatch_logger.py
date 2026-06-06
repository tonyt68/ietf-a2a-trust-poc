import logging
import os

def setup_cloudwatch_logging(service_name):
    """Setup CloudWatch logging for a service (optional)"""
    try:
        import watchtower

        log_group = os.getenv('CLOUDWATCH_LOG_GROUP', '/a2a-trust-poc/audit')
        log_stream = service_name
        aws_region = os.getenv('AWS_REGION', 'us-east-1')

        handler = watchtower.CloudWatchLogHandler(
            log_group=log_group,
            stream_name=log_stream,
            region_name=aws_region
        )

        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)

        logger = logging.getLogger()
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        print(f"✅ CloudWatch logging enabled: {log_group}/{log_stream}")

    except Exception as e:
        print(f"⚠️  CloudWatch logging skipped: {e}")
