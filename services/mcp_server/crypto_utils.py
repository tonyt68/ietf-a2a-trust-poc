"""Shared cryptographic utilities for RSA signing and verification."""

import base64
import logging
import subprocess
import tempfile
import os
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


def sign_data_rsa_sha256(data: str, key_path: Path) -> Optional[str]:
    """Sign data with RSA private key (SHA256), return base64 signature."""
    data_file = None
    sig_file = None

    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.dat', delete=False) as f:
            f.write(data)
            data_file = f.name

        sig_file = data_file + ".sig"
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(key_path), "-out", sig_file, data_file],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            log.error("RSA signing failed", extra={"error": result.stderr})
            return None

        with open(sig_file, 'rb') as f:
            sig_bytes = f.read()

        return base64.b64encode(sig_bytes).decode('utf-8')
    except Exception as e:
        log.error("Sign failed", extra={"error": str(e)})
        return None
    finally:
        for f in [data_file, sig_file]:
            if f and os.path.exists(f):
                try:
                    os.unlink(f)
                except OSError:
                    pass
