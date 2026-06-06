import subprocess
import logging
from pathlib import Path

log = logging.getLogger(__name__)


class CertGenerator:
    """Generates self-signed CA + agent certificates for mTLS"""

    def __init__(self, ca_path: str):
        self.ca_path = Path(ca_path)
        self.ca_path.mkdir(parents=True, exist_ok=True)

    def generate_ca(self) -> bool:
        """Generate self-signed CA certificate"""
        try:
            ca_key = self.ca_path / "ca.key"
            ca_crt = self.ca_path / "ca.crt"

            if ca_key.exists() and ca_crt.exists():
                log.info("CA certs already exist", extra={"path": str(self.ca_path)})
                return True

            # Generate CA private key (2048-bit RSA)
            subprocess.run([
                "openssl", "genrsa",
                "-out", str(ca_key),
                "2048"
            ], check=True, capture_output=True)

            # Generate CA certificate (self-signed, valid 10 years)
            subprocess.run([
                "openssl", "req",
                "-new", "-x509",
                "-key", str(ca_key),
                "-out", str(ca_crt),
                "-days", "3650",
                "-subj", "/C=US/ST=CA/L=San Francisco/O=TonyAI/CN=A2A-Trust-PoC-CA"
            ], check=True, capture_output=True)

            log.info("CA generated", extra={"key": str(ca_key), "crt": str(ca_crt)})
            return True

        except Exception as e:
            log.error("CA generation failed", extra={"error": str(e)})
            return False

    def generate_agent_cert(self, agent_id: str) -> bool:
        """Generate agent certificate signed by CA"""
        try:
            ca_key = self.ca_path / "ca.key"
            ca_crt = self.ca_path / "ca.crt"
            agent_key = self.ca_path / f"{agent_id}.key"
            agent_csr = self.ca_path / f"{agent_id}.csr"
            agent_crt = self.ca_path / f"{agent_id}.crt"

            if agent_crt.exists():
                log.info("Agent cert already exists", extra={"agent": agent_id})
                return True

            # Generate agent private key
            subprocess.run([
                "openssl", "genrsa",
                "-out", str(agent_key),
                "2048"
            ], check=True, capture_output=True)

            # Generate CSR (Certificate Signing Request)
            subprocess.run([
                "openssl", "req",
                "-new",
                "-key", str(agent_key),
                "-out", str(agent_csr),
                "-subj", f"/C=US/ST=CA/L=San Francisco/O=TonyAI/CN={agent_id}"
            ], check=True, capture_output=True)

            # Sign with CA
            subprocess.run([
                "openssl", "x509",
                "-req",
                "-in", str(agent_csr),
                "-CA", str(ca_crt),
                "-CAkey", str(ca_key),
                "-CAcreateserial",
                "-out", str(agent_crt),
                "-days", "365"
            ], check=True, capture_output=True)

            # Clean up CSR
            agent_csr.unlink()

            log.info("Agent cert generated", extra={"agent": agent_id})
            return True

        except Exception as e:
            log.error("Agent cert generation failed",
                     extra={"agent": agent_id, "error": str(e)})
            return False
