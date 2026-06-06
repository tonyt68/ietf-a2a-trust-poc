import logging
from typing import List

log = logging.getLogger(__name__)


class CRLManager:
    """Manages Certificate Revocation List (CRL)"""

    def __init__(self):
        self.revoked_certs = set()

    def revoke_cert(self, cert_id: str) -> bool:
        """
        Revoke a certificate.
        Once revoked, cert is on CRL and cannot be used.
        Fail-closed: any agent using revoked cert = DENY
        """
        try:
            self.revoked_certs.add(cert_id)
            log.info("Certificate revoked", extra={"cert": cert_id})
            return True

        except Exception as e:
            log.error("Revocation failed", extra={"cert": cert_id, "error": str(e)})
            return False

    def is_revoked(self, cert_id: str) -> bool:
        """Check if certificate is revoked"""
        return cert_id in self.revoked_certs

    def get_revocation_list(self) -> List[str]:
        """Get list of all revoked certs"""
        return list(self.revoked_certs)

    def reactivate_cert(self, cert_id: str) -> bool:
        """
        Reactivate a revoked cert (e.g., if revocation was in error).
        DISABLED → ACTIVE (reversible).
        """
        try:
            if cert_id in self.revoked_certs:
                self.revoked_certs.remove(cert_id)
                log.info("Certificate reactivated", extra={"cert": cert_id})
                return True
            else:
                log.warning("Certificate not in CRL", extra={"cert": cert_id})
                return False

        except Exception as e:
            log.error("Reactivation failed", extra={"cert": cert_id, "error": str(e)})
            return False
