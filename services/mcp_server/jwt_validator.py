import jwt
import logging
from datetime import datetime
from typing import Optional, Dict

log = logging.getLogger(__name__)


class JWTValidator:
    """Validates JWT RS256 tokens (Agent A → Agent B)"""

    def __init__(self, jwt_secret: str):
        self.secret = jwt_secret

    def validate(self, token: str) -> Optional[Dict]:
        """
        Validate JWT token.
        Returns: decoded token claims if valid, None if invalid.
        Fail-closed: any error = invalid
        """
        try:
            # Validate RS256 signature
            decoded = jwt.decode(
                token,
                self.secret,
                algorithms=['HS256'],  # PoC uses HMAC, prod uses RS256
                options={"verify_signature": True, "verify_exp": True}
            )

            # Verify required claims
            if not all(k in decoded for k in ['sub', 'aud', 'exp']):
                log.warning("JWT missing required claims", extra={"claims": decoded.keys()})
                return None

            # Verify expiry
            if decoded['exp'] < datetime.utcnow().timestamp():
                log.warning("JWT expired", extra={"exp": decoded.get('exp')})
                return None

            log.info("JWT validated", extra={"sub": decoded.get('sub'), "aud": decoded.get('aud')})
            return decoded

        except jwt.InvalidSignatureError:
            log.warning("JWT signature invalid")
            return None
        except jwt.DecodeError:
            log.warning("JWT decode error")
            return None
        except Exception as e:
            log.error("JWT validation error", extra={"error": str(e)})
            return None
