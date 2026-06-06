import json
import logging
from typing import Dict, List, Optional
from pathlib import Path

log = logging.getLogger(__name__)


class CedarPolicyEvaluator:
    """Evaluates Cedar policies for scope/spawn authorization"""

    def __init__(self, policy_path: str):
        self.policy_path = Path(policy_path)
        self.policies = self._load_policies()

    def _load_policies(self) -> Dict:
        """Load all Cedar policy files from disk"""
        policies = {}

        if not self.policy_path.exists():
            log.warning("Policy path does not exist", extra={"path": str(self.policy_path)})
            return policies

        for policy_file in self.policy_path.glob("*.cedar"):
            try:
                with open(policy_file, 'r') as f:
                    policy_name = policy_file.stem
                    policies[policy_name] = f.read()
                    log.info("Policy loaded", extra={"policy": policy_name})
            except Exception as e:
                log.error("Failed to load policy", extra={"file": str(policy_file), "error": str(e)})

        return policies

    def evaluate(self, agent_id: str, requested_scopes: List[str]) -> Optional[List[str]]:
        """
        Evaluate Cedar policy for agent + scopes.
        Returns: granted scopes if allowed, None if denied.
        Fail-closed: policy error = DENY
        """
        try:
            policy_name = f"{agent_id}"
            if policy_name not in self.policies:
                log.warning("No policy for agent", extra={"agent": agent_id})
                return None

            policy = self.policies[policy_name]

            # Parse allowed scopes from Cedar policy
            allowed_scopes = self._parse_allowed_scopes(policy)

            if not allowed_scopes:
                log.warning("No scopes allowed in policy", extra={"agent": agent_id})
                return None

            # Check ALL requested scopes are in allowed list (fail-closed)
            granted = [scope for scope in requested_scopes if scope in allowed_scopes]

            # DENY if ANY requested scope is not explicitly allowed
            if len(granted) != len(requested_scopes):
                log.warning("Scope escalation attempt",
                           extra={"agent": agent_id, "requested": requested_scopes, "allowed": allowed_scopes})
                return None

            log.info("Cedar policy evaluated", extra={"agent": agent_id, "scopes": granted})
            return granted

        except Exception as e:
            log.error("Cedar policy evaluation error", extra={"agent": agent_id, "error": str(e)})
            return None

    def _parse_allowed_scopes(self, policy_content: str) -> List[str]:
        """
        Parse allowed scopes from Cedar policy file.
        Cedar format: "SCOPE" in principal.scopes
        Example: "write:events" in principal.scopes
        """
        scopes = []
        for line in policy_content.split('\n'):
            # Look for pattern: "scope_name" in principal.scopes
            if 'in principal.scopes' in line:
                # Extract quoted string before 'in principal.scopes'
                parts = line.split('in principal.scopes')[0].strip()
                # Remove quotes and whitespace
                scope = parts.strip('"\'').strip()
                if scope:
                    scopes.append(scope)

        return scopes

    def reload_policies(self):
        """Reload policies from disk (for dynamic policy updates)"""
        self.policies = self._load_policies()
        log.info("Policies reloaded")
