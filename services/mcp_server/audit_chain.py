"""Tamper-evident audit log using hash chain (blockchain-style)"""

import logging
import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict

log = logging.getLogger(__name__)


class AuditChain:
    """Maintains tamper-evident audit trail using hash chain"""

    def __init__(self, chain_path: str = "./certs/audit_chain.json"):
        self.chain_path = Path(chain_path)
        self.chain = self._load_chain()

    def _load_chain(self) -> Dict:
        """Load audit chain from disk"""
        if self.chain_path.exists():
            try:
                with open(self.chain_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                log.error("Failed to load audit chain", extra={"error": str(e)})
        return {
            "chain": [],
            "current_hash": None
        }

    def _save_chain(self):
        """Persist audit chain to disk"""
        try:
            with open(self.chain_path, 'w') as f:
                json.dump(self.chain, f, indent=2)
        except Exception as e:
            log.error("Failed to save audit chain", extra={"error": str(e)})

    def _hash_block(self, block_data: str) -> str:
        """Compute SHA-256 hash of block"""
        return hashlib.sha256(block_data.encode()).hexdigest()

    def append_event(self, event: Dict) -> str:
        """
        Append audit event to chain.
        Returns: block hash
        """
        try:
            # Get previous hash
            previous_hash = self.chain.get("current_hash", "genesis")

            # Create block
            block = {
                "index": len(self.chain.get("chain", [])),
                "timestamp": datetime.utcnow().isoformat(),
                "previous_hash": previous_hash,
                "event": event,
                "hash": None  # Will be computed
            }

            # Compute block hash
            block_json = json.dumps(
                {
                    "index": block["index"],
                    "timestamp": block["timestamp"],
                    "previous_hash": previous_hash,
                    "event": event
                },
                sort_keys=True
            )
            block_hash = self._hash_block(block_json)
            block["hash"] = block_hash

            # Add to chain
            if "chain" not in self.chain:
                self.chain["chain"] = []
            self.chain["chain"].append(block)
            self.chain["current_hash"] = block_hash

            # Save to disk
            self._save_chain()

            log.info("Audit event appended to chain",
                    extra={"block_index": block["index"], "hash": block_hash[:16]})

            return block_hash

        except Exception as e:
            log.error("Failed to append audit event", extra={"error": str(e)})
            return None

    def verify_chain(self) -> tuple:
        """
        Verify chain integrity (no tampering).
        Returns: (valid: bool, broken_at: int or None)
        """
        try:
            chain = self.chain.get("chain", [])

            if not chain:
                return (True, None)

            # Verify genesis block
            if chain[0]["previous_hash"] != "genesis":
                return (False, 0)

            # Verify each block hash
            for i, block in enumerate(chain):
                expected_hash = self._hash_block(
                    json.dumps(
                        {
                            "index": block["index"],
                            "timestamp": block["timestamp"],
                            "previous_hash": block["previous_hash"],
                            "event": block["event"]
                        },
                        sort_keys=True
                    )
                )

                if block["hash"] != expected_hash:
                    log.warning("Chain integrity broken", extra={"block_index": i})
                    return (False, i)

                # Verify link to previous block
                if i > 0:
                    if block["previous_hash"] != chain[i - 1]["hash"]:
                        log.warning("Chain link broken", extra={"block_index": i})
                        return (False, i)

            log.info("Audit chain verified", extra={"blocks": len(chain)})
            return (True, None)

        except Exception as e:
            log.error("Chain verification error", extra={"error": str(e)})
            return (False, None)

    def get_chain(self) -> list:
        """Get full audit chain"""
        return self.chain.get("chain", [])

    def get_events_since(self, timestamp: str) -> list:
        """Get audit events after timestamp"""
        try:
            cutoff = datetime.fromisoformat(timestamp)
            events = []

            for block in self.chain.get("chain", []):
                block_time = datetime.fromisoformat(block["timestamp"])
                if block_time > cutoff:
                    events.append(block["event"])

            return events

        except Exception as e:
            log.error("Failed to retrieve events", extra={"error": str(e)})
            return []
