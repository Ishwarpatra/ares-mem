"""
base.py — Abstract base class for all ARES-Mem agents.

Every agent inherits from BaseAgent to enforce a uniform interface,
structured logging, and consistent error handling across the pipeline.
"""
import time
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict

# ── Module-level logger ──────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)


class BaseAgent(ABC):
    """
    Abstract base class for all ARES-Mem agents.

    Provides:
    - Uniform `process()` interface
    - Structured agent-level logger
    - Execution timing (latency tracking for SOC overhead analysis)
    - Standardised error envelope
    """

    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(name)

    @abstractmethod
    def process(self, payload: Any) -> Dict[str, Any]:
        """
        Core processing method. Each agent must implement this.

        Args:
            payload: Input data appropriate to the agent's role.

        Returns:
            A dictionary containing the agent's output and metadata.
        """
        ...

    def run(self, payload: Any) -> Dict[str, Any]:
        """
        Wrapper around `process()` that adds timing and error handling.

        Returns:
            Dict with agent output plus `_meta` containing timing and agent name.
        """
        start_ms = time.monotonic() * 1000
        try:
            self.logger.info("Starting processing...")
            result = self.process(payload)
            elapsed_ms = time.monotonic() * 1000 - start_ms
            result["_meta"] = {
                "agent": self.name,
                "latency_ms": round(elapsed_ms, 2),
                "status": "success"
            }
            self.logger.info("Completed in %.2f ms", elapsed_ms)
            return result
        except Exception as exc:  # pylint: disable=broad-except
            elapsed_ms = time.monotonic() * 1000 - start_ms
            self.logger.error("Failed after %.2f ms: %s", elapsed_ms, exc)
            return {
                "_meta": {
                    "agent": self.name,
                    "latency_ms": round(elapsed_ms, 2),
                    "status": "error",
                    "error": str(exc)
                }
            }
