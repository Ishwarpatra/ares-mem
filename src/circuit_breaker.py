from enum import Enum
import time
import logging
from typing import Callable, Any, TypeVar, Optional

logger = logging.getLogger("CircuitBreaker")

class CircuitState(Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"

T = TypeVar("T")

class CircuitBreaker:
    def __init__(
        self,
        name: str,
        failure_threshold: int = 3,
        recovery_timeout: float = 60.0
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self._lock = False # A simple lock mechanism can be added if multithreading becomes an issue.

    def _on_success(self):
        self.failure_count = 0
        self.state = CircuitState.CLOSED

    def _on_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            if self.state != CircuitState.OPEN:
                logger.error(f"[CircuitBreaker:{self.name}] State changed to OPEN after {self.failure_count} failures")
                self.state = CircuitState.OPEN

    def call(self, func: Callable[..., T], fallback: Callable[..., T], *args, **kwargs) -> T:
        if self.state == CircuitState.OPEN:
            if time.time() - (self.last_failure_time or 0) > self.recovery_timeout:
                logger.info(f"[CircuitBreaker:{self.name}] State changed to HALF_OPEN")
                self.state = CircuitState.HALF_OPEN
            else:
                logger.warning(f"[CircuitBreaker:{self.name}] Circuit is OPEN, using fallback")
                return fallback(*args, **kwargs)

        try:
            result = func(*args, **kwargs)
            if self.state == CircuitState.HALF_OPEN:
                logger.info(f"[CircuitBreaker:{self.name}] State changed to CLOSED after successful HALF_OPEN call")
            self._on_success()
            return result
        except Exception as e:
            logger.error(f"[CircuitBreaker:{self.name}] Call failed: {e}")
            self._on_failure()
            if self.state == CircuitState.HALF_OPEN:
                 self.state = CircuitState.OPEN
            return fallback(*args, **kwargs)

# Global instances
llm_circuit_breaker = CircuitBreaker("LLM", failure_threshold=3, recovery_timeout=60.0)
chroma_circuit_breaker = CircuitBreaker("ChromaDB", failure_threshold=3, recovery_timeout=60.0)
