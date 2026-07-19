"""
Request tracing with correlation IDs.
Enables debugging distributed requests across the pipeline.
"""

from contextvars import ContextVar
import uuid
import logging
from typing import Optional

logger = logging.getLogger("Tracing")

# Thread-safe storage of request ID
REQUEST_ID_CTX: ContextVar[str] = ContextVar('request_id', default='')

class RequestTracer:
    """Manages request ID context for correlation."""
    
    def __init__(self):
        self.request_id = str(uuid.uuid4())
    
    def get_id(self) -> str:
        """Get current request ID from context."""
        ctx_id = REQUEST_ID_CTX.get()
        return ctx_id if ctx_id else self.request_id
    
    def set_id(self, request_id: str) -> None:
        """Set request ID in context."""
        REQUEST_ID_CTX.set(request_id)
        logger.info(f"Request ID set: {request_id}")
    
    def generate_id(self) -> str:
        """Generate new UUID for request."""
        new_id = str(uuid.uuid4())
        self.set_id(new_id)
        return new_id

# Global tracer instance
tracer = RequestTracer()
