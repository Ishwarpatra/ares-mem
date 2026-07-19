"""
Immutable audit logging system.
All events are append-only; no deletions allowed.
Used for compliance: SOC2, ISO27001, HIPAA.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from enum import Enum

logger = logging.getLogger("AuditLogger")

class AuditEventType(Enum):
    """Valid audit event types."""
    DECISION_MADE = "decision_made"
    ESCALATION_APPROVED = "escalation_approved"
    ESCALATION_DENIED = "escalation_denied"
    FEEDBACK_SUBMITTED = "feedback_submitted"
    SETTINGS_UPDATED = "settings_updated"
    CIRCUIT_BREAKER_OPENED = "circuit_breaker_opened"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"

class AuditLogger:
    """Append-only event logging for compliance."""
    
    COLLECTION_NAME = "audit_events"
    
    def __init__(self, store=None):
        """Initialize with MemoryStore instance."""
        self.store = store
    
    def log_event(
        self,
        event_type: AuditEventType,
        actor: str,
        resource_id: str,
        action: str,
        details: Dict[str, Any],
        outcome: str,  # "success" or "failure"
        request_id: Optional[str] = None,
    ) -> str:
        """
        Log immutable audit event.
        
        Args:
            event_type: Type of event (from AuditEventType enum)
            actor: Who performed action (api_key, user_id, system)
            resource_id: What was affected (event_id, ticket_id, etc.)
            action: Specific action taken (blocked, escalated, etc.)
            details: Context dict with additional info
            outcome: success/failure
            request_id: Correlation ID from request tracing
        
        Returns:
            audit_event_id for reference
        """
        timestamp = datetime.now(timezone.utc)
        
        event = {
            "timestamp": timestamp.isoformat(),
            "event_type": event_type.value,
            "actor": actor,
            "resource_id": resource_id,
            "action": action,
            "details": details,
            "outcome": outcome,
            "request_id": request_id,
        }
        
        # Generate unique audit ID
        audit_id = f"audit_{resource_id}_{int(timestamp.timestamp() * 1000)}"
        
        try:
            # CRITICAL: Use upsert to avoid duplicates, NEVER use add()
            self.store.audit_events.upsert(
                ids=[audit_id],
                documents=[json.dumps(event)],
                metadatas=[{
                    "event_type": event_type.value,
                    "actor": actor,
                    "resource_id": resource_id,
                    "timestamp": timestamp.isoformat(),
                    "outcome": outcome,
                }],
            )
            logger.info(
                f"Audit event logged: {event_type.value} | actor={actor} | action={action}",
                extra={"audit_id": audit_id, "request_id": request_id}
            )
            return audit_id
        except Exception as e:
            # CRITICAL: Audit failures must not be silent
            logger.error(
                f"Audit logging failed: {e}",
                exc_info=True,
                extra={"event_type": event_type.value}
            )
            raise

# Initialize after store is available
audit_logger: Optional[AuditLogger] = None

def init_audit_logger(store) -> AuditLogger:
    """Initialize audit logger with store instance."""
    global audit_logger
    audit_logger = AuditLogger(store)
    return audit_logger

def get_audit_logger() -> Optional[AuditLogger]:
    """Retrieve the initialized audit logger."""
    return audit_logger
