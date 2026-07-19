"""
service.py — ARES-Mem FastAPI Service (ACIF v2).

Endpoints:
  POST /ingest          — ingest a raw log through the ACIF pipeline
  GET  /metrics         — system health, CIE trust weights, reliability, and pipeline stats
  GET  /quarantine      — list all escalation tickets in PENDING_REVIEW status
  POST /resolve         — approve or reverse an escalation ticket
  POST /feedback        — submit analyst feedback (triggers SelfLearningAgent)
  GET  /explain/{id}    — retrieve the CIE explanation narrative for an event

  GET  /                — Glassmorphic HTML Dashboard (ACIF v2 edition)

Auth: API key via X-API-KEY header. Three keys map to provenance tiers:
  system-key-123    → system (0 hops)
  internal-key-456  → internal (1 hop)
  external-key-789  → external (2 hops)
"""

import json
import logging
import os
import secrets
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List
from uuid import uuid4

import chromadb
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from enum import Enum

# Ensure src/ is importable when running from project root
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from orchestrator import run_ares, _get_agent, get_agent_registry, AgentRegistry
from self_learning_agent import (
    SelfLearningAgent,
    VERDICT_CONFIRMED, VERDICT_FALSE_POS, VERDICT_MISSED, VERDICT_BENIGN,
)
from models import ErrorResponse, SuccessResponse

class JSONFormatter(logging.Formatter):
    """Outputs structured JSON logs"""
    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        from src.tracing import tracer
        request_id = tracer.get_id()
        if request_id:
            log_obj["request_id"] = request_id
            
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
            
        # Incorporate any extra kwargs passed to logger
        for key, value in record.__dict__.items():
            if key not in ["args", "asctime", "created", "exc_info", "exc_text", "filename", "funcName", "levelname", "levelno", "lineno", "message", "module", "msecs", "msg", "name", "pathname", "process", "processName", "relativeCreated", "stack_info", "thread", "threadName", "taskName"]:
                if key not in log_obj:
                    log_obj[key] = value
                    
        return json.dumps(log_obj)

def setup_logging(level: str = "INFO"):
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    
    root_logger = logging.getLogger()
    root_logger.setLevel(level.upper())
    # clear existing handlers to avoid duplicates
    root_logger.handlers = []
    root_logger.addHandler(handler)
    
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("chromadb").setLevel(logging.WARNING)

logger = logging.getLogger("AresMemService")

# ── API Key → provenance tier mapping ─────────────────────────────────────────
_API_KEYS: Dict[str, Dict[str, Any]] = {
    "system-key-123":   {"source": "system",   "provenance_hops": 0},
    "internal-key-456": {"source": "internal", "provenance_hops": 1},
    "external-key-789": {"source": "external", "provenance_hops": 2},
}

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="ARES-Mem API (ACIF v2)",
    description="Adaptive Coordination Intelligence Framework for Autonomous Cyber Defense",
    version="2.0.0",
)

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from src.tracing import tracer
import uuid

@app.middleware("http")
async def add_request_tracing_middleware(request: Request, call_next):
    """
    Add request ID to every HTTP request for tracing.
    If X-Request-ID header provided, use it. Otherwise generate new UUID.
    """
    # Extract or generate request ID
    request_id = request.headers.get("X-Request-ID")
    if not request_id:
        request_id = str(uuid.uuid4())
    
    # Set in context for access in handlers
    tracer.set_id(request_id)
    
    # Add to request state
    request.state.request_id = request_id
    
    # Process request
    response = await call_next(request)
    
    # Add request ID to response headers
    response.headers["X-Request-ID"] = request_id
    
    return response

@app.on_event("startup")
async def startup_event():
    from config.settings import load_settings
    settings = load_settings()
    setup_logging(settings.logging.level)
    
    # Initialize audit logger
    from src.audit_logger import init_audit_logger
    store = get_agent_registry().get_agent("store")
    init_audit_logger(store)
    
    logger.info(f"Starting {settings.app_name} v{settings.version}")

@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    logger.warning(f"Validation error: {exc}")
    return JSONResponse(
        status_code=400,
        content=ErrorResponse(
            code="INVALID_VALUE",
            message=str(exc),
            request_id=request.headers.get("X-Request-ID")
        ).dict()
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            code="INTERNAL_ERROR",
            message="An unexpected error occurred",
            request_id=request.headers.get("X-Request-ID")
        ).dict()
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    code = "AUTH_REQUIRED" if exc.status_code in (401, 403) else "HTTP_ERROR"
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            code=code,
            message=exc.detail,
            request_id=request.headers.get("X-Request-ID")
        ).dict()
    )


# ── Auth dependency ───────────────────────────────────────────────────────────

def verify_api_key(request: Request) -> Dict[str, Any]:
    """Validate X-API-KEY header using constant-time comparison."""
    provided = request.headers.get("X-API-KEY", "")
    for key, meta in _API_KEYS.items():
        if secrets.compare_digest(provided, key):
            return meta
    raise HTTPException(status_code=403, detail="Invalid or missing API key")


# ── Pydantic request/response models ─────────────────────────────────────────

class IngestRequest(BaseModel):
    id: Optional[str] = None
    log: str

class ResolveRequest(BaseModel):
    ticket_id: str
    action: str                      # "approve" | "reverse"
    analyst_note: Optional[str] = ""

class FeedbackRequest(BaseModel):
    event_id: str
    decision_made: str
    analyst_verdict: str             # CONFIRMED_THREAT | FALSE_POSITIVE | MISSED_THREAT | CONFIRMED_BENIGN
    trace_id: Optional[str] = None
    analyst_note: Optional[str] = None

class IngestResponse(BaseModel):
    status: str
    decision: str
    risk_score: int
    conflict_detected: bool
    threat_belief: float
    event_id: str
    explanation_preview: str
    execution_status: str
    history: list


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"

class HealthCheck(BaseModel):
    status: HealthStatus
    timestamp: str
    version: str
    checks: Dict[str, str]

# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/ingest", response_model=SuccessResponse[IngestResponse], tags=["Pipeline"])
def ingest(
    body: IngestRequest, 
    auth: Dict = Depends(verify_api_key),
    registry: AgentRegistry = Depends(get_agent_registry)
):
    """
    Ingest a raw security log through the full ACIF pipeline.
    Safely ingests escalation data with automatic upsert.
    """
    logger.info(f"[/ingest] source={auth['source']} log_len={len(body.log)}")
    try:
        # Pass registry to run_ares so orchestrator can use it
        result = run_ares(body.log, registry=registry)
        cie    = result.get("cie_output", {})
        dec    = result.get("decision", {})
        fusion = cie.get("fusion_result", {})
        conf   = cie.get("conflict_report", {})
        exec_r = result.get("execution_result", {})
        expl   = cie.get("explanation", "")

        # Store escalation ticket if generated
        ticket = result.get("escalation_ticket")
        if ticket:
            escalation_id = body.id or ticket.get("ticket_id") or f"escalation_{uuid4()}"
            store_agent = registry.get("store")
            if store_agent and hasattr(store_agent, "escalations"):
                store_agent.escalations.upsert(
                    ids=[escalation_id],
                    metadatas=[{
                        "ticket_id":  ticket.get("ticket_id", ""),
                        "status":     ticket.get("status", ""),
                        "source_ip":  ticket.get("source_ip", ""),
                        "risk_score": ticket.get("risk_score", 0),
                        "created_at": ticket.get("created_at", ""),
                        "timestamp":  datetime.utcnow().isoformat(),
                    }],
                    documents=[json.dumps(ticket)],
                )

        data = IngestResponse(
            status="processed",
            decision=dec.get("decision", "UNKNOWN"),
            risk_score=result.get("threat_analysis", {}).get("risk_score", 0),
            conflict_detected=conf.get("conflict_detected", False),
            threat_belief=fusion.get("threat_belief", 0.0),
            event_id=cie.get("event_id", ""),
            explanation_preview=expl[:300] if expl else "",
            execution_status=exec_r.get("status", ""),
            history=result.get("history", []),
        )
        return SuccessResponse(data=data)
    except Exception as exc:
        logger.error(f"[/ingest] Pipeline error: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/metrics", response_model=SuccessResponse[Dict], tags=["Monitoring"])
def metrics(
    auth: Dict = Depends(verify_api_key),
    registry: AgentRegistry = Depends(get_agent_registry)
):
    """
    System health and CIE metrics: trust weights, agent reliability,
    pipeline statistics, and pending delay queue.
    """
    try:
        cie_agent  = registry.get("cie")
        resp_agent = registry.get("muscle")
        store      = registry.get("store")
        learner    = registry.get("self_learner")

        if not all([cie_agent, resp_agent, store, learner]):
            # If not initialized yet, initialize them by fetching through _get_agent once
            _get_agent("cie")
            _get_agent("muscle")
            _get_agent("self_learner")
            cie_agent  = registry.get("cie")
            resp_agent = registry.get("muscle")
            store      = registry.get("store")
            learner    = registry.get("self_learner")

        cie_metrics   = cie_agent.get_metrics() if cie_agent else {}
        history       = resp_agent.get_history() if resp_agent else []
        pending_delays = resp_agent.get_pending_delays() if resp_agent else []
        memories      = store.get_all_memories(limit=100) if store else []
        feedback_stats = learner.get_summary_stats() if learner else {}

        # Decision distribution from action history
        decision_counts: Dict[str, int] = {}
        for h in history:
            d = h.get("decision", "UNKNOWN")
            decision_counts[d] = decision_counts.get(d, 0) + 1

        data = {
            "cie": {
                "trust_weights":  cie_metrics.get("trust_weights"),
                "beta_params":    cie_metrics.get("beta_params"),
                "reliability":    cie_metrics.get("reliability"),
            },
            "pipeline": {
                "total_events":    len(history),
                "decision_counts": decision_counts,
                "pending_delays":  len(pending_delays),
                "memory_entries":  len(memories),
            },
            "self_learning": feedback_stats,
            "service": {
                "status": "healthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": "2.0.0-acif",
            },
        }
        return SuccessResponse(data=data)
    except Exception as exc:
        logger.error(f"[/metrics] {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/quarantine", response_model=SuccessResponse[List[Dict]], tags=["Escalations"])
def list_quarantine(
    auth: Dict = Depends(verify_api_key),
    registry: AgentRegistry = Depends(get_agent_registry)
):
    """List all escalation tickets currently in PENDING_REVIEW status."""
    try:
        store_agent = registry.get("store") or _get_agent("store")
        escalations = store_agent.escalations
        total = escalations.count()
        if total == 0:
            return SuccessResponse(data=[], meta={"total": 0})
        result = escalations.get(limit=min(total, 50))
        tickets = []
        for doc, meta in zip(result.get("documents") or [], result.get("metadatas") or []):
            if meta and meta.get("status") in ("quarantined_pending_review", "OPEN"):
                try:
                    ticket_data = json.loads(doc)
                except Exception:
                    ticket_data = {"raw": doc}
                tickets.append({**ticket_data, **(meta or {})})
        return SuccessResponse(data=tickets, meta={"total": len(tickets)})
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/resolve", response_model=SuccessResponse[Dict], tags=["Escalations"])
def resolve_ticket(
    body: ResolveRequest, 
    auth: Dict = Depends(verify_api_key),
    registry: AgentRegistry = Depends(get_agent_registry)
):
    """
    Approve or reverse an escalation ticket.
    Uses ChromaDB .update() to avoid duplicate-key bugs.
    """
    action = body.action.lower()
    if action not in ("approve", "reverse"):
        raise HTTPException(status_code=400, detail="action must be 'approve' or 'reverse'")

    new_status = "RESOLVED_APPROVED" if action == "approve" else "RESOLVED_REVERSED"
    try:
        store_agent = registry.get("store") or _get_agent("store")
        store_agent.escalations.update(
            ids=[body.ticket_id],
            metadatas=[{
                "status":      new_status,
                "resolved_at": datetime.now(timezone.utc).isoformat(),
                "analyst_note": body.analyst_note or "",
            }],
        )
        from src.audit_logger import get_audit_logger, AuditEventType
        logger_instance = get_audit_logger()
        if logger_instance:
            try:
                request_id = getattr(getattr(auth, "request", None), "state", None)
                req_id_str = request_id.request_id if request_id and hasattr(request_id, "request_id") else None
                logger_instance.log_event(
                    event_type=AuditEventType.ESCALATION_APPROVED if action == "approve" else AuditEventType.ESCALATION_DENIED,
                    actor=auth.get("source", "system"),
                    resource_id=body.ticket_id,
                    action="escalation_resolved",
                    details={
                        "operator_decision": action,
                        "analyst_note": body.analyst_note or "",
                    },
                    outcome="success",
                    request_id=req_id_str,
                )
            except Exception as exc:
                logger.error(f"Audit log failed in /resolve: {exc}")

        return SuccessResponse(data={
            "ticket_id":  body.ticket_id,
            "new_status": new_status,
            "resolved_at": datetime.now(timezone.utc).isoformat(),
        })
    except Exception as exc:
        logger.error(f"[/resolve] Update failed for {body.ticket_id}: {exc}")
        raise HTTPException(status_code=404, detail=f"Ticket {body.ticket_id} not found or update failed")


@app.post("/feedback", response_model=SuccessResponse[Dict], tags=["Self-Learning"])
def submit_feedback(
    body: FeedbackRequest, 
    auth: Dict = Depends(verify_api_key),
    registry: AgentRegistry = Depends(get_agent_registry)
):
    """
    Submit analyst feedback to the SelfLearningAgent.
    """
    try:
        learner = registry.get("self_learner") or _get_agent("self_learner")
        result  = learner.record_feedback(
            event_id=body.event_id,
            decision_made=body.decision_made,
            analyst_verdict=body.analyst_verdict,
            trace_id=body.trace_id,
            analyst_note=body.analyst_note,
        )
        return SuccessResponse(data=result)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.error(f"[/feedback] {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))

@app.get("/audit/events", tags=["Compliance"])
def get_audit_events(
    auth: Dict = Depends(verify_api_key),
    event_type: Optional[str] = None,
    actor: Optional[str] = None,
    resource_id: Optional[str] = None,
    limit: int = 100,
):
    """
    Query immutable audit trail.
    Requires: internal or system tier API key.
    """
    if auth["source"] not in ("system", "internal"):
        raise HTTPException(status_code=403, detail="Insufficient permissions for audit access")
    
    if limit > 1000:
        limit = 1000
    
    store = _get_agent("store")
    
    try:
        # Build where filter
        where_filter = {}
        if event_type:
            where_filter["event_type"] = {"$eq": event_type}
        if actor:
            where_filter["actor"] = {"$eq": actor}
        if resource_id:
            where_filter["resource_id"] = {"$eq": resource_id}
        
        # Query
        where_clause = where_filter if where_filter else None
        results = store.audit_events.get(
            where=where_clause,
            limit=limit,
        )
        
        # Parse events
        events = []
        for doc, meta in zip(
            results.get("documents", []),
            results.get("metadatas", [])
        ):
            try:
                event = json.loads(doc)
                # Merge metadata
                event_obj = {**event, **meta}
                events.append(event_obj)
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse audit event document")
        
        return JSONResponse({
            "events": events,
            "total": len(events),
            "query": {
                "event_type": event_type,
                "actor": actor,
                "resource_id": resource_id,
                "limit": limit,
            },
        })
    
    except Exception as e:
        logger.error(f"Audit query failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to query audit trail")


@app.get("/explain/{event_id}", response_model=SuccessResponse[Dict], tags=["Explainability"])
def explain_event(
    event_id: str, 
    auth: Dict = Depends(verify_api_key),
    registry: AgentRegistry = Depends(get_agent_registry)
):
    """
    Retrieve the CIE explanation narrative for a given event_id.
    """
    try:
        store_agent = registry.get("store") or _get_agent("store")
        result = store_agent.escalations.get(ids=[event_id])
        docs   = result.get("documents") or []
        metas  = result.get("metadatas") or []
        if not docs:
            raise HTTPException(status_code=404, detail=f"Event {event_id} not found in escalation store")
        ticket_data = json.loads(docs[0]) if docs[0] else {}
        return SuccessResponse(data={
            "event_id":    event_id,
            "explanation": ticket_data.get("explanation", "No explanation available"),
            "decision":    ticket_data.get("decision", "UNKNOWN"),
            "status":      (metas[0] or {}).get("status", "UNKNOWN"),
            "created_at":  ticket_data.get("created_at", ""),
        })
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.get("/health", response_model=HealthCheck)
async def health_check(registry: AgentRegistry = Depends(get_agent_registry)) -> HealthCheck:
    """Kubernetes-compatible health check"""
    checks = {}
    from config.settings import load_settings
    settings = load_settings()
    try:
        memory_store = registry.get("store") or _get_agent("store")
        checks["memory_store"] = "ok" if memory_store else "unavailable"
        
        coord_engine = registry.get("cie") or _get_agent("cie")
        checks["coordination_engine"] = "ok" if coord_engine else "unavailable"
        
        try:
            if memory_store and hasattr(memory_store, "escalations"):
                memory_store.escalations.get(limit=1)  # Test query
                checks["escalations_db"] = "ok"
            else:
                checks["escalations_db"] = "unavailable"
        except Exception as e:
            logger.warning(f"DB health check failed: {e}")
            checks["escalations_db"] = "error"
        
        failed = [k for k, v in checks.items() if v != "ok"]
        if not failed:
            overall_status = HealthStatus.HEALTHY
        elif len(failed) < len(checks):
            overall_status = HealthStatus.DEGRADED
        else:
            overall_status = HealthStatus.UNHEALTHY
        
        return HealthCheck(
            status=overall_status,
            timestamp=datetime.utcnow().isoformat(),
            version=settings.version,
            checks=checks
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        return HealthCheck(
            status=HealthStatus.UNHEALTHY,
            timestamp=datetime.utcnow().isoformat(),
            version=settings.version,
            checks={"error": str(e)}
        )

@app.get("/live")
async def liveness() -> Dict:
    return {"status": "alive"}

@app.get("/ready")
async def readiness(registry: AgentRegistry = Depends(get_agent_registry)) -> Dict:
    health = await health_check(registry)
    if health.status == HealthStatus.HEALTHY:
        return {"status": "ready"}
    else:
        raise HTTPException(status_code=503, detail="Service not ready")


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
def dashboard():
    """ACIF v2 glassmorphic dashboard with real-time CIE metrics panel."""
    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>ARES-Mem Security Operations Center (ACIF v2 Dashboard)</title>
<meta name="description" content="Adaptive Coordination Intelligence Framework — real-time cyber defense dashboard"/>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet"/>
<style>
  :root {
    --bg: #050812;
    --surface: rgba(255,255,255,0.04);
    --surface-hover: rgba(255,255,255,0.07);
    --border: rgba(255,255,255,0.08);
    --accent: #6366f1;
    --accent2: #06b6d4;
    --accent3: #10b981;
    --danger: #ef4444;
    --warning: #f59e0b;
    --text: #e2e8f0;
    --muted: #64748b;
    --glow: 0 0 20px rgba(99,102,241,0.25);
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:var(--bg); color:var(--text); font-family:'Inter',sans-serif;
         min-height:100vh; overflow-x:hidden; }
  body::before {
    content:''; position:fixed; inset:0; z-index:-1;
    background: radial-gradient(ellipse 80% 60% at 20% 0%, rgba(99,102,241,0.12) 0%, transparent 60%),
                radial-gradient(ellipse 60% 50% at 80% 100%, rgba(6,182,212,0.10) 0%, transparent 60%);
  }
  header { padding: 2rem 3rem 1.5rem; border-bottom: 1px solid var(--border);
           display:flex; align-items:center; gap:1rem; }
  .logo { width:40px; height:40px; background:linear-gradient(135deg,var(--accent),var(--accent2));
          border-radius:10px; display:flex; align-items:center; justify-content:center;
          font-size:1.3rem; box-shadow:var(--glow); }
  header h1 { font-size:1.3rem; font-weight:600; letter-spacing:.5px; }
  header .badge { margin-left:auto; background:rgba(99,102,241,0.2); color:var(--accent);
                  padding:.25rem .75rem; border-radius:999px; font-size:.75rem;
                  border:1px solid rgba(99,102,241,0.3); }
  main { max-width:1400px; margin:0 auto; padding:2rem 3rem 4rem; }
  .section-title { font-size:.7rem; font-weight:600; letter-spacing:.12em;
                   text-transform:uppercase; color:var(--muted); margin-bottom:1rem; }
  .grid-4 { display:grid; grid-template-columns:repeat(4,1fr); gap:1rem; margin-bottom:2rem; }
  .grid-3 { display:grid; grid-template-columns:repeat(3,1fr); gap:1rem; margin-bottom:2rem; }
  .grid-2 { display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin-bottom:2rem; }
  .card {
    background:var(--surface); border:1px solid var(--border); border-radius:16px;
    padding:1.5rem; backdrop-filter:blur(12px);
    transition:background .2s, box-shadow .2s;
  }
  .card:hover { background:var(--surface-hover); box-shadow:0 4px 30px rgba(0,0,0,0.3); }
  .card-label { font-size:.7rem; color:var(--muted); text-transform:uppercase;
                letter-spacing:.08em; margin-bottom:.4rem; }
  .card-value { font-size:2rem; font-weight:700; line-height:1; }
  .card-sub { font-size:.8rem; color:var(--muted); margin-top:.3rem; }
  .text-accent  { color:var(--accent); }
  .text-accent2 { color:var(--accent2); }
  .text-green   { color:var(--accent3); }
  .text-red     { color:var(--danger); }
  .text-yellow  { color:var(--warning); }

  /* CIE Trust Panel */
  .cie-panel { background:var(--surface); border:1px solid var(--border); border-radius:16px;
               padding:1.5rem; margin-bottom:2rem; }
  .cie-panel h3 { font-size:.85rem; font-weight:600; margin-bottom:1.2rem;
                  color:var(--accent2); letter-spacing:.04em; }
  .trust-row { display:flex; align-items:center; gap:1rem; margin-bottom:.9rem; }
  .trust-name { font-size:.8rem; font-family:'JetBrains Mono',monospace;
                width:220px; color:var(--text); flex-shrink:0; }
  .trust-bar-wrap { flex:1; background:rgba(255,255,255,0.06); border-radius:999px;
                    height:8px; overflow:hidden; }
  .trust-bar { height:8px; border-radius:999px;
               background:linear-gradient(90deg,var(--accent),var(--accent2)); transition:width .5s ease; }
  .trust-pct { font-size:.8rem; font-family:'JetBrains Mono',monospace;
               width:50px; text-align:right; color:var(--muted); }

  /* Pipeline log */
  .pipeline-log { background:rgba(0,0,0,0.4); border:1px solid var(--border); border-radius:12px;
                  padding:1.2rem; font-family:'JetBrains Mono',monospace; font-size:.78rem;
                  height:240px; overflow-y:auto; line-height:1.7; color:#94a3b8; }
  .log-ts   { color:var(--muted); }
  .log-ok   { color:var(--accent3); }
  .log-warn { color:var(--warning); }
  .log-err  { color:var(--danger); }

  /* Ingest form */
  .form-wrap { background:var(--surface); border:1px solid var(--border); border-radius:16px;
               padding:1.5rem; margin-bottom:2rem; }
  .form-row { display:flex; gap:.75rem; align-items:flex-end; }
  textarea { flex:1; background:rgba(0,0,0,0.4); border:1px solid var(--border);
             border-radius:10px; color:var(--text); font-family:'JetBrains Mono',monospace;
             font-size:.82rem; padding:.8rem 1rem; resize:vertical; min-height:80px;
             outline:none; transition:border-color .2s; }
  textarea:focus { border-color:var(--accent); }
  .api-key-row { display:flex; gap:.75rem; margin-bottom:.75rem; align-items:center; }
  input[type=text] { background:rgba(0,0,0,0.4); border:1px solid var(--border);
                     border-radius:8px; color:var(--text); padding:.55rem .9rem;
                     font-size:.82rem; outline:none; font-family:'JetBrains Mono',monospace;
                     width:260px; transition:border-color .2s; }
  input[type=text]:focus { border-color:var(--accent); }
  button { background:linear-gradient(135deg,var(--accent),var(--accent2));
           color:#fff; border:none; border-radius:10px; padding:.6rem 1.4rem;
           font-size:.85rem; font-weight:600; cursor:pointer; transition:opacity .2s, transform .1s; }
  button:hover { opacity:.88; }
  button:active { transform:scale(.98); }
  .result-box { margin-top:1rem; background:rgba(0,0,0,0.35); border-radius:10px;
                padding:1rem; font-family:'JetBrains Mono',monospace; font-size:.78rem;
                color:#94a3b8; white-space:pre-wrap; display:none; max-height:200px; overflow:auto; }

  /* Endpoint reference */
  .endpoint { display:flex; align-items:center; gap:.7rem; padding:.5rem 0;
              border-bottom:1px solid var(--border); font-size:.82rem; }
  .endpoint:last-child { border-bottom:none; }
  .method { font-family:'JetBrains Mono',monospace; font-size:.72rem; font-weight:600;
            padding:.15rem .5rem; border-radius:5px; }
  .method-post { background:rgba(99,102,241,0.2); color:var(--accent); }
  .method-get  { background:rgba(6,182,212,0.2); color:var(--accent2); }
  .ep-path { color:var(--text); font-family:'JetBrains Mono',monospace; }
  .ep-desc { color:var(--muted); font-size:.75rem; margin-left:auto; }

  /* Conflict panel */
  .conflict-badge { display:inline-flex; align-items:center; gap:.4rem; padding:.3rem .8rem;
                    border-radius:999px; font-size:.75rem; font-weight:600; }
  .no-conflict { background:rgba(16,185,129,0.15); color:var(--accent3);
                 border:1px solid rgba(16,185,129,0.3); }
  .has-conflict { background:rgba(239,68,68,0.15); color:var(--danger);
                  border:1px solid rgba(239,68,68,0.3); }

  @keyframes pulse { 0%,100%{opacity:.7} 50%{opacity:1} }
  .live-dot { width:8px; height:8px; border-radius:50%; background:var(--accent3);
              display:inline-block; animation:pulse 2s infinite; }
</style>
</head>
<body>
<header>
  <div class="logo">🛡</div>
  <div>
    <h1>ARES-Mem — ACIF v2</h1>
    <div style="font-size:.75rem;color:var(--muted)">Adaptive Coordination Intelligence Framework</div>
  </div>
  <span class="badge">▶ LIVE <span class="live-dot" style="margin-left:.3rem"></span></span>
</header>

<main>

  <!-- Section: KPI Row -->
  <div class="section-title">System Overview</div>
  <div class="grid-4">
    <div class="card" id="kpi-events">
      <div class="card-label">Total Events</div>
      <div class="card-value text-accent" id="val-events">—</div>
      <div class="card-sub">Pipeline ingestions</div>
    </div>
    <div class="card">
      <div class="card-label">Memory Entries</div>
      <div class="card-value text-accent2" id="val-memory">—</div>
      <div class="card-sub">ChromaDB traces</div>
    </div>
    <div class="card">
      <div class="card-label">Pending Delays</div>
      <div class="card-value text-yellow" id="val-delays">—</div>
      <div class="card-sub">Deferred actions</div>
    </div>
    <div class="card">
      <div class="card-label">Feedback Events</div>
      <div class="card-value text-green" id="val-feedback">—</div>
      <div class="card-sub">Analyst labels</div>
    </div>
  </div>

  <!-- Section: CIE Coordination Panel -->
  <div class="section-title">Coordination Intelligence Engine</div>
  <div class="cie-panel">
    <h3>⚖ Agent Trust Weights (Beta Posterior Means)</h3>
    <div id="trust-bars"><div style="color:var(--muted);font-size:.82rem">Loading trust weights...</div></div>
    <div style="margin-top:1.2rem;display:flex;gap:2rem;flex-wrap:wrap;" id="beta-params"></div>
  </div>

  <!-- Section: Decision Distribution + Self-Learning -->
  <div class="grid-2">
    <div class="card">
      <div class="card-label" style="margin-bottom:.8rem">Decision Distribution</div>
      <div id="decision-dist" style="font-family:'JetBrains Mono',monospace;font-size:.8rem;">
        <span style="color:var(--muted)">No events yet</span>
      </div>
    </div>
    <div class="card">
      <div class="card-label" style="margin-bottom:.8rem">Self-Learning Stats</div>
      <div id="learning-stats" style="font-family:'JetBrains Mono',monospace;font-size:.8rem;">
        <span style="color:var(--muted)">No feedback recorded</span>
      </div>
    </div>
  </div>

  <!-- Section: Ingest Form -->
  <div class="section-title">Ingest Log</div>
  <div class="form-wrap">
    <div class="api-key-row">
      <label style="font-size:.8rem;color:var(--muted)">API Key:</label>
      <input type="text" id="api-key-input" value="internal-key-456" placeholder="API key"/>
      <span style="font-size:.75rem;color:var(--muted)">Default: internal-key-456</span>
    </div>
    <div class="form-row">
      <textarea id="log-input" placeholder="Enter raw security log... e.g. Suspicious login from 185.220.1.1 with brute force indicators"></textarea>
      <button id="ingest-btn" onclick="ingestLog()">▶ Ingest</button>
    </div>
    <div id="ingest-result" class="result-box"></div>
  </div>

  <!-- Section: API Reference -->
  <div class="section-title">API Endpoints (ACIF v2)</div>
  <div class="card">
    <div class="endpoint">
      <span class="method method-post">POST</span>
      <span class="ep-path">/ingest</span>
      <span class="ep-desc">Run log through full ACIF pipeline</span>
    </div>
    <div class="endpoint">
      <span class="method method-get">GET</span>
      <span class="ep-path">/metrics</span>
      <span class="ep-desc">CIE trust weights, reliability, pipeline stats</span>
    </div>
    <div class="endpoint">
      <span class="method method-get">GET</span>
      <span class="ep-path">/quarantine</span>
      <span class="ep-desc">List escalation tickets pending review</span>
    </div>
    <div class="endpoint">
      <span class="method method-post">POST</span>
      <span class="ep-path">/resolve</span>
      <span class="ep-desc">Approve or reverse an escalation ticket</span>
    </div>
    <div class="endpoint">
      <span class="method method-post">POST</span>
      <span class="ep-path">/feedback</span>
      <span class="ep-desc">Submit analyst verdict → update CIE trust weights</span>
    </div>
    <div class="endpoint">
      <span class="method method-get">GET</span>
      <span class="ep-path">/explain/{id}</span>
      <span class="ep-desc">Retrieve CIE explanation narrative for an event</span>
    </div>
  </div>

</main>

<script>
const API_KEY = () => document.getElementById('api-key-input').value || 'internal-key-456';

async function loadMetrics() {
  try {
    const r = await fetch('/metrics', { headers: { 'X-API-KEY': API_KEY() } });
    if (!r.ok) return;
    const d = await r.json();

    // KPIs
    const p = d.pipeline || {};
    document.getElementById('val-events').textContent  = p.total_events ?? '0';
    document.getElementById('val-memory').textContent  = p.memory_entries ?? '0';
    document.getElementById('val-delays').textContent  = p.pending_delays ?? '0';
    const sl = d.self_learning || {};
    document.getElementById('val-feedback').textContent = sl.total_events ?? '0';

    // Trust bars
    const cie = d.cie || {};
    const tw  = cie.trust_weights || {};
    const bp  = cie.beta_params   || {};
    const trustEl = document.getElementById('trust-bars');
    if (Object.keys(tw).length === 0) {
      trustEl.innerHTML = '<div style="color:var(--muted);font-size:.82rem">No trust data yet — ingest some logs</div>';
    } else {
      trustEl.innerHTML = Object.entries(tw).map(([name, w]) => {
        const pct = Math.round(w * 100);
        const params = bp[name] || {};
        const a = (params.alpha || 2).toFixed(1), b = (params.beta || 1).toFixed(1);
        return `<div class="trust-row">
          <span class="trust-name">${name}</span>
          <div class="trust-bar-wrap"><div class="trust-bar" style="width:${pct}%"></div></div>
          <span class="trust-pct">${pct}%</span>
          <span style="font-size:.72rem;color:var(--muted);font-family:'JetBrains Mono',monospace;width:120px">α=${a} β=${b}</span>
        </div>`;
      }).join('');
    }

    // Decision distribution
    const dc = p.decision_counts || {};
    const decEl = document.getElementById('decision-dist');
    if (Object.keys(dc).length === 0) {
      decEl.innerHTML = '<span style="color:var(--muted)">No decisions yet</span>';
    } else {
      const total = Object.values(dc).reduce((a,b)=>a+b,0);
      const colors = { BLOCK_IP:'#ef4444', QUARANTINE:'#f59e0b', MONITOR:'#6366f1',
                       ALERT:'#06b6d4', LOG_ONLY:'#64748b', ESCALATE:'#a855f7',
                       DELAY:'#84cc16', ROLLBACK:'#fb923c' };
      decEl.innerHTML = Object.entries(dc).map(([k,v])=>{
        const pct = Math.round(v/total*100);
        const c = colors[k] || '#94a3b8';
        return `<div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.4rem">
          <span style="color:${c};width:100px">${k}</span>
          <div style="flex:1;background:rgba(255,255,255,0.06);border-radius:4px;height:6px;overflow:hidden">
            <div style="width:${pct}%;height:6px;background:${c};border-radius:4px"></div></div>
          <span style="color:var(--muted);width:30px">${v}</span>
        </div>`;
      }).join('');
    }

    // Self-learning
    const learnEl = document.getElementById('learning-stats');
    if (!sl.total_events) {
      learnEl.innerHTML = '<span style="color:var(--muted)">No feedback recorded</span>';
    } else {
      const vc = sl.verdict_counts || {};
      learnEl.innerHTML = `
        <div style="margin-bottom:.4rem">Total Feedback: <span style="color:var(--accent2)">${sl.total_events}</span></div>
        <div style="margin-bottom:.4rem">Precision: <span style="color:var(--accent3)">${sl.precision ?? 'N/A'}</span></div>
        <div style="margin-bottom:.4rem">Recall: <span style="color:var(--accent3)">${sl.recall ?? 'N/A'}</span></div>
        <div style="margin-bottom:.4rem">FP: <span style="color:var(--danger)">${sl.false_positives ?? 0}</span>
             &nbsp; FN: <span style="color:var(--warning)">${sl.false_negatives ?? 0}</span></div>
      `;
    }

  } catch(e) { console.warn('metrics load error:', e); }
}

async function ingestLog() {
  const log = document.getElementById('log-input').value.trim();
  if (!log) return;
  const btn = document.getElementById('ingest-btn');
  btn.textContent = '⏳';
  btn.disabled = true;
  const resultEl = document.getElementById('ingest-result');
  resultEl.style.display = 'block';
  resultEl.textContent = 'Processing...';
  try {
    const r = await fetch('/ingest', {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'X-API-KEY': API_KEY() },
      body: JSON.stringify({ log }),
    });
    const d = await r.json();
    resultEl.textContent = JSON.stringify(d, null, 2);
    loadMetrics();
  } catch(e) {
    resultEl.textContent = 'Error: ' + e.message;
  } finally {
    btn.textContent = '▶ Ingest';
    btn.disabled = false;
  }
}

// Auto-refresh metrics every 30 seconds
loadMetrics();
setInterval(loadMetrics, 30000);
</script>
</body>
</html>"""
    return html


# ── Legacy API routes for test suite backwards compatibility ─────────────────

class LegacyLogIngestRequest(BaseModel):
    log_text: str

@app.post("/api/logs/ingest")
def legacy_ingest(
    body: LegacyLogIngestRequest, 
    auth: Dict = Depends(verify_api_key),
    registry: AgentRegistry = Depends(get_agent_registry)
):
    result = run_ares(body.log_text, registry=registry)
    return result

@app.get("/api/escalations")
def api_escalations(
    auth: Dict = Depends(verify_api_key),
    registry: AgentRegistry = Depends(get_agent_registry)
):
    store_agent = registry.get("store") or _get_agent("store")
    total = store_agent.escalations.count()
    if total == 0:
        return []
    result = store_agent.escalations.get(limit=min(total, 50))
    tickets = []
    for doc, meta in zip(result.get("documents") or [], result.get("metadatas") or []):
        try:
            ticket_data = json.loads(doc)
        except Exception:
            ticket_data = {"raw": doc}
        tickets.append({**ticket_data, **(meta or {})})
    return tickets

@app.get("/api/quarantine")
def api_quarantine(
    auth: Dict = Depends(verify_api_key),
    registry: AgentRegistry = Depends(get_agent_registry)
):
    return api_escalations(auth, registry)

class LegacyResolveRequest(BaseModel):
    status: str
    resolution_notes: str

@app.post("/api/escalations/{ticket_id}/resolve")
def api_resolve_ticket(
    ticket_id: str, 
    body: LegacyResolveRequest, 
    auth: Dict = Depends(verify_api_key),
    registry: AgentRegistry = Depends(get_agent_registry)
):
    try:
        store_agent = registry.get("store") or _get_agent("store")
        res = store_agent.escalations.get(ids=[ticket_id])
        if not res or not res.get("documents"):
            raise HTTPException(status_code=404, detail="Ticket not found")
        store_agent.escalations.update(
            ids=[ticket_id],
            metadatas=[{
                "status": body.status,
                "resolved_at": datetime.now(timezone.utc).isoformat(),
                "analyst_note": body.resolution_notes,
            }],
        )
        return {"status": "success", "ticket_id": ticket_id}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.get("/api/metrics")
def get_api_metrics(
    auth: Dict = Depends(verify_api_key),
    registry: AgentRegistry = Depends(get_agent_registry)
):
    store_agent = registry.get("store") or _get_agent("store")
    esc_res = store_agent.escalations.get()
    tickets_count = len(esc_res.get("ids") or [])
    resolved_count = 0
    for m in (esc_res.get("metadatas") or []):
        if m:
            status = m.get("status")
            if isinstance(status, str) and (status.startswith("RESOLVED") or status == "AUTO_RESOLVED" or status == "RESOLVED_APPROVED"):
                resolved_count += 1
    return {
        "memory_count": store_agent.collection.count(),
        "quarantine_count": store_agent.quarantine.count(),
        "escalation_count": tickets_count,
        "resolved_escalations": resolved_count,
        "active_operator_role": auth["source"],
        "system_status": "healthy"
    }


# ── Dev server entry ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    port = int(os.getenv("PORT", 8080))
    sys.path.insert(0, _SRC_DIR)
    uvicorn.run("service:app", host="0.0.0.0", port=port, reload=False)
