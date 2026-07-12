"""
service.py — FastAPI Service and Glassmorphic SOC Dashboard for ARES-Mem.
"""
import os
import time
import secrets
from typing import Dict, Any, List, Optional
import logging
import uvicorn
from fastapi import FastAPI, Header, Query, HTTPException, Body, Depends
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from orchestrator import run_ares, _store as store, _overseer as overseer

# Setup logger
logger = logging.getLogger("ares_service")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="ARES-Mem Security Operations Center (SOC) API")

# API Keys Configuration
SYSTEM_KEY = os.getenv("ARES_SYSTEM_KEY", "system-key-123")
INTERNAL_KEY = os.getenv("ARES_INTERNAL_KEY", "internal-key-456")
EXTERNAL_KEY = os.getenv("ARES_EXTERNAL_KEY", "external-key-789")

# Model definitions
class LogIngestRequest(BaseModel):
    log_text: str

class ResolveRequest(BaseModel):
    status: str  # RESOLVED_APPROVED or RESOLVED_REVERSED
    resolution_notes: str

# Helper to authenticate API Key and map to tier
def authenticate_key(
    x_api_key: Optional[str] = Header(None),
    api_key: Optional[str] = Query(None)
) -> Dict[str, Any]:
    key = x_api_key or api_key
    if not key:
        raise HTTPException(
            status_code=401,
            detail="Authentication key missing. Provide X-API-KEY header or api_key query param."
        )
        
    if secrets.compare_digest(key, SYSTEM_KEY):
        return {"source": "system", "provenance_hops": 0}
    elif secrets.compare_digest(key, INTERNAL_KEY):
        return {"source": "internal", "provenance_hops": 1}
    elif secrets.compare_digest(key, EXTERNAL_KEY):
        return {"source": "external", "provenance_hops": 2}
    else:
        raise HTTPException(status_code=401, detail="Invalid API key.")

@app.post("/api/logs/ingest")
def ingest_log(
    req: LogIngestRequest,
    cred: Dict[str, Any] = Depends(authenticate_key)
):
    logger.info("Ingesting log from credentials: %s", cred)
    # Silently discard client-supplied source/hops and use credential-derived ones
    result = run_ares(
        log_text=req.log_text,
        source=cred["source"],
        provenance_hops=cred["provenance_hops"]
    )
    
    # Format a response keeping it serializeable
    return {
        "raw_log": result.get("raw_log"),
        "validation_flag": result.get("validation_flag"),
        "privilege_level": result.get("privilege_level"),
        "threat_score": result.get("threat_score"),
        "decision": result.get("decision"),
        "execution_result": result.get("execution_result"),
        "escalation_result": result.get("escalation_result"),
        "security_status": result.get("security_status"),
        "history": result.get("history")
    }

@app.get("/api/escalations")
def list_escalations(cred: Dict[str, Any] = Depends(authenticate_key)):
    # Read all escalations from collection
    res = store.escalations.get()
    tickets = []
    ids = res.get("ids") or []
    metadatas = res.get("metadatas") or []
    documents = res.get("documents") or []
    
    for ticket_id, meta, doc in zip(ids, metadatas, documents):
        if not meta:
            continue
        indicators_str = meta.get("matched_indicators")
        if isinstance(indicators_str, str) and indicators_str:
            indicators = indicators_str.split(",")
        else:
            indicators = []
        tickets.append({
            "ticket_id": meta.get("ticket_id"),
            "severity": meta.get("severity"),
            "risk_score": meta.get("risk_score"),
            "confidence_score": meta.get("confidence_score"),
            "threat_classification": meta.get("threat_classification"),
            "matched_indicators": indicators,
            "original_decision": meta.get("original_decision"),
            "rationale": meta.get("rationale"),
            "environment": meta.get("environment"),
            "status": meta.get("status"),
            "timestamp": meta.get("timestamp"),
            "payload_text": doc
        })
        
    tickets.sort(key=lambda t: t.get("timestamp", 0), reverse=True)
    return tickets

@app.post("/api/escalations/{ticket_id}/resolve")
def resolve_ticket(
    ticket_id: str,
    req: ResolveRequest,
    cred: Dict[str, Any] = Depends(authenticate_key)
):
    if req.status not in ("RESOLVED_APPROVED", "RESOLVED_REVERSED"):
        raise HTTPException(
            status_code=400,
            detail="Invalid resolution status. Must be RESOLVED_APPROVED or RESOLVED_REVERSED."
        )
        
    res = store.escalations.get(ids=[ticket_id])
    if not res or not res.get("ids"):
        raise HTTPException(status_code=404, detail=f"Ticket {ticket_id} not found.")
        
    metadatas = res.get("metadatas")
    documents = res.get("documents")
    if not metadatas or not documents or metadatas[0] is None or documents[0] is None:
        raise HTTPException(status_code=404, detail=f"Ticket {ticket_id} metadata or document missing.")
        
    meta = dict(metadatas[0])
    doc = documents[0]
    
    meta["status"] = req.status
    meta["resolution_notes"] = req.resolution_notes
    meta["resolved_by"] = cred["source"]
    meta["resolved_timestamp"] = time.time()
    
    # ChromaDB duplicate-ID pitfall: use collection.update() directly
    store.escalations.update(
        ids=[ticket_id],
        metadatas=[meta]
    )
    
    if req.status == "RESOLVED_REVERSED":
        logger.info(
            "REVERSAL SUCCESS | ticket=%s | Releasing active quarantine for ticket payload: %s",
            ticket_id,
            doc[:80] + "..." if len(doc) > 80 else doc
        )
        
    return {
        "status": "success",
        "message": f"Ticket {ticket_id} resolved with status {req.status}",
        "ticket": {
            "ticket_id": ticket_id,
            "status": req.status,
            "resolution_notes": req.resolution_notes
        }
    }

@app.get("/api/quarantine")
def list_quarantine(cred: Dict[str, Any] = Depends(authenticate_key)):
    res = store.quarantine.get(limit=100)
    items = []
    ids = res.get("ids") or []
    metadatas = res.get("metadatas") or []
    documents = res.get("documents") or []
    for doc_id, meta, doc in zip(ids, metadatas, documents):
        items.append({
            "id": doc_id,
            "text": doc,
            "metadata": meta
        })
    return items

@app.get("/api/metrics")
def get_metrics(cred: Dict[str, Any] = Depends(authenticate_key)):
    esc_res = store.escalations.get()
    tickets_count = len(esc_res.get("ids") or [])
    resolved_count = 0
    for m in (esc_res.get("metadatas") or []):
        if m:
            status = m.get("status")
            if isinstance(status, str) and status.startswith("RESOLVED"):
                resolved_count += 1
    return {
        "memory_count": store.collection.count(),
        "quarantine_count": store.quarantine.count(),
        "escalation_count": tickets_count,
        "resolved_escalations": resolved_count,
        "active_operator_role": cred["source"],
        "system_status": "healthy"
    }

HTML_CONTENT = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ARES-Mem SOC Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-glow: radial-gradient(circle at 50% 50%, #1a153b 0%, #090816 100%);
            --glass-bg: rgba(17, 12, 38, 0.45);
            --glass-border: rgba(255, 255, 255, 0.08);
            --neon-blue: #00f2fe;
            --neon-purple: #9d4edd;
            --neon-pink: #ff007f;
            --neon-red: #ff3366;
            --neon-green: #39ff14;
            --text-primary: #f3f0ff;
            --text-secondary: #a9a2d2;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            background: var(--bg-glow);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
            display: flex;
            flex-direction: column;
        }
        
        header {
            background: rgba(9, 8, 22, 0.7);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--glass-border);
            padding: 1.2rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        
        .logo-container {
            display: flex;
            align-items: center;
            gap: 0.8rem;
        }
        
        .logo-icon {
            width: 32px;
            height: 32px;
            background: linear-gradient(135deg, var(--neon-blue), var(--neon-purple));
            border-radius: 8px;
            box-shadow: 0 0 15px rgba(0, 242, 254, 0.4);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            color: #000;
        }
        
        header h1 {
            font-size: 1.3rem;
            font-weight: 700;
            letter-spacing: 0.5px;
            background: linear-gradient(90deg, #fff, var(--text-secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .cred-badge {
            background: rgba(0, 242, 254, 0.1);
            border: 1px solid rgba(0, 242, 254, 0.2);
            color: var(--neon-blue);
            padding: 0.4rem 1rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            box-shadow: inset 0 0 10px rgba(0, 242, 254, 0.05);
            cursor: pointer;
        }
        
        main {
            flex: 1;
            padding: 2.5rem 2rem;
            max-width: 1400px;
            width: 100%;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1.5rem;
        }
        
        .stat-card {
            background: var(--glass-bg);
            border: 1px solid var(--glass-border);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border-radius: 16px;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-4px);
            border-color: rgba(255, 255, 255, 0.15);
            box-shadow: 0 10px 25px rgba(0,0,0,0.3);
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
        }
        
        .stat-card.pending::before { background: var(--neon-pink); }
        .stat-card.quarantined::before { background: var(--neon-purple); }
        .stat-card.resolved::before { background: var(--neon-green); }
        .stat-card.avg-risk::before { background: var(--neon-blue); }
        
        .stat-title {
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .stat-value {
            font-size: 2.2rem;
            font-weight: 700;
            line-height: 1;
            letter-spacing: -1px;
        }
        
        .content-area {
            display: grid;
            grid-template-columns: 1fr;
            gap: 2rem;
        }
        
        .section-card {
            background: var(--glass-bg);
            border: 1px solid var(--glass-border);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border-radius: 16px;
            padding: 1.8rem;
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }
        
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .section-title {
            font-size: 1.15rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 0.6rem;
        }
        
        .section-title::before {
            content: '';
            width: 8px;
            height: 18px;
            background: linear-gradient(to bottom, var(--neon-blue), var(--neon-purple));
            border-radius: 4px;
            display: inline-block;
        }
        
        .refresh-btn {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--glass-border);
            color: var(--text-primary);
            padding: 0.5rem 1.2rem;
            border-radius: 8px;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .refresh-btn:hover {
            background: rgba(255, 255, 255, 0.1);
            border-color: rgba(255, 255, 255, 0.2);
        }
        
        .ticket-list {
            display: flex;
            flex-direction: column;
            gap: 1rem;
            max-height: 600px;
            overflow-y: auto;
            padding-right: 0.5rem;
        }
        
        .ticket-list::-webkit-scrollbar {
            width: 6px;
        }
        
        .ticket-list::-webkit-scrollbar-track {
            background: rgba(255,255,255,0.02);
            border-radius: 10px;
        }
        
        .ticket-list::-webkit-scrollbar-thumb {
            background: rgba(255,255,255,0.1);
            border-radius: 10px;
        }
        
        .ticket-card {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 1.2rem;
            display: grid;
            grid-template-columns: 1fr;
            gap: 1rem;
            transition: all 0.2s ease;
        }
        
        @media(min-width: 900px) {
            .ticket-card {
                grid-template-columns: 100px 180px 1fr 240px;
                align-items: center;
            }
        }
        
        .ticket-card:hover {
            background: rgba(255, 255, 255, 0.04);
            border-color: rgba(255, 255, 255, 0.1);
        }
        
        .ticket-id {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            color: var(--neon-blue);
            font-size: 0.9rem;
        }
        
        .ticket-info {
            display: flex;
            flex-direction: column;
            gap: 0.3rem;
        }
        
        .classification-badge {
            background: rgba(255, 51, 102, 0.1);
            border: 1px solid rgba(255, 51, 102, 0.2);
            color: var(--neon-red);
            padding: 0.2rem 0.6rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 700;
            width: fit-content;
            text-transform: uppercase;
        }
        
        .risk-badge {
            font-size: 0.8rem;
            color: var(--text-secondary);
            display: flex;
            align-items: center;
            gap: 0.4rem;
        }
        
        .risk-value {
            font-weight: 700;
            color: var(--text-primary);
        }
        
        .ticket-details {
            display: flex;
            flex-direction: column;
            gap: 0.4rem;
        }
        
        .payload-text {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            color: var(--text-primary);
            background: rgba(0, 0, 0, 0.25);
            padding: 0.6rem 0.8rem;
            border-radius: 6px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            border: 1px solid rgba(255, 255, 255, 0.02);
        }
        
        .rationale-text {
            font-size: 0.8rem;
            color: var(--text-secondary);
            line-height: 1.4;
        }
        
        .ticket-actions {
            display: flex;
            gap: 0.8rem;
            justify-content: flex-end;
        }
        
        .btn {
            padding: 0.5rem 1rem;
            border-radius: 8px;
            font-size: 0.8rem;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s ease;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
        }
        
        .btn-approve {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            border: none;
            color: #fff;
            box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
        }
        
        .btn-approve:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(16, 185, 129, 0.5);
        }
        
        .btn-reverse {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            border: none;
            color: #fff;
            box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
        }
        
        .btn-reverse:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(239, 68, 68, 0.5);
        }
        
        .status-pill {
            padding: 0.4rem 1rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            text-align: center;
        }
        
        .status-pill.resolved-approved {
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: #10b981;
        }
        
        .status-pill.resolved-reversed {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #ef4444;
        }
        
        .status-pill.pending {
            background: rgba(245, 158, 11, 0.1);
            border: 1px solid rgba(245, 158, 11, 0.3);
            color: #f59e0b;
        }
        
        .status-pill.quarantined-pending-review {
            background: rgba(157, 78, 221, 0.15);
            border: 1px solid rgba(157, 78, 221, 0.4);
            color: #c77dff;
        }
        
        .empty-state {
            text-align: center;
            padding: 4rem 2rem;
            color: var(--text-secondary);
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 1rem;
        }
        
        .empty-icon {
            font-size: 3rem;
            filter: drop-shadow(0 0 10px rgba(157, 78, 221, 0.3));
        }

        /* Modal styling */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background: rgba(0, 0, 0, 0.85);
            backdrop-filter: blur(15px);
            z-index: 1000;
            display: flex;
            align-items: center;
            justify-content: center;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.3s ease;
        }

        .modal-overlay.active {
            opacity: 1;
            pointer-events: auto;
        }

        .modal {
            background: var(--glass-bg);
            border: 1px solid var(--glass-border);
            padding: 2.5rem;
            border-radius: 16px;
            width: 100%;
            max-width: 450px;
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5);
            text-align: center;
        }

        .modal h2 {
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(90deg, var(--neon-blue), var(--neon-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .modal p {
            font-size: 0.9rem;
            color: var(--text-secondary);
        }

        .modal-input {
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--glass-border);
            padding: 0.8rem 1rem;
            border-radius: 8px;
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            outline: none;
            text-align: center;
            transition: border-color 0.2s ease;
        }

        .modal-input:focus {
            border-color: var(--neon-blue);
        }

        .modal-btn {
            background: linear-gradient(135deg, var(--neon-blue) 0%, var(--neon-purple) 100%);
            border: none;
            color: #000;
            font-weight: 700;
            padding: 0.8rem;
            border-radius: 8px;
            cursor: pointer;
            text-transform: uppercase;
            letter-spacing: 1px;
            box-shadow: 0 4px 15px rgba(0, 242, 254, 0.3);
            transition: all 0.2s ease;
        }

        .modal-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 242, 254, 0.5);
        }
    </style>
</head>
<body>
    <header>
        <div class="logo-container">
            <div class="logo-icon">Ω</div>
            <h1>ARES-Mem Security Operations Center</h1>
        </div>
        <div class="cred-badge" id="client-role" onclick="changeApiKey()">loading credential...</div>
    </header>
    
    <main>
        <div class="stats-grid">
            <div class="stat-card pending">
                <span class="stat-title">Unresolved Tickets</span>
                <span class="stat-value" id="stats-unresolved">0</span>
            </div>
            <div class="stat-card quarantined">
                <span class="stat-title">Quarantine Actions</span>
                <span class="stat-value" id="stats-quarantined">0</span>
            </div>
            <div class="stat-card resolved">
                <span class="stat-title">Resolved Tickets</span>
                <span class="stat-value" id="stats-resolved">0</span>
            </div>
            <div class="stat-card avg-risk">
                <span class="stat-title">Max Risk Score</span>
                <span class="stat-value" id="stats-risk">0</span>
            </div>
        </div>
        
        <div class="content-area">
            <div class="section-card">
                <div class="section-header">
                    <span class="section-title">SOC Escalation Audit Trail</span>
                    <button class="refresh-btn" onclick="fetchTickets()">Refresh</button>
                </div>
                
                <div class="ticket-list" id="ticket-queue">
                    <div class="empty-state">
                        <span class="empty-icon">🛡️</span>
                        <span>No escalation events registered in the audit trail.</span>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <div class="modal-overlay" id="auth-modal">
        <div class="modal">
            <h2>Authentication Required</h2>
            <p>Accessing the ARES-Mem SOC Dashboard requires a valid API key. Enter your operator credential key below.</p>
            <input type="password" class="modal-input" id="api-key-input" placeholder="internal-key-456">
            <button class="modal-btn" onclick="submitApiKey()">Authenticate</button>
        </div>
    </div>
    
    <script>
        const urlParams = new URLSearchParams(window.location.search);
        let apiKey = urlParams.get('api_key') || localStorage.getItem('ares_api_key');
        
        if (!apiKey) {
            document.getElementById('auth-modal').classList.add('active');
        } else {
            localStorage.setItem('ares_api_key', apiKey);
            initDashboard();
        }

        function submitApiKey() {
            const inputVal = document.getElementById('api-key-input').value.trim();
            if (inputVal) {
                apiKey = inputVal;
                localStorage.setItem('ares_api_key', apiKey);
                document.getElementById('auth-modal').classList.remove('active');
                initDashboard();
            }
        }

        function changeApiKey() {
            const newKey = prompt("Enter new API Key:", apiKey);
            if (newKey) {
                apiKey = newKey.trim();
                localStorage.setItem('ares_api_key', apiKey);
                window.location.reload();
            }
        }

        function initDashboard() {
            document.getElementById('client-role').innerText = `Role: ${apiKey.split('-')[0] || 'Operator'}`;
            fetchTickets();
            setInterval(fetchTickets, 5000);
        }
        
        async function fetchTickets() {
            try {
                const response = await fetch(`/api/escalations?api_key=${apiKey}`);
                if (!response.ok) {
                    if (response.status === 401) {
                        localStorage.removeItem('ares_api_key');
                        window.location.reload();
                    }
                    throw new Error('Failed to fetch tickets');
                }
                const tickets = await response.json();
                
                // Update stats
                const unresolved = tickets.filter(t => t.status === 'PENDING_HUMAN' || t.status === 'quarantined_pending_review').length;
                const quarantined = tickets.filter(t => t.original_decision === 'QUARANTINE' || t.original_decision === 'QUARANTINE_HOST').length;
                const resolved = tickets.filter(t => t.status.startsWith('RESOLVED') || t.status === 'AUTO_RESOLVED').length;
                const maxRisk = tickets.length > 0 ? Math.max(...tickets.map(t => t.risk_score)) : 0;
                
                document.getElementById('stats-unresolved').innerText = unresolved;
                document.getElementById('stats-quarantined').innerText = quarantined;
                document.getElementById('stats-resolved').innerText = resolved;
                document.getElementById('stats-risk').innerText = maxRisk;
                
                const container = document.getElementById('ticket-queue');
                if (tickets.length === 0) {
                    container.innerHTML = `
                        <div class="empty-state">
                            <span class="empty-icon">🛡️</span>
                            <span>No escalation events registered in the audit trail.</span>
                        </div>
                    `;
                    return;
                }
                
                container.innerHTML = tickets.map(t => {
                    let actionHtml = '';
                    if (t.status === 'PENDING_HUMAN' || t.status === 'quarantined_pending_review') {
                        actionHtml = `
                            <div class="ticket-actions">
                                <button class="btn btn-approve" onclick="resolveTicket('${t.ticket_id}', 'RESOLVED_APPROVED')">Approve</button>
                                <button class="btn btn-reverse" onclick="resolveTicket('${t.ticket_id}', 'RESOLVED_REVERSED')">Reverse</button>
                            </div>
                        `;
                    } else {
                        actionHtml = `
                            <span class="status-pill ${t.status.toLowerCase().replace(/_/g, '-')}">${t.status}</span>
                        `;
                    }
                    
                    return `
                        <div class="ticket-card">
                            <span class="ticket-id">${t.ticket_id}</span>
                            <div class="ticket-info">
                                <span class="classification-badge">${t.threat_classification}</span>
                                <div class="risk-badge">Risk: <span class="risk-value">${t.risk_score}</span> | Conf: <span class="risk-value">${t.confidence_score}</span></div>
                            </div>
                            <div class="ticket-details">
                                <div class="payload-text" title="${escapeHtml(t.payload_text)}">${escapeHtml(t.payload_text)}</div>
                                <div class="rationale-text">${escapeHtml(t.rationale)}</div>
                            </div>
                            ${actionHtml}
                        </div>
                    `;
                }).join('');
                
            } catch (err) {
                console.error(err);
            }
        }
        
        async function resolveTicket(ticketId, status) {
            try {
                const response = await fetch(`/api/escalations/${ticketId}/resolve?api_key=${apiKey}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        status: status,
                        resolution_notes: `Resolved manually via SOC Dashboard as ${status}`
                    })
                });
                
                if (!response.ok) throw new Error('Failed to resolve ticket');
                await fetchTickets();
            } catch (err) {
                console.error(err);
                alert(`Error: ${err.message}`);
            }
        }
        
        function escapeHtml(str) {
            if (!str) return '';
            return str
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def get_dashboard_root(api_key: Optional[str] = Query(None)):
    return HTMLResponse(content=HTML_CONTENT)

@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard(api_key: Optional[str] = Query(None)):
    return HTMLResponse(content=HTML_CONTENT)

if __name__ == "__main__":
    uvicorn.run("service:app", host="0.0.0.0", port=8080, reload=True)
