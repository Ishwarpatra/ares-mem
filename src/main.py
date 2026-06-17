"""
main.py — ARES-Mem Production Entry Point.

Runs the full LangGraph orchestration pipeline against 5 representative
synthetic logs spanning all threat categories. Prints a structured
execution report with per-log latency metrics (satisfying the SOC
latency documentation requirement from the methodology constraints).
"""
import os
import sys
import time
from typing import List, Dict, Any

from dotenv import load_dotenv

# Ensure src/ is on the path when run directly
sys.path.insert(0, os.path.dirname(__file__))

from orchestrator import run_ares
from synthetic_logs import get_pipeline_test_logs
from memory_store import MemoryStore

load_dotenv()


def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║         PROJECT ARES-Mem — Autonomous Cybersecurity Defense      ║
║         Multi-Agent Orchestration with Memory Sandboxing         ║
╚══════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def run_pipeline(logs: List[str]) -> List[Dict[str, Any]]:
    """Runs the ARES-Mem pipeline on a list of raw logs."""
    results = []
    for i, log in enumerate(logs, 1):
        print(f"\n{'─'*60}")
        print(f"[Log {i}/{len(logs)}] Processing...")
        print(f"  Input: {log[:100]}...")

        start_ms = time.monotonic() * 1000
        result = run_ares(log)
        elapsed_ms = time.monotonic() * 1000 - start_ms

        result["_pipeline_latency_ms"] = round(elapsed_ms, 2)
        result["_log_index"] = i
        results.append(result)

        print(f"  ✔ Complete | Latency: {elapsed_ms:.1f}ms | "
              f"Decision: {result.get('decision', {}).get('decision', 'N/A')} | "
              f"Risk: {result.get('threat_score', 0)} | "
              f"Quarantined: {result.get('validation_flag', False)}")

    return results


def print_summary_report(results: List[Dict[str, Any]]):
    """Prints the final execution report."""
    print(f"\n{'═'*60}")
    print("FINAL EXECUTION REPORT")
    print(f"{'═'*60}")
    print(f"{'#':<4} {'Event Type':<20} {'Risk':>6} {'Decision':<15} {'Priv':<6} {'Latency':>10}")
    print(f"{'─'*60}")

    total_latency = 0
    for r in results:
        idx = r.get("_log_index", "?")
        threat = r.get("threat_analysis", {}).get("threat_type", "UNKNOWN")[:18]
        score = r.get("threat_score", 0)
        decision = r.get("decision", {}).get("decision", "N/A")[:13]
        priv = r.get("privilege_level", "?")
        lat = r.get("_pipeline_latency_ms", 0)
        total_latency += lat
        print(f"{idx:<4} {threat:<20} {score:>6} {decision:<15} {priv:<6} {lat:>8.1f}ms")

    print(f"{'─'*60}")
    avg_lat = total_latency / len(results) if results else 0
    print(f"{'Total logs:':<30} {len(results)}")
    print(f"{'Total latency:':<30} {total_latency:.1f}ms")
    print(f"{'Average latency per log:':<30} {avg_lat:.1f}ms")

    # Memory store stats
    try:
        store = MemoryStore()
        stats = store.stats()
        print(f"\n{'─'*60}")
        print("MEMORY STORE STATISTICS")
        print(f"{'─'*60}")
        print(f"  ares_memory (verified):   {stats['memory_count']} entries")
        print(f"  ares_quarantine (flagged): {stats['quarantine_count']} entries")

        quarantine_info = store.get_quarantine_summary()
        if quarantine_info.get("count", 0) > 0:
            print(f"\n  Quarantine samples:")
            for sample in quarantine_info.get("samples", []):
                print(f"    • [{sample['privilege_label'].upper()}] {sample['text_preview']}")
    except Exception as e:
        print(f"  [Warning] Could not fetch memory stats: {e}")

    print(f"\n{'═'*60}")
    print("ARES-Mem pipeline complete.")
    print(f"{'═'*60}\n")


def main():
    print_banner()
    print("Initializing ARES-Mem pipeline...")
    print(f"Environment: {os.getenv('ARES_ENV', 'local')}")
    print(f"ChromaDB mode: {'HTTP (' + os.getenv('CHROMA_HOST','') + ')' if os.getenv('CHROMA_HOST') else 'local persistent'}")

    logs = get_pipeline_test_logs()
    print(f"\nProcessing {len(logs)} synthetic security logs...\n")

    results = run_pipeline(logs)
    print_summary_report(results)


if __name__ == "__main__":
    main()
