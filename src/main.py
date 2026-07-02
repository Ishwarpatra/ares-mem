"""
main.py — ARES-Mem Production Entry Point.

Runs the full LangGraph orchestration pipeline against 6 representative
synthetic logs spanning all threat categories (including one prompt injection
payload to exercise the quarantine gate). Prints a structured execution
report with per-log latency metrics (satisfying the SOC latency documentation
requirement from the methodology constraints).
"""
import os
import sys
import time
from typing import List, Dict, Any

from dotenv import load_dotenv

# Reconfigure stdout on Windows to prevent UnicodeEncodeError in legacy consoles
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(errors="replace")
    except AttributeError:
        pass

load_dotenv()

# Ensure src/ is on the path when run directly
sys.path.insert(0, os.path.dirname(__file__))

from orchestrator import run_ares
from synthetic_logs import get_pipeline_test_logs
from memory_store import MemoryStore

load_dotenv()


def print_banner():
    banner = """
====================================================================
          PROJECT ARES-Mem - Autonomous Cybersecurity Defense      
          Multi-Agent Orchestration with Memory Sandboxing          
====================================================================
"""
    print(banner)


def run_pipeline(logs: List[str]) -> List[Dict[str, Any]]:
    """Runs the ARES-Mem pipeline on a list of raw logs."""
    results = []
    for i, log in enumerate(logs, 1):
        print(f"\n{'-'*60}")
        print(f"[Log {i}/{len(logs)}] Processing...")
        print(f"  Input: {log[:100]}...")

        start_ms = time.monotonic() * 1000
        result = run_ares(log)
        elapsed_ms = time.monotonic() * 1000 - start_ms

        result["_pipeline_latency_ms"] = round(elapsed_ms, 2)
        result["_log_index"] = i
        results.append(result)

        print(f"  [OK] Complete | Latency: {elapsed_ms:.1f}ms | "
              f"Decision: {result.get('decision', {}).get('decision', 'N/A')} | "
              f"Risk: {result.get('threat_score', 0)} | "
              f"Status: {result.get('security_status', 'valid').upper()}")

    return results


def print_summary_report(results: List[Dict[str, Any]]):
    """Prints the final execution report."""
    print(f"\n{'='*80}")
    print("FINAL EXECUTION REPORT")
    print(f"{'='*80}")
    print(f"{'#':<4} {'Event Type':<16} {'Risk':>6} {'Decision':<12} {'Priv':<6} {'Status':<12} {'Latency':>12}")
    print(f"{'-'*80}")

    total_latency = 0
    for r in results:
        idx = r.get("_log_index", "?")
        threat = r.get("threat_analysis", {}).get("threat_type", "UNKNOWN")[:15]
        score = r.get("threat_score", 0)
        decision = r.get("decision", {}).get("decision", "N/A")[:11]
        priv = r.get("privilege_level", "?")
        status = r.get("security_status", "valid")[:11]
        lat = r.get("_pipeline_latency_ms", 0)
        total_latency += lat
        print(f"{idx:<4} {threat:<16} {score:>6} {decision:<12} {priv:<6} {status:<12} {lat:>10.1f}ms")

    print(f"{'-'*80}")
    avg_lat = total_latency / len(results) if results else 0
    print(f"{'Total logs:':<30} {len(results)}")
    print(f"{'Total latency:':<30} {total_latency:.1f}ms")
    print(f"{'Average latency per log:':<30} {avg_lat:.1f}ms")

    # Memory store stats
    try:
        store = MemoryStore()
        stats = store.stats()
        print(f"\n{'-'*60}")
        print("MEMORY STORE STATISTICS")
        print(f"{'-'*60}")
        print(f"  ares_memory (verified):   {stats['memory_count']} entries")
        print(f"  ares_quarantine (flagged): {stats['quarantine_count']} entries")

        quarantine_info = store.get_quarantine_summary()
        if quarantine_info.get("count", 0) > 0:
            print(f"\n  Quarantine samples:")
            for sample in quarantine_info.get("samples", []):
                print(f"    * [{sample['privilege_label'].upper()}] {sample['text_preview']}")
    except Exception as e:
        print(f"  [Warning] Could not fetch memory stats: {e}")

    print(f"\n{'='*60}")
    print("ARES-Mem pipeline complete.")
    print(f"{'='*60}\n")


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
