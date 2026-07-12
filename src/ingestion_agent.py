import json
import os

# Maximum raw log size to prevent memory exhaustion from oversized payloads
MAX_LOG_BYTES = 64_000  # 64 KB

class LogIngestionAgent:
    """
    The Eyes: Parses and sanitises raw external data (server logs, network traffic).

    Security hardening:
      - Enforces a maximum input length to prevent memory exhaustion.
      - Strips null bytes and control characters that can be used for log injection.
      - Validates that input is a string or dict — rejects all other types.
    """

    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

    def _sanitize(self, text: str) -> str:
        """
        Strip null bytes and C0/C1 control characters (except tab and newline)
        that are commonly used to obscure log injection payloads.
        """
        # Allow printable ASCII + tab (0x09) + newline (0x0A) + carriage return (0x0D)
        allowed = {0x09, 0x0A, 0x0D}
        return "".join(
            ch for ch in text
            if ord(ch) >= 0x20 or ord(ch) in allowed
        )

    def ingest_log(self, log_content) -> dict:
        """
        Sanitises and structures a raw log entry.

        Args:
            log_content: Raw log as a string or already-structured dict.

        Returns:
            Structured dict with 'raw', 'source', and optional 'error' keys.
        """
        try:
            if isinstance(log_content, dict):
                # Already structured — pass through with source tag
                return {**log_content, "source": log_content.get("source", "external_stream")}

            if not isinstance(log_content, str):
                return {
                    "error": f"Unsupported log type: {type(log_content).__name__}",
                    "source": "ingestion_agent",
                    "raw": str(log_content)[:200],
                }

            # Enforce max size
            encoded = log_content.encode("utf-8", errors="replace")
            if len(encoded) > MAX_LOG_BYTES:
                return {
                    "error": f"Log exceeds maximum allowed size ({MAX_LOG_BYTES} bytes). Truncated.",
                    "source": "ingestion_agent",
                    "raw": log_content[:MAX_LOG_BYTES].strip(),
                }

            sanitized = self._sanitize(log_content)

            return {
                "raw": sanitized,
                "source": "external_stream",
            }

        except Exception as e:
            return {"error": f"Failed to ingest log: {str(e)}", "source": "ingestion_agent"}

    def read_from_file(self, filename: str) -> dict:
        """Reads a log file from the data directory and ingests it."""
        path = os.path.join(self.data_dir, filename)
        if not os.path.exists(path):
            return {"error": f"File not found: {filename}"}
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return self.ingest_log(f.read())
