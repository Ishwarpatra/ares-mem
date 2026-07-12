import json
import os

class LogIngestionAgent:
    """
    The Eyes: Continuously parses external raw data (server logs, network traffic).
    """
    def __init__(self, data_dir="data"):
        self.data_dir = data_dir
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

    def ingest_log(self, log_content):
        """
        Simulates ingesting a raw log and converting it to a structured format.
        """
        # In a real scenario, this would involve complex parsing.
        # For this prototype, we assume the log is a string or simple JSON.
        try:
            if isinstance(log_content, str):
                structured_log = {"raw": log_content, "source": "external_stream"}
            else:
                structured_log = log_content
            
            return structured_log
        except Exception as e:
            return {"error": f"Failed to ingest log: {str(e)}"}

    def read_from_file(self, filename):
        path = os.path.join(self.data_dir, filename)
        if os.path.exists(path):
            with open(path, 'r') as f:
                return self.ingest_log(f.read())
        return {"error": "File not found"}
