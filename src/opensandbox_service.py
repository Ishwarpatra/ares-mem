import asyncio
import os
from datetime import timedelta
from typing import Optional, Dict, Any, List, Union
from dataclasses import dataclass

# Try to import OpenSandbox SDK components
try:
    from opensandbox import SandboxSync
    from opensandbox.config import ConnectionConfigSync
    from opensandbox.exceptions import SandboxException
    from opensandbox.models.filesystem import WriteEntry
except ImportError:
    # Placeholder for environment where SDK is not yet installed
    SandboxSync = None
    ConnectionConfigSync = None
    SandboxException = Exception
    WriteEntry = None

@dataclass
class ExecutionResult:
    stdout: str
    stderr: str
    exit_code: int
    execution_time_ms: int

class OpenSandboxService:
    """
    A reusable service to wrap the OpenSandbox API for secure code execution.
    """
    def __init__(self, domain: str = "api.opensandbox.io", api_key: Optional[str] = None):
        self.domain = domain
        self.api_key = api_key or os.getenv("OPENSANDBOX_API_KEY")
        self.config = ConnectionConfigSync(
            domain=self.domain,
            api_key=self.api_key
        ) if ConnectionConfigSync else None
        self.sandbox: Optional[Any] = None

    def initialize(self, image: str = "ubuntu:22.04", timeout_min: int = 30) -> str:
        """
        Initializes a new sandbox session.
        """
        try:
            if not SandboxSync:
                raise RuntimeError("OpenSandbox SDK is not installed.")
            
            self.sandbox = SandboxSync.create(
                image,
                connection_config=self.config,
                timeout=timedelta(minutes=timeout_min)
            )
            return self.sandbox.id
        except Exception as e:
            raise RuntimeError(f"Failed to initialize sandbox: {str(e)}")

    def connect(self, sandbox_id: str):
        """
        Connects to an existing sandbox session.
        """
        try:
            # Note: Assuming SandboxSync has a resume/connect method based on documentation patterns
            # If resume is not in Sync, we use the constructor pattern if supported
            self.sandbox = SandboxSync(
                sandbox_id=sandbox_id,
                connection_config=self.config
            )
        except Exception as e:
            raise RuntimeError(f"Failed to connect to sandbox {sandbox_id}: {str(e)}")

    def execute(self, code: str, language: str = "python") -> ExecutionResult:
        """
        Executes raw code in the sandbox and returns structured results.
        """
        if not self.sandbox:
            raise RuntimeError("Sandbox not initialized. Call initialize() or connect() first.")

        # Construct the command based on the language
        if language.lower() == "python":
            cmd = f"python3 -c {repr(code)}"
        elif language.lower() in ["bash", "sh", "shell"]:
            cmd = code
        else:
            # Generic execution for other languages if they are supported via their CLI
            cmd = f"{language} -c {repr(code)}"

        try:
            execution = self.sandbox.commands.run(cmd)
            
            stdout = "".join([log.text for log in execution.logs.stdout])
            stderr = "".join([log.text for log in execution.logs.stderr])
            
            return ExecutionResult(
                stdout=stdout,
                stderr=stderr,
                exit_code=execution.exit_code,
                execution_time_ms=execution.execution_time_in_millis
            )
        except SandboxException as e:
            return ExecutionResult(
                stdout="",
                stderr=f"Sandbox Error: {str(e)}",
                exit_code=-1,
                execution_time_ms=0
            )
        except Exception as e:
            return ExecutionResult(
                stdout="",
                stderr=f"Unexpected Error: {str(e)}",
                exit_code=-1,
                execution_time_ms=0
            )

    def upload_file(self, local_path: str, remote_path: str):
        """
        Uploads a local file to the sandbox.
        """
        if not self.sandbox:
            raise RuntimeError("Sandbox not initialized.")
        
        try:
            with open(local_path, 'r') as f:
                data = f.read()
            
            self.sandbox.files.write_files([
                WriteEntry(
                    path=remote_path,
                    data=data,
                    mode=644
                )
            ])
        except Exception as e:
            raise RuntimeError(f"Failed to upload file: {str(e)}")

    def download_file(self, remote_path: str, local_path: str):
        """
        Downloads a file from the sandbox to the host.
        """
        if not self.sandbox:
            raise RuntimeError("Sandbox not initialized.")
        
        try:
            content = self.sandbox.files.read_file(remote_path)
            with open(local_path, 'w') as f:
                f.write(content)
        except Exception as e:
            raise RuntimeError(f"Failed to download file: {str(e)}")

    def cleanup(self):
        """
        Cleanly destroys the sandbox session.
        """
        if self.sandbox:
            try:
                self.sandbox.kill()
                self.sandbox.close()
                self.sandbox = None
            except Exception as e:
                import logging
                logging.getLogger("AresMemSandbox").warning(f"Error during sandbox cleanup: {str(e)}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
