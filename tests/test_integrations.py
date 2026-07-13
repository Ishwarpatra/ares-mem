import os
import sys
from opensandbox_service import OpenSandboxService
from google_adk_service import GoogleADKService

def test_opensandbox():
    print("\n--- Testing OpenSandbox Integration ---")
    # Note: This requires OPENSANDBOX_API_KEY to be set
    api_key = os.getenv("OPENSANDBOX_API_KEY")
    if not api_key:
        print("[Skip] OPENSANDBOX_API_KEY not set. Skipping real API test.")
        return

    try:
        with OpenSandboxService(api_key=api_key) as sbx_service:
            print("[1] Initializing Sandbox...")
            sbx_id = sbx_service.initialize(image="ubuntu:22.04")
            print(f"Sandbox ID: {sbx_id}")

            print("[2] Executing Python Code...")
            code = "print('Hello from OpenSandbox!')"
            result = sbx_service.execute(code, language="python")
            print(f"Stdout: {result.stdout.strip()}")
            print(f"Exit Code: {result.exit_code}")

            print("[3] Uploading/Downloading File...")
            test_file = "test_sbx.txt"
            with open(test_file, "w") as f: f.write("Sandbox File Content")
            sbx_service.upload_file(test_file, "/tmp/test.txt")
            sbx_service.download_file("/tmp/test.txt", "downloaded_test.txt")
            
            with open("downloaded_test.txt", "r") as f:
                content = f.read()
                print(f"Downloaded Content: {content}")
            
            # Cleanup local test files
            os.remove(test_file)
            os.remove("downloaded_test.txt")
            
            print("[Success] OpenSandbox integration verified.")
    except Exception as e:
        print(f"[Error] OpenSandbox test failed: {str(e)}")

def test_google_adk():
    print("\n--- Testing Google ADK Integration ---")
    # Note: This requires GOOGLE_API_KEY to be set
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        print("[Skip] GOOGLE_API_KEY not set. Skipping real API test.")
        return

    try:
        google_service = GoogleADKService(api_key=api_key)
        print("[1] Creating Google ADK Agent...")
        google_service.create_agent(
            name="SecurityAssistant",
            instructions="You are a security assistant for Project ARES-Mem. Help analyze logs."
        )

        print("[2] Running Agent Prompt...")
        response = google_service.run("Hello, who are you?")
        print(f"Agent Response: {response}")
        
        print("[Success] Google ADK integration verified.")
    except Exception as e:
        print(f"[Error] Google ADK test failed: {str(e)}")

def check_environment():
    print("\n--- Environment Check ---")
    print(f"Python Version: {sys.version.split()[0]}")
    
    dependencies = ["opensandbox", "google_adk", "langgraph", "chromadb"]
    for dep in dependencies:
        try:
            __import__(dep)
            print(f"[OK] {dep} is installed.")
        except ImportError:
            print(f"[Missing] {dep} is NOT installed.")

if __name__ == "__main__":
    check_environment()
    test_opensandbox()
    test_google_adk()
