import os
from typing import Optional, List, Dict, Any

# Try to import Google ADK components
try:
    import google_adk as adk
    from google_adk.models import ModelConfig
    from google_adk.agents import Agent
except ImportError:
    # Placeholder for environment where SDK is not yet installed
    adk = None
    ModelConfig = None
    Agent = None

class GoogleADKService:
    """
    A service wrapper for the Google Agent Development Kit (ADK).
    """
    def __init__(self, model_name: str = "gemini-1.5-pro", api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        self.model_name = model_name
        self.agent: Optional[Any] = None
        
        if adk:
            self.model_config = ModelConfig(
                model=self.model_name,
                api_key=self.api_key
            )
        else:
            self.model_config = None

    def create_agent(self, name: str, instructions: str, tools: Optional[List[Any]] = None):
        """
        Creates a new Google ADK agent.
        """
        if not adk:
            raise RuntimeError("Google ADK SDK is not installed.")
        
        try:
            self.agent = Agent(
                name=name,
                instructions=instructions,
                model_config=self.model_config,
                tools=tools or []
            )
            return self.agent
        except Exception as e:
            raise RuntimeError(f"Failed to create Google ADK agent: {str(e)}")

    def run(self, prompt: str) -> str:
        """
        Runs the agent with a given prompt.
        """
        if not self.agent:
            raise RuntimeError("Agent not created. Call create_agent() first.")
        
        try:
            response = self.agent.run(prompt)
            return response.text
        except Exception as e:
            return f"Error running Google ADK agent: {str(e)}"

    def add_tool(self, tool_func):
        """
        Adds a tool to the agent.
        """
        if self.agent:
            self.agent.add_tool(tool_func)
        else:
            raise RuntimeError("Agent not created.")
