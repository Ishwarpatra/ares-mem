class ResponseAgent:
    """
    The Muscle: Executes defensive actions via infrastructure APIs.
    """
    def __init__(self):
        # In a real system, this would have API clients for Firewalls, EDRs, etc.
        self.action_history = []

    def execute(self, decision_data):
        """
        Simulates the execution of a defensive action.
        """
        action = decision_data.get("action", "NO_ACTION")
        decision = decision_data.get("decision", "UNKNOWN")
        
        execution_log = {
            "status": "executed",
            "action": action,
            "decision": decision,
            "message": f"Successfully performed {action} based on {decision} decision."
        }
        
        self.action_history.append(execution_log)
        return execution_log

    def get_history(self):
        return self.action_history
