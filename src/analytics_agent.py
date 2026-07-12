import matplotlib.pyplot as plt
import pandas as pd
import os
from typing import List, Dict, Any
from datetime import datetime

class AnalyticsAgent:
    """
    Agent responsible for generating statistical graphs and system analytics.
    """
    def __init__(self, output_dir: str = "analytics"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_risk_trend(self, execution_data: List[Dict[str, Any]]):
        """
        Generates a line graph showing risk scores over time.
        """
        if not execution_data:
            return None

        df = pd.DataFrame(execution_data)
        df['timestamp'] = pd.to_datetime(df.get('timestamp', datetime.now()))
        
        plt.figure(figsize=(10, 6))
        plt.plot(df['timestamp'], df['risk_score'], marker='o', linestyle='-', color='r')
        plt.title('System Risk Score Trend')
        plt.xlabel('Time')
        plt.ylabel('Risk Score (0-100)')
        plt.grid(True)
        
        file_path = os.path.join(self.output_dir, 'risk_trend.png')
        plt.savefig(file_path)
        plt.close()
        return file_path

    def generate_agent_activity(self, activity_counts: Dict[str, int]):
        """
        Generates a bar chart showing activity counts per agent.
        """
        if not activity_counts:
            return None

        agents = list(activity_counts.keys())
        counts = list(activity_counts.values())

        plt.figure(figsize=(10, 6))
        plt.bar(agents, counts, color='skyblue')
        plt.title('Agent Activity Distribution')
        plt.xlabel('Agent Name')
        plt.ylabel('Execution Count')
        
        file_path = os.path.join(self.output_dir, 'agent_activity.png')
        plt.savefig(file_path)
        plt.close()
        return file_path

    def generate_memory_stats(self, memory_data: List[Dict[str, Any]]):
        """
        Generates a pie chart of memory validation trust tiers.
        """
        if not memory_data:
            return None

        df = pd.DataFrame(memory_data)
        trust_counts = df['trust_tier'].value_counts()

        plt.figure(figsize=(8, 8))
        plt.pie(trust_counts, labels=trust_counts.index, autopct='%1.1f%%', startangle=140, colors=['#ff9999','#66b3ff','#99ff99'])
        plt.title('Memory Trust Tier Distribution')
        
        file_path = os.path.join(self.output_dir, 'memory_stats.png')
        plt.savefig(file_path)
        plt.close()
        return file_path
