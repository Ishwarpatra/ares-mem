import logging
import asyncio
from slack_sdk.web.async_client import AsyncWebClient
import os
from typing import Dict, Any

logger = logging.getLogger("Notifications")

class NotificationService:
    def __init__(self):
        self.slack_token = os.environ.get("SLACK_BOT_TOKEN")
        self.slack_channel = os.environ.get("SLACK_ALERT_CHANNEL", "#security-alerts")
        if self.slack_token:
            self.slack_client = AsyncWebClient(token=self.slack_token)
        else:
            self.slack_client = None

    async def _send_slack(self, message: str, blocks: list = None):
        if not self.slack_client:
            logger.warning("Slack token not configured. Skipping Slack notification.")
            return False
            
        try:
            await self.slack_client.chat_postMessage(
                channel=self.slack_channel,
                text=message,
                blocks=blocks
            )
            return True
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False

    async def _send_email(self, subject: str, body: str):
        # Placeholder for email logic
        logger.info(f"[Email Notification] Subject: {subject} | Body: {body}")
        return True

    def notify_alert_sync(self, alert_data: Dict[str, Any]):
        """Synchronous wrapper to fire and forget notifications"""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.notify_alert(alert_data))
        except RuntimeError:
            # If no running loop, just run it
            asyncio.run(self.notify_alert(alert_data))

    async def notify_alert(self, alert_data: Dict[str, Any]):
        event_id = alert_data.get("event_id", "UNKNOWN")
        risk_score = alert_data.get("risk_score", 0)
        action = alert_data.get("action", "ALERT")
        details = alert_data.get("details", {})
        
        msg = f"🚨 *ARES-Mem Security Alert* 🚨\n*Event ID*: {event_id}\n*Risk Score*: {risk_score}\n*Action*: {action}\n*Details*: {details}"
        
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": msg
                }
            }
        ]
        
        logger.info(f"Dispatching notifications for alert {event_id}")
        await asyncio.gather(
            self._send_slack(msg, blocks),
            self._send_email(f"ARES-Mem Security Alert: {event_id}", msg)
        )

# Global singleton
_notification_service = NotificationService()

def get_notification_service():
    return _notification_service
