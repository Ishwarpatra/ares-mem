import pytest
from unittest.mock import AsyncMock, patch
from src.notifications import NotificationService

@pytest.fixture
def notify_service():
    service = NotificationService()
    service.slack_client = AsyncMock()
    return service

@pytest.mark.asyncio
async def test_slack_notification(notify_service):
    # Test slack sends successfully
    notify_service.slack_client.chat_postMessage.return_value = {"ok": True}
    
    result = await notify_service._send_slack("Test Alert", [])
    assert result is True
    notify_service.slack_client.chat_postMessage.assert_called_once()

@pytest.mark.asyncio
async def test_email_notification(notify_service):
    # Test email sends successfully
    result = await notify_service._send_email("Test Alert", "Body")
    assert result is True

@pytest.mark.asyncio
async def test_notify_alert(notify_service):
    notify_service.slack_client.chat_postMessage.return_value = {"ok": True}
    
    alert_data = {
        "event_id": "EVT-123",
        "risk_score": 95,
        "action": "ALERT",
        "details": "Suspicious login"
    }
    
    await notify_service.notify_alert(alert_data)
    notify_service.slack_client.chat_postMessage.assert_called_once()
    args, kwargs = notify_service.slack_client.chat_postMessage.call_args
    assert "EVT-123" in kwargs["text"]
    assert "95" in kwargs["text"]
