"""
response_agents.py — Re-exports ResponseAgent for backwards compatibility.

The ResponseAgent primary implementation lives in decision_agents.py
(co-located with DecisionAgent for the sequential pipeline).
This module provides a clean import alias.
"""
from decision_agents import ResponseAgent  # noqa: F401

__all__ = ["ResponseAgent"]
