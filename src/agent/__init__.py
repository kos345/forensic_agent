"""
Forseti Agent - AI-агент для криминалистического анализа образов дисков.

Модули:
- state: Определение состояния агента (LangGraph State)
- simple_agent: Простой агент для сбора и анализа артефактов
- forensic_deep_agent: Deep Agent для интеллектуального анализа
- prompts: Промпты для LLM-анализа
"""

from .state import (
    BaseAgentState,
    AgentState,
    TriageData,
    ForensicAgentState,
    InvestigatedPath,
    SuspiciousFinding,
    sync_store_to_state,
)
from .simple_agent import ForensicAgent, run_agent
# NOTE: forensic_deep_agent НЕ импортируется здесь, чтобы разорвать циклическую зависимость:
#   src.tools -> investigation_tools -> src.agent.state -> src.agent.__init__ -> forensic_deep_agent -> src.tools
# Импортируйте напрямую: from src.agent.forensic_deep_agent import ForensicDeepAgent, run_deep_agent

__all__ = [
    # State
    'BaseAgentState',
    'AgentState',
    'TriageData',
    'ForensicAgentState',
    'InvestigatedPath',
    'SuspiciousFinding',
    'sync_store_to_state',
    # Simple Agent
    'ForensicAgent',
    'run_agent',
]
