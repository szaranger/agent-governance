"""
agent_governance - A reference framework for agentic AI governance.

Based on the lifecycle and 8-step model in Palo Alto Networks' "A Complete Guide to
Agentic AI Governance". Maps to the steps like this:

  1. Scope & authority ........ AgentCharter (incl. prohibited actions)
  2. Identity & access ........ AgentCharter.credential_id + ToolPolicy (least privilege)
  3. Impact assessment ........ ImpactAssessment + lifecycle gate (cannot deploy without it)
  4. Runtime controls ......... GovernanceGateway.authorize()  (separate from agent logic)
  5. Logging & traceability ... AuditLog (append-only, hash-chained)
  6. Human oversight .......... ApprovalQueue + escalation thresholds
  7. Incident / shutdown ...... GovernanceGateway.suspend() / decommission()
  8. Drift monitoring ......... DriftMonitor + charter review dates

Design rule: the agent never calls tools directly. Every action goes through the
gateway, which enforces policy independently of the agent's reasoning.

No third-party dependencies. Python 3.10+.
"""
from __future__ import annotations

from .approvals import ApprovalQueue, PendingApproval
from .audit import AuditLog
from .drift import DriftMonitor
from .gateway import GovernanceError, GovernanceGateway
from .types import (ActionRequest, AgentCharter, Decision, GovernanceResult,
                    ImpactAssessment, Lifecycle, Owners, Tier, ToolPolicy, now)

__all__ = [
    "ActionRequest",
    "AgentCharter",
    "ApprovalQueue",
    "AuditLog",
    "Decision",
    "DriftMonitor",
    "GovernanceError",
    "GovernanceGateway",
    "GovernanceResult",
    "ImpactAssessment",
    "Lifecycle",
    "Owners",
    "PendingApproval",
    "Tier",
    "ToolPolicy",
    "now",
]

__version__ = "0.1.0"