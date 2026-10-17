"""
agent_governance - A reference framework for agentic AI governance.

Based on the lifecycle and 8-step model in Palo Alto Networks' "A Complete Guide to
Agentic AI Governance". Maps to the steps like this:

  1. Scope & authority ........ AgentCharter (incl. prohibited actions)
  2. Identity & access ........ AgentCharter.credential_id + ToolPolicy (least privilege)
  3. Impact assessment ........ ImpactAssessment + lifecycle gate (cannot deploy without it)
  4. Runtime controls ......... GovernanceGateway.authorize() and govern()
  5. Logging & traceability ... AuditLog (append-only, hash-chained, disk-verified)
  6. Human oversight .......... ApprovalQueue (digest-bound, expiring, re-checked)
  7. Incident / shutdown ...... GovernanceGateway.suspend() / decommission()
  8. Drift monitoring ......... DriftMonitor; tripwire calls suspend()

Design rule: the agent never calls tools directly. govern() invokes a tool only
after ALLOW, and the gateway enforces policy independently of the agent's
reasoning.

No third-party dependencies. Python 3.10+.
"""
from __future__ import annotations

from .approvals import ApprovalQueue, PendingApproval, request_digest
from .audit import AuditIntegrityError, AuditLog
from .drift import DriftMonitor
from .gateway import (GovernanceDenied, GovernanceError, GovernanceEscalated,
                      GovernanceGateway, GovernedTool)
from .tools import ToolAdmissionError, ToolManifest, screen_tool
from .types import (ActionRequest, AgentCharter, Decision, GovernanceResult,
                    ImpactAssessment, Lifecycle, Owners, Tier, ToolPolicy, now)

__all__ = [
    "ActionRequest",
    "AgentCharter",
    "ApprovalQueue",
    "AuditIntegrityError",
    "AuditLog",
    "Decision",
    "DriftMonitor",
    "GovernedTool",
    "GovernanceDenied",
    "GovernanceError",
    "GovernanceEscalated",
    "GovernanceGateway",
    "GovernanceResult",
    "ImpactAssessment",
    "Lifecycle",
    "Owners",
    "PendingApproval",
    "Tier",
    "ToolAdmissionError",
    "ToolManifest",
    "ToolPolicy",
    "now",
    "request_digest",
    "screen_tool",
]

__version__ = "0.1.0"