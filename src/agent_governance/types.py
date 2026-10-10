"""Core types: lifecycle, risk tiers, decision outcomes, and the agent charter."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable


def now() -> datetime:
    return datetime.now(timezone.utc)


class Lifecycle(str, Enum):
    DESIGN = "design"
    DEVELOPMENT = "development"
    TESTING = "pre_deployment_testing"
    DEPLOYED = "deployed"
    SUSPENDED = "suspended"
    DECOMMISSIONED = "decommissioned"


class Tier(str, Enum):
    """Risk tier. Higher tier => deeper review and tighter oversight."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Decision(str, Enum):
    ALLOW = "allow"
    ESCALATE = "escalate"   # human-in-the-loop approval required
    DENY = "deny"


@dataclass
class Owners:
    """Named humans, assigned before deployment (accountability must not diffuse)."""
    accountable_executive: str   # deploying organisation's primary owner
    monitoring_owner: str        # watches behaviour
    approval_owner: str          # approves high-impact actions
    intervention_owner: str      # can suspend execution
    incident_owner: str          # investigates + reports material impact


@dataclass
class ToolPolicy:
    """Least-privilege rule for one tool."""
    name: str
    allowed_actions: set[str]
    # Numeric parameter (e.g. 'amount') above which a human must approve.
    approval_param: str | None = None
    approval_threshold: float | None = None
    # Numeric parameter hard ceiling - above this is denied outright.
    hard_limit: float | None = None
    # Extra validators: return error string to deny, None to pass.
    validators: list[Callable[[dict[str, Any]], str | None]] = field(default_factory=list)
    max_calls_per_minute: int = 30


@dataclass
class AgentCharter:
    """Steps 1 + 2: purpose, authority, identity. The agent's 'delegation of authority'."""
    agent_id: str
    purpose: str
    tier: Tier
    owners: Owners
    credential_id: str                       # dedicated service identity, never shared
    tools: dict[str, ToolPolicy]
    prohibited_actions: set[str]             # explicit misuse boundaries
    allowed_data_classes: set[str]           # e.g. {"procurement", "vendor_master"}
    review_interval_days: int = 90           # forced re-attestation of authority
    authority_expires: datetime | None = None
    allowed_peer_agents: set[str] = field(default_factory=set)  # A2A allow-list

    def __post_init__(self):
        if self.authority_expires is None:
            self.authority_expires = now() + timedelta(days=self.review_interval_days)
        overlap = self.prohibited_actions & {a for t in self.tools.values() for a in t.allowed_actions}
        if overlap:
            raise ValueError(f"Charter contradicts itself; actions both allowed and prohibited: {overlap}")


@dataclass
class ImpactAssessment:
    """Step 3: documented before activation. Depth should scale with tier."""
    financial: str
    operational: str
    legal: str
    reputational: str
    completed_by: str
    signoffs: list[str] = field(default_factory=list)   # cross-functional for HIGH tier
    simulation_passed: bool = False                     # escalation + limits tested

    def satisfies(self, tier: Tier) -> tuple[bool, str]:
        if not all([self.financial, self.operational, self.legal, self.reputational]):
            return False, "impact assessment incomplete"
        if not self.simulation_passed:
            return False, "pre-deployment simulation has not passed"
        needed = {Tier.LOW: 0, Tier.MEDIUM: 1, Tier.HIGH: 3}[tier]
        if len(set(self.signoffs)) < needed:
            return False, f"{tier.value} tier needs {needed} distinct sign-offs, has {len(set(self.signoffs))}"
        return True, "ok"


@dataclass
class ActionRequest:
    agent_id: str
    tool: str
    action: str
    params: dict[str, Any]
    data_classes: set[str] = field(default_factory=set)
    on_behalf_of: str | None = None   # end user / initiating principal, for attribution
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    peer_agent: str | None = None     # set when request originates from another agent


@dataclass
class GovernanceResult:
    decision: Decision
    reason: str
    approval_id: str | None = None