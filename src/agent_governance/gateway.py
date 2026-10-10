"""Steps 4 + 7: runtime enforcement, kill switch, and lifecycle."""
from __future__ import annotations

import time
from collections import deque
from dataclasses import asdict
from datetime import timedelta

from .approvals import ApprovalQueue
from .audit import AuditLog
from .drift import DriftMonitor
from .types import (ActionRequest, AgentCharter, Decision, GovernanceResult,
                    ImpactAssessment, Lifecycle, now)


class GovernanceError(Exception):
    pass


class GovernanceGateway:
    """
    The single choke point for agent actions. Enforcement lives here, NOT in the
    agent's prompt or reasoning layer, so it holds even if the agent is manipulated
    (prompt injection, poisoned MCP context, a compromised peer agent).
    """

    def __init__(self, charter: AgentCharter, audit: AuditLog | None = None):
        self.charter = charter
        self.audit = audit or AuditLog()
        self.approvals = ApprovalQueue(self.audit)
        self.drift = DriftMonitor(baseline_tools=set(charter.tools))
        self.state = Lifecycle.DESIGN
        self.assessment: ImpactAssessment | None = None
        self.credential_active = False
        self._call_times: dict[str, deque[float]] = {}
        self.audit.record("charter_registered", agent=charter.agent_id, tier=charter.tier.value,
                          purpose=charter.purpose, owners=asdict(charter.owners),
                          prohibited=sorted(charter.prohibited_actions))

    # ---- lifecycle -------------------------------------------------------- #
    def advance(self, to: Lifecycle, actor: str) -> None:
        order = [Lifecycle.DESIGN, Lifecycle.DEVELOPMENT, Lifecycle.TESTING, Lifecycle.DEPLOYED]
        if to == Lifecycle.DEPLOYED:
            if self.state != Lifecycle.TESTING:
                raise GovernanceError("must pass through pre-deployment testing before deployment")
            if not self.assessment:
                raise GovernanceError("no impact assessment on file")
            ok, why = self.assessment.satisfies(self.charter.tier)
            if not ok:
                raise GovernanceError(f"deployment blocked: {why}")
            self.credential_active = True
        elif to in order and (self.state not in order or order.index(to) != order.index(self.state) + 1):
            raise GovernanceError(f"invalid transition {self.state.value} -> {to.value}")
        self.audit.record("lifecycle", agent=self.charter.agent_id, frm=self.state.value, to=to.value, actor=actor)
        self.state = to

    def attach_assessment(self, a: ImpactAssessment) -> None:
        self.assessment = a
        self.audit.record("impact_assessment_filed", agent=self.charter.agent_id, by=a.completed_by,
                          signoffs=a.signoffs, simulation_passed=a.simulation_passed)

    # ---- step 7: shutdown ------------------------------------------------- #
    def suspend(self, by: str, reason: str) -> None:
        if by != self.charter.owners.intervention_owner:
            raise PermissionError(f"{by} is not the intervention owner")
        self.state = Lifecycle.SUSPENDED
        self.audit.record("suspended", agent=self.charter.agent_id, by=by, reason=reason)

    def resume(self, by: str, reason: str) -> None:
        if by != self.charter.owners.accountable_executive:
            raise PermissionError("only the accountable executive can resume a suspended agent")
        self.state = Lifecycle.DEPLOYED
        self.audit.record("resumed", agent=self.charter.agent_id, by=by, reason=reason)

    def decommission(self, by: str) -> None:
        """Authority ends as deliberately as it began: revoke access, keep records."""
        self.credential_active = False
        self.state = Lifecycle.DECOMMISSIONED
        self.audit.record("decommissioned", agent=self.charter.agent_id, by=by,
                          credential_revoked=self.charter.credential_id, tools_disabled=sorted(self.charter.tools),
                          records_retained=True)

    def attest(self, by: str) -> None:
        """Periodic re-attestation: authority lapses unless an owner renews it (anti-drift)."""
        if by != self.charter.owners.accountable_executive:
            raise PermissionError("only the accountable executive can re-attest authority")
        self.charter.authority_expires = now() + timedelta(days=self.charter.review_interval_days)
        self.audit.record("authority_reattested", agent=self.charter.agent_id, by=by,
                          expires=self.charter.authority_expires)

    # ---- step 4: runtime enforcement ------------------------------------- #
    def authorize(self, req: ActionRequest) -> GovernanceResult:
        result = self._evaluate(req)
        self.drift.observe(req.tool, result.decision)
        self.audit.record("action_decision", agent=req.agent_id, session=req.session_id,
                          on_behalf_of=req.on_behalf_of, tool=req.tool, action=req.action,
                          params=req.params, decision=result.decision.value, reason=result.reason,
                          approval_id=result.approval_id, peer=req.peer_agent)
        return result

    def _deny(self, why: str) -> GovernanceResult:
        return GovernanceResult(Decision.DENY, why)

    def _evaluate(self, req: ActionRequest) -> GovernanceResult:
        c = self.charter
        if req.agent_id != c.agent_id:
            return self._deny("identity mismatch")
        if self.state != Lifecycle.DEPLOYED or not self.credential_active:
            return self._deny(f"agent not operational (state={self.state.value})")
        if now() > c.authority_expires:
            return self._deny("delegated authority expired; re-attestation required")

        # Agent-to-agent trust: peers must be explicitly allowed
        if req.peer_agent and req.peer_agent not in c.allowed_peer_agents:
            return self._deny(f"peer agent '{req.peer_agent}' not trusted")

        # Explicit prohibitions win over everything
        if req.action in c.prohibited_actions:
            return self._deny(f"action '{req.action}' is explicitly prohibited")

        policy = c.tools.get(req.tool)
        if policy is None:
            return self._deny(f"tool '{req.tool}' is outside approved scope")
        if req.action not in policy.allowed_actions:
            return self._deny(f"action '{req.action}' not permitted on '{req.tool}'")

        # Data boundary
        out_of_scope = req.data_classes - c.allowed_data_classes
        if out_of_scope:
            return self._deny(f"data classes out of scope: {sorted(out_of_scope)}")

        # Rate limit (blast-radius control for runaway loops)
        window = self._call_times.setdefault(req.tool, deque())
        t = time.monotonic()
        while window and t - window[0] > 60:
            window.popleft()
        if len(window) >= policy.max_calls_per_minute:
            return self._deny(f"rate limit exceeded on '{req.tool}'")
        window.append(t)

        # Parameter validation (input checking against policy)
        for v in policy.validators:
            err = v(req.params)
            if err:
                return self._deny(f"validation failed: {err}")

        # Thresholds: hard limit -> deny; approval threshold -> escalate
        if policy.approval_param:
            val = req.params.get(policy.approval_param)
            if not isinstance(val, (int, float)):
                return self._deny(f"'{policy.approval_param}' missing or non-numeric")
            if policy.hard_limit is not None and val > policy.hard_limit:
                return self._deny(f"{policy.approval_param}={val} exceeds hard limit {policy.hard_limit}")
            if policy.approval_threshold is not None and val > policy.approval_threshold:
                aid = self.approvals.submit(req, f"{policy.approval_param}={val} > {policy.approval_threshold}",
                                            c.owners.approval_owner)
                return GovernanceResult(Decision.ESCALATE, "human approval required", aid)

        return GovernanceResult(Decision.ALLOW, "within delegated authority")

    def execute_approved(self, approval_id: str) -> GovernanceResult:
        """After a human approves, the (already-validated) request may proceed once."""
        if not self.approvals.is_approved(approval_id):
            return self._deny("no valid approval")
        self.audit.record("approved_action_released", approval_id=approval_id)
        return GovernanceResult(Decision.ALLOW, "released after human approval", approval_id)