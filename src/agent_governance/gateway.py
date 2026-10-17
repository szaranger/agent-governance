"""Steps 4 + 7: runtime enforcement, kill switch, and lifecycle."""
from __future__ import annotations

import math
import time
from collections import deque
from collections.abc import Callable
from dataclasses import asdict
from datetime import timedelta
from typing import Any

from .approvals import DEFAULT_APPROVAL_TTL, ApprovalQueue
from .audit import AuditLog
from .drift import DriftMonitor
from .tools import ToolAdmissionError, ToolManifest, schema_digest, screen_tool
from .types import (ActionRequest, AgentCharter, Decision, GovernanceResult,
                    ImpactAssessment, Lifecycle, ToolPolicy, now)


class GovernanceError(Exception):
    pass


class GovernanceDenied(Exception):
    """A governed tool was not called. `result` is the gateway decision."""

    def __init__(self, result: GovernanceResult):
        self.result = result
        super().__init__(f"{result.decision.value}: {result.reason}")


class GovernanceEscalated(GovernanceDenied):
    """The tool was not called. A human must approve `result.approval_id`."""


class GovernanceGateway:
    """
    The single choke point for agent actions. Enforcement lives here, NOT in the
    agent's prompt or reasoning layer, so it holds even if the agent is manipulated
    (prompt injection, poisoned MCP context, a compromised peer agent).

    `authorize()` reports a decision. `govern()` is the enforcement path: the
    wrapped function runs only after ALLOW, and only while the agent is still
    deployed.
    """

    def __init__(self, charter: AgentCharter, audit: AuditLog | None = None, *,
                 approval_ttl: timedelta = DEFAULT_APPROVAL_TTL, tripwire: bool = True):
        self.charter = charter
        self.audit = audit or AuditLog()
        self.approval_ttl = approval_ttl
        self.tripwire = tripwire
        self.approvals = ApprovalQueue(self.audit, extra=lambda: {"charter_hash": self._charter_hash()})
        self.drift = DriftMonitor(baseline_tools=set(charter.tools))
        self.manifests: dict[str, ToolManifest] = {}
        self.state = Lifecycle.DESIGN
        self.assessment: ImpactAssessment | None = None
        self.credential_active = False
        self._call_times: dict[str, deque[float]] = {}
        self._record("charter_registered", agent=charter.agent_id, tier=charter.tier.value,
                     purpose=charter.purpose, owners=asdict(charter.owners),
                     prohibited=sorted(charter.prohibited_actions))

    def _charter_hash(self) -> str | None:
        try:
            return self.charter.digest()
        except Exception:
            return None

    def _record(self, event: str, **fields: Any) -> dict[str, Any]:
        fields.setdefault("charter_hash", self._charter_hash())
        return self.audit.record(event, **fields)

    # ---- tool admission --------------------------------------------------- #
    def admit_tool(self, manifest: ToolManifest, policy: ToolPolicy,
                   baseline: ToolManifest | None = None) -> None:
        """Screen a tool definition and add it to the charter.

        Admission is refused once the agent is deployed. Hidden instructions,
        schema drift, and a changed server id are recorded and rejected.
        """
        if self.state not in (Lifecycle.DESIGN, Lifecycle.DEVELOPMENT, Lifecycle.TESTING):
            raise GovernanceError(f"cannot admit tools from state {self.state.value}")
        if policy.name != manifest.name:
            raise ToolAdmissionError(["policy name does not match manifest"])
        findings = screen_tool(manifest, baseline)
        stored = self.manifests.get(manifest.name)
        if stored is not None and stored != baseline:
            findings.extend(screen_tool(manifest, stored))
        findings = list(dict.fromkeys(findings))
        overlap = policy.allowed_actions & self.charter.prohibited_actions
        if overlap:
            findings.append(f"actions both allowed and prohibited: {sorted(overlap)}")
        if findings:
            self._record("tool_admission_denied", tool=manifest.name, findings=findings)
            raise ToolAdmissionError(findings)
        self.charter.tools[manifest.name] = policy
        self.manifests[manifest.name] = manifest
        self.drift.baseline_tools.add(manifest.name)
        self._record("tool_admitted", tool=manifest.name, server_id=manifest.server_id,
                     schema_hash=schema_digest(manifest.input_schema))

    # ---- lifecycle -------------------------------------------------------- #
    def advance(self, to: Lifecycle, actor: str) -> None:
        order = [Lifecycle.DESIGN, Lifecycle.DEVELOPMENT, Lifecycle.TESTING, Lifecycle.DEPLOYED]
        if to not in order:
            raise GovernanceError(f"cannot advance to {to.value}; use suspend(), resume() or decommission()")
        if to == Lifecycle.DEPLOYED:
            if self.state != Lifecycle.TESTING:
                raise GovernanceError("must pass through pre-deployment testing before deployment")
            if not self.assessment:
                raise GovernanceError("no impact assessment on file")
            ok, why = self.assessment.satisfies(self.charter.tier)
            if not ok:
                raise GovernanceError(f"deployment blocked: {why}")
            self.credential_active = True
        elif self.state not in order or order.index(to) != order.index(self.state) + 1:
            raise GovernanceError(f"invalid transition {self.state.value} -> {to.value}")
        self._record("lifecycle", agent=self.charter.agent_id, frm=self.state.value, to=to.value, actor=actor)
        self.state = to

    def attach_assessment(self, a: ImpactAssessment) -> None:
        self.assessment = a
        self._record("impact_assessment_filed", agent=self.charter.agent_id, by=a.completed_by,
                     signoffs=a.signoffs, simulation_passed=a.simulation_passed)

    # ---- step 7: shutdown ------------------------------------------------- #
    def suspend(self, by: str, reason: str, *, automatic: bool = False) -> None:
        if not automatic and by != self.charter.owners.intervention_owner:
            raise PermissionError(f"{by} is not the intervention owner")
        if self.state != Lifecycle.DEPLOYED:
            raise GovernanceError(f"cannot suspend from state {self.state.value}")
        self.state = Lifecycle.SUSPENDED
        self._record("suspended", agent=self.charter.agent_id, by=by, reason=reason,
                     automatic=automatic)

    def resume(self, by: str, reason: str) -> None:
        if by != self.charter.owners.accountable_executive:
            raise PermissionError("only the accountable executive can resume a suspended agent")
        if self.state != Lifecycle.SUSPENDED:
            raise GovernanceError(f"cannot resume from state {self.state.value}")
        self.state = Lifecycle.DEPLOYED
        self._record("resumed", agent=self.charter.agent_id, by=by, reason=reason)

    def decommission(self, by: str) -> None:
        """Authority ends as deliberately as it began: revoke access, keep records."""
        owners = self.charter.owners
        if by not in (owners.accountable_executive, owners.intervention_owner):
            raise PermissionError("only the accountable executive or intervention owner can decommission")
        if self.state == Lifecycle.DECOMMISSIONED:
            raise GovernanceError("agent is already decommissioned")
        self.credential_active = False
        self.state = Lifecycle.DECOMMISSIONED
        self._record("decommissioned", agent=self.charter.agent_id, by=by,
                     credential_revoked=self.charter.credential_id, tools_disabled=sorted(self.charter.tools),
                     records_retained=True)

    def attest(self, by: str) -> None:
        """Periodic re-attestation: authority lapses unless an owner renews it (anti-drift)."""
        if by != self.charter.owners.accountable_executive:
            raise PermissionError("only the accountable executive can re-attest authority")
        self.charter.authority_expires = now() + timedelta(days=self.charter.review_interval_days)
        self._record("authority_reattested", agent=self.charter.agent_id, by=by,
                     expires=self.charter.authority_expires)

    # ---- step 4: runtime enforcement ------------------------------------- #
    def govern(self, fn: Callable[..., Any], *, tool: str, action: str,
               data_classes: set[str] | None = None,
               on_behalf_of: str | None = None,
               peer_agent: str | None = None) -> GovernedTool:
        """Return a wrapper that calls `fn` only when the decision is ALLOW.

        Keyword arguments are the tool parameters. Positional arguments are
        denied. An ESCALATE decision raises `GovernanceEscalated` and does not
        call `fn`; `wrapper.call_approved(approval_id)` runs `fn` with the
        snapshotted parameters after `execute_approved` allows the release.
        """

        def wrapped(*args: Any, **params: Any) -> Any:
            if args:
                req = ActionRequest(
                    agent_id=self.charter.agent_id, tool=tool, action=action,
                    params=params, data_classes=set(data_classes or ()),
                    on_behalf_of=on_behalf_of, peer_agent=peer_agent,
                )
                result = GovernanceResult(Decision.DENY, "governed calls take keyword arguments only")
                self._finish(req, result)
                raise GovernanceDenied(result)
            req = ActionRequest(
                agent_id=self.charter.agent_id, tool=tool, action=action, params=params,
                data_classes=set(data_classes or ()), on_behalf_of=on_behalf_of,
                peer_agent=peer_agent,
            )
            result = self.authorize(req)
            if result.decision is Decision.ALLOW and self.state is Lifecycle.DEPLOYED and self.credential_active:
                return fn(**params)
            if result.decision is Decision.ESCALATE and self.state is Lifecycle.DEPLOYED:
                raise GovernanceEscalated(result)
            if self.state is not Lifecycle.DEPLOYED or not self.credential_active:
                raise GovernanceDenied(GovernanceResult(
                    Decision.DENY, f"agent not operational (state={self.state.value})"))
            raise GovernanceDenied(result)

        def call_approved(approval_id: str) -> Any:
            item = self.approvals.get(approval_id)
            if item is None or item.request.tool != tool or item.request.action != action:
                result = GovernanceResult(Decision.DENY, "approval is not for this tool")
                raise GovernanceDenied(result)
            result = self.execute_approved(approval_id)
            if result.decision is not Decision.ALLOW:
                raise GovernanceDenied(result)
            return fn(**item.request.params)

        return GovernedTool(wrapped, call_approved)

    def authorize(self, req: ActionRequest) -> GovernanceResult:
        try:
            result = self._evaluate(req)
        except Exception as exc:
            result = self._deny(f"evaluation failed closed: {type(exc).__name__}")
        return self._finish(req, result)

    def _finish(self, req: ActionRequest, result: GovernanceResult) -> GovernanceResult:
        self.drift.observe(req.tool, result.decision)
        self._record("action_decision", agent=req.agent_id, session=req.session_id,
                     on_behalf_of=req.on_behalf_of, tool=req.tool, action=req.action,
                     params=req.params, decision=result.decision.value, reason=result.reason,
                     approval_id=result.approval_id, peer=req.peer_agent)
        self._apply_drift_tripwire()
        return result

    def _apply_drift_tripwire(self) -> None:
        if not self.tripwire or self.state is not Lifecycle.DEPLOYED:
            return
        findings = self.drift.report()
        if findings:
            self.suspend("drift-monitor", "; ".join(findings), automatic=True)

    def _deny(self, why: str) -> GovernanceResult:
        return GovernanceResult(Decision.DENY, why)

    def _operational_denial(self) -> GovernanceResult | None:
        if self.state != Lifecycle.DEPLOYED or not self.credential_active:
            return self._deny(f"agent not operational (state={self.state.value})")
        if now() > self.charter.authority_expires:
            return self._deny("delegated authority expired; re-attestation required")
        return None

    def _evaluate(self, req: ActionRequest, *, releasing: bool = False) -> GovernanceResult:
        c = self.charter
        if req.agent_id != c.agent_id:
            return self._deny("identity mismatch")
        denial = self._operational_denial()
        if denial:
            return denial

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

        # Rate limit (blast-radius control for runaway loops).
        # A release was already counted when it escalated, so it is not counted again.
        if not releasing:
            window = self._call_times.setdefault(req.tool, deque())
            t = time.monotonic()
            while window and t - window[0] > 60:
                window.popleft()
            if len(window) >= policy.max_calls_per_minute:
                return self._deny(f"rate limit exceeded on '{req.tool}'")
            window.append(t)

        # Parameter validation (input checking against policy)
        for v in policy.validators:
            try:
                err = v(req.params)
            except Exception as exc:
                return self._deny(f"validator error: {type(exc).__name__}")
            if err:
                return self._deny(f"validation failed: {err}")

        # Thresholds: hard limit -> deny; approval threshold -> escalate
        if policy.approval_param:
            val = req.params.get(policy.approval_param)
            # bool is an int subclass, and NaN compares False against every limit.
            if isinstance(val, bool) or not isinstance(val, (int, float)) or not math.isfinite(val):
                return self._deny(f"'{policy.approval_param}' missing, non-numeric or non-finite")
            if policy.hard_limit is not None and val > policy.hard_limit:
                return self._deny(f"{policy.approval_param}={val} exceeds hard limit {policy.hard_limit}")
            if policy.approval_threshold is not None and val > policy.approval_threshold:
                if releasing:
                    return GovernanceResult(Decision.ALLOW, "within approved threshold")
                aid = self.approvals.submit(
                    req, f"{policy.approval_param}={val} > {policy.approval_threshold}",
                    c.owners.approval_owner, ttl=self.approval_ttl)
                return GovernanceResult(Decision.ESCALATE, "human approval required", aid)

        return GovernanceResult(Decision.ALLOW, "within delegated authority")

    def execute_approved(self, approval_id: str) -> GovernanceResult:
        """Release a single approved action after the policy is checked again.

        The stored request must still match its digest, the approval must be
        unexpired, and the charter must still allow the action. Crossing the
        approval threshold is expected; that is why a human approved it. A
        hard limit, a new prohibition, or a failed validator still denies.
        """
        result = self._release(approval_id)
        self._record("approved_action_release", approval_id=approval_id,
                     decision=result.decision.value, reason=result.reason)
        return result

    def _release(self, approval_id: str) -> GovernanceResult:
        item = self.approvals.get(approval_id)
        if item is None or item.request.agent_id != self.charter.agent_id:
            return self._deny("no valid approval")
        stale = self.approvals.stale_reason(item)
        if stale:
            return self._deny(stale)
        denial = self._operational_denial()
        if denial:
            return denial
        reviewed = self._evaluate(item.request, releasing=True)
        if reviewed.decision is Decision.DENY:
            return reviewed
        try:
            self.approvals.consume(approval_id)
        except ValueError:
            return self._deny("no valid approval")
        return GovernanceResult(Decision.ALLOW, "released after human approval", approval_id)


class GovernedTool:
    """Callable tool wrapper. `call_approved` runs a previously approved action."""

    def __init__(self, invoke: Callable[..., Any], release: Callable[[str], Any]):
        self._invoke = invoke
        self.call_approved = release

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._invoke(*args, **kwargs)
