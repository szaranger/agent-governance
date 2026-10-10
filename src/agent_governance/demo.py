"""Demo: the article's procurement agent run through the full governance lifecycle."""
from __future__ import annotations

from .gateway import GovernanceError, GovernanceGateway
from .types import (ActionRequest, AgentCharter, ImpactAssessment, Lifecycle,
                    Owners, Tier, ToolPolicy)


def run_demo() -> None:
    charter = AgentCharter(
        agent_id="procurement-agent-01",
        purpose="Review routine purchase requests and raise POs for approved vendors within budget.",
        tier=Tier.MEDIUM,
        owners=Owners("cfo@corp", "ops-lead@corp", "proc-manager@corp", "sec-oncall@corp", "ciso@corp"),
        credential_id="svc-procurement-agent-01",
        tools={
            "erp": ToolPolicy(
                name="erp",
                allowed_actions={"read_purchase_request", "create_purchase_order"},
                approval_param="amount", approval_threshold=5_000, hard_limit=50_000,
                validators=[lambda p: None if p.get("vendor_approved") else "vendor not on approved list"],
            )
        },
        prohibited_actions={"modify_budget_rules", "add_vendor", "override_approval_hierarchy"},
        allowed_data_classes={"procurement", "vendor_master"},
    )
    gw = GovernanceGateway(charter)

    # Lifecycle gate: cannot deploy without assessment
    gw.advance(Lifecycle.DEVELOPMENT, "eng")
    gw.advance(Lifecycle.TESTING, "eng")
    try:
        gw.advance(Lifecycle.DEPLOYED, "eng")
    except GovernanceError as e:
        print("Blocked (expected):", e)
    gw.attach_assessment(ImpactAssessment(
        financial="Max single PO $50k; monthly exposure capped by rate limit",
        operational="ERP write access limited to PO creation",
        legal="Within delegated purchasing authority",
        reputational="Low; vendors already approved",
        completed_by="risk@corp", signoffs=["finance@corp"], simulation_passed=True))
    gw.advance(Lifecycle.DEPLOYED, "eng")

    def attempt(label: str, **kw):
        r = gw.authorize(ActionRequest(agent_id="procurement-agent-01", tool=kw.pop("tool", "erp"),
                                       on_behalf_of="alice@corp", **kw))
        print(f"{label:<42} -> {r.decision.value.upper():<8} {r.reason}")
        return r

    attempt("Routine PO $1,200", action="create_purchase_order",
            params={"amount": 1200, "vendor_approved": True}, data_classes={"procurement"})
    big = attempt("PO $12,000 (above threshold)", action="create_purchase_order",
                  params={"amount": 12000, "vendor_approved": True}, data_classes={"procurement"})
    attempt("PO $80,000 (above hard limit)", action="create_purchase_order",
            params={"amount": 80000, "vendor_approved": True}, data_classes={"procurement"})
    attempt("Add new vendor (prohibited)", action="add_vendor", params={})
    attempt("Unapproved vendor", action="create_purchase_order",
            params={"amount": 100, "vendor_approved": False}, data_classes={"procurement"})
    attempt("Reads HR data (out of scope)", action="read_purchase_request",
            params={"amount": 0}, data_classes={"hr_records"})
    attempt("Unknown tool (email)", tool="email", action="send", params={})
    attempt("Untrusted peer agent", action="create_purchase_order", params={"amount": 10, "vendor_approved": True},
            peer_agent="random-agent")

    # Human approval path incl. separation of duties
    try:
        gw.approvals.decide(big.approval_id, "alice@corp", True)
    except PermissionError as e:
        print("Blocked (expected):", e)
    gw.approvals.decide(big.approval_id, "proc-manager@corp", True)
    print("Released after approval ->", gw.execute_approved(big.approval_id).decision.value)

    # Kill switch
    gw.suspend("sec-oncall@corp", "anomalous spend pattern")
    attempt("Routine PO after suspension", action="create_purchase_order",
            params={"amount": 10, "vendor_approved": True}, data_classes={"procurement"})

    gw.resume("cfo@corp", "investigated, benign")
    gw.decommission("cfo@corp")

    print("\nAudit entries:", len(gw.audit.entries), "| chain intact:", gw.audit.verify())
    gw.audit.entries[3]["reason"] = "tampered"
    print("After tampering, chain intact:", gw.audit.verify())


if __name__ == "__main__":
    run_demo()