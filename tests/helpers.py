from agent_governance import AgentCharter, Owners, Tier, ToolPolicy


def make_charter(**overrides) -> AgentCharter:
    defaults = dict(
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
    defaults.update(overrides)
    return AgentCharter(**defaults)


def make_assessment(**overrides) -> object:
    from agent_governance import ImpactAssessment

    defaults = dict(
        financial="Max single PO $50k; monthly exposure capped by rate limit",
        operational="ERP write access limited to PO creation",
        legal="Within delegated purchasing authority",
        reputational="Low; vendors already approved",
        completed_by="risk@corp",
        signoffs=["finance@corp"],
        simulation_passed=True,
    )
    defaults.update(overrides)
    return ImpactAssessment(**defaults)