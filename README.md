# Agentic AI Governance Framework

A small, dependency-free Python reference implementation of **agentic AI governance**: the structured management of delegated authority in autonomous AI systems that plan and execute actions on behalf of an organisation.

It is based on the lifecycle and eight-step implementation model in Palo Alto Networks' [A Complete Guide to Agentic AI Governance](https://www.paloaltonetworks.com.au/cyberpedia/what-is-agentic-ai-governance).

## Why this exists

Traditional AI governance focuses on **output risk**: is the answer accurate, fair, compliant? Agents add **action risk**: they call tools, hold credentials, and change records without waiting for a human. Governance therefore has to move from policy documents to **runtime control**.

This framework puts that control in code. The agent never calls tools directly. Every action passes through a **gateway** that enforces policy independently of the agent's reasoning, so limits hold even if the agent is manipulated (prompt injection, poisoned tool context, a compromised peer agent).

## Requirements

- Python 3.10+
- No third-party runtime packages (pytest is only needed for the test suite)

## Project layout

```
agent-governance/
├── pyproject.toml
└── src/agent_governance/
    ├── types.py       # charter, owners, tool policy, impact assessment, requests
    ├── audit.py       # tamper-evident audit log (step 5)
    ├── approvals.py   # human approval queue (step 6)
    ├── drift.py       # drift monitor (step 8)
    ├── gateway.py     # runtime enforcement + lifecycle + shutdown (steps 4, 7)
    └── demo.py        # procurement-agent demo
```

## Quick start

Using [uv](https://docs.astral.sh/uv/) (recommended):

```bash
uv sync                 # creates .venv, installs the package and dev deps
uv run python -m agent_governance.demo
```

Or with plain pip:

```bash
pip install -e .
python -m agent_governance.demo
```

This runs a demo of the article's procurement-agent example:

```
Routine PO $1,200                          -> ALLOW    within delegated authority
PO $12,000 (above threshold)               -> ESCALATE human approval required
PO $80,000 (above hard limit)              -> DENY     amount=80000 exceeds hard limit 50000
Add new vendor (prohibited)                -> DENY     action 'add_vendor' is explicitly prohibited
Unapproved vendor                          -> DENY     validation failed: vendor not on approved list
Reads HR data (out of scope)               -> DENY     data classes out of scope: ['hr_records']
Unknown tool (email)                       -> DENY     tool 'email' is outside approved scope
Untrusted peer agent                       -> DENY     peer agent 'random-agent' not trusted
Routine PO after suspension                -> DENY     agent not operational (state=suspended)
```

## Tests

With uv:

```bash
uv run python -m unittest discover -s tests   # stdlib runner
uv run pytest                                 # pytest, installed by uv sync
```

Or with plain pip:

```bash
python -m unittest discover -s tests          # stdlib runner, no dependencies
pip install -e ".[dev]"                       # or: install pytest first
pytest
```

## How the code maps to the eight steps

| # | Article step | Implementation |
|---|---|---|
| 1 | Define scope and authority | `AgentCharter`: purpose, allowed tools, explicit `prohibited_actions`, allowed data classes. Contradictory charters are rejected at creation. |
| 2 | Map identity and access | Dedicated `credential_id` per agent; per-tool least-privilege `ToolPolicy`; `allowed_peer_agents` allow-list for agent-to-agent trust. |
| 3 | Pre-deployment impact assessment | `ImpactAssessment` is a hard lifecycle gate. Deployment is blocked without a complete assessment, a passed simulation and enough sign-offs for the risk tier (0 / 1 / 3 for low / medium / high). |
| 4 | Runtime controls | `GovernanceGateway.authorize()` returns `ALLOW`, `ESCALATE` or `DENY` (see the evaluation order below). |
| 5 | Logging and traceability | `AuditLog`: append-only and hash-chained. Editing any past entry makes `verify()` fail. Entries carry agent, session and `on_behalf_of` attribution. |
| 6 | Human oversight thresholds | `ApprovalQueue` routes over-threshold actions to a named approver and enforces separation of duties (requesters cannot approve their own actions). |
| 7 | Incident response and shutdown | `suspend()` (intervention owner only), `resume()` (accountable executive only), `decommission()` (accountable executive or intervention owner; revokes credentials, retains records). Each is guarded to the lifecycle state it applies to. |
| 8 | Ongoing evaluation and drift | `DriftMonitor` flags high deny or escalation rates and tools outside the baseline. Delegated authority expires unless an owner calls `attest()`. |

## Core concepts

**Lifecycle.** `DESIGN → DEVELOPMENT → TESTING → DEPLOYED`, plus `SUSPENDED` and `DECOMMISSIONED`. Transitions are validated and logged. Skipping testing or the impact assessment raises `GovernanceError`.

**Risk tiers.** `Tier.LOW | MEDIUM | HIGH` scale the required review depth (number of sign-offs).

**Owners.** Accountability is assigned to named people before deployment, matching the article's responsibility model:

| Role | Responsibility |
|---|---|
| `accountable_executive` | Primary accountability; can resume and re-attest the agent |
| `monitoring_owner` | Watches behaviour |
| `approval_owner` | Approves high-impact actions |
| `intervention_owner` | Can suspend execution |
| `incident_owner` | Investigates and reports material impact |

**Evaluation order in `authorize()`.** The first failing check denies the request:

1. Identity matches the charter
2. Lifecycle state is `DEPLOYED` and the credential is active
3. Delegated authority has not expired
4. Originating peer agent is trusted
5. Action is not explicitly prohibited
6. Tool and action are in scope
7. Data classes are in scope
8. Per-tool rate limit
9. Custom parameter validators (a raising validator denies rather than crashing the gateway)
10. Thresholds: hard limit (deny) and approval threshold (escalate); non-numeric, boolean and non-finite (NaN/±inf) values are denied

## Usage

```python
from agent_governance import *

charter = AgentCharter(
    agent_id="procurement-agent-01",
    purpose="Raise POs for approved vendors within budget.",
    tier=Tier.MEDIUM,
    owners=Owners(
        accountable_executive="cfo@corp",
        monitoring_owner="ops-lead@corp",
        approval_owner="proc-manager@corp",
        intervention_owner="sec-oncall@corp",
        incident_owner="ciso@corp",
    ),
    credential_id="svc-procurement-agent-01",
    tools={
        "erp": ToolPolicy(
            name="erp",
            allowed_actions={"read_purchase_request", "create_purchase_order"},
            approval_param="amount", approval_threshold=5_000, hard_limit=50_000,
        )
    },
    prohibited_actions={"modify_budget_rules", "add_vendor"},
    allowed_data_classes={"procurement", "vendor_master"},
)

gw = GovernanceGateway(charter)
gw.advance(Lifecycle.DEVELOPMENT, "eng")
gw.advance(Lifecycle.TESTING, "eng")
gw.attach_assessment(ImpactAssessment(
    financial="...", operational="...", legal="...", reputational="...",
    completed_by="risk@corp", signoffs=["finance@corp"], simulation_passed=True,
))
gw.advance(Lifecycle.DEPLOYED, "eng")

# Wrap every tool call the agent wants to make:
result = gw.authorize(ActionRequest(
    agent_id="procurement-agent-01", tool="erp", action="create_purchase_order",
    params={"amount": 12_000}, data_classes={"procurement"}, on_behalf_of="alice@corp",
))

if result.decision == Decision.ALLOW:
    ...  # perform the real tool call
elif result.decision == Decision.ESCALATE:
    gw.approvals.decide(result.approval_id, by="proc-manager@corp", approve=True)
    gw.execute_approved(result.approval_id)
else:
    ...  # blocked; result.reason explains why
```

## Production notes

- **Enforcement only works if routed.** Wrap your real tool layer (for example your MCP client or API clients) so nothing bypasses `authorize()`. For MCP and A2A, also inspect tool definitions and the data exchanged on each call.
- **Persistence.** The audit log and approval queue are in memory by default. Use durable, access-controlled storage and ship the audit log to an external or write-once sink.
- **Configurable values.** Thresholds, rate limits, tier sign-off counts and review intervals are illustrative defaults. Set them from your own risk appetite.
- **Approved actions.** Approvals are single-use: `execute_approved()` consumes the approval (its status moves to `executed`) and cannot release while the agent is suspended, decommissioned or past its authority period. A consumed approval cannot be replayed. Approvals do not expire on their own, so add a time limit in your integration if you need one.
- **Identity.** `credential_id` is a label here. Integrate with your IAM so the gateway controls real credential issuance and revocation.
- **Drift review.** Call `gw.drift.report()` on a schedule and route findings to the monitoring owner. Reassess permissions periodically, since drift often appears as expanding authority rather than changing outputs.

## Alignment with standards

The article cites these frameworks as relevant to agentic governance. This code is **not** a certified implementation of any of them, and the controls are not formally mapped to specific clauses.

- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [ISO/IEC 42001:2023](https://www.iso.org/standard/42001) (AI management systems)
- [ISO/IEC 42005](https://www.iso.org/standard/42005) (AI impact assessment)
- [ISO/IEC 23894](https://www.iso.org/standard/77304.html) (AI risk management)
- [EU AI Act](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications)

## Disclaimer

This is an educational reference implementation, not legal, compliance or security advice. Review and adapt it to your own environment and regulatory obligations before relying on it.