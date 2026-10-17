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
    ├── tools.py       # tool-description and schema admission checks
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

| # | Step | Implementation |
|---|---|---|
| 1 | Define scope and authority | `AgentCharter`: purpose, allowed tools, explicit `prohibited_actions`, allowed data classes. Contradictory charters are rejected at creation. |
| 2 | Map identity and access | Dedicated `credential_id` per agent; per-tool least-privilege `ToolPolicy`; `allowed_peer_agents` allow-list for agent-to-agent trust. |
| 3 | Pre-deployment impact assessment | `ImpactAssessment` is a hard lifecycle gate. Deployment is blocked without a complete assessment, a passed simulation and enough sign-offs for the risk tier (0 / 1 / 3 for low / medium / high). |
| 4 | Runtime controls | `authorize()` returns `ALLOW`, `ESCALATE` or `DENY`. `govern()` calls the tool only after `ALLOW`. Unexpected evaluation errors deny (fail closed). |
| 5 | Logging and traceability | `AuditLog`: append-only and hash-chained. `verify()` checks memory; `verify_disk()` re-reads the file. A rewritten file fails verification and further appends are refused. Every gateway entry carries `charter_hash`, plus agent, session and `on_behalf_of`. |
| 6 | Human oversight thresholds | `ApprovalQueue` routes over-threshold actions to a named approver, binds the approval to a digest of the request, expires it, and enforces separation of duties (requesters cannot approve their own actions). `execute_approved()` checks the charter again before release. |
| 7 | Incident response and shutdown | `suspend()` (intervention owner, or the drift tripwire), `resume()` (accountable executive only), `decommission()` (accountable executive or intervention owner; revokes credentials, retains records). Each is guarded to the lifecycle state it applies to. |
| 8 | Ongoing evaluation and drift | `DriftMonitor` flags high deny or escalation rates and tools outside the baseline. With the tripwire on (the default), those findings call `suspend()` automatically. Delegated authority expires unless an owner calls `attest()`. |

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

Any other exception during evaluation becomes `DENY` with reason `evaluation failed closed`. The exception does not propagate as an allow. On release of an approved action the same checks run again, except the approval threshold (a human already accepted that) and the rate-limit counter (the escalation already consumed a slot).

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

# Prefer govern(): the function runs only after ALLOW.
def create_purchase_order(*, amount, vendor_approved):
    ...  # the real tool call

safe = gw.govern(create_purchase_order, tool="erp", action="create_purchase_order",
                 data_classes={"procurement"}, on_behalf_of="alice@corp")
safe(amount=1_200, vendor_approved=True)          # calls through
# safe(amount=12_000, vendor_approved=True)       # raises GovernanceEscalated
# safe.call_approved(approval_id)                 # calls through after a human approves

# authorize() is the decision API when the caller needs the result object:
result = gw.authorize(ActionRequest(
    agent_id="procurement-agent-01", tool="erp", action="create_purchase_order",
    params={"amount": 12_000, "vendor_approved": True},
    data_classes={"procurement"}, on_behalf_of="alice@corp",
))

if result.decision == Decision.ALLOW:
    ...  # govern() already did this for you
elif result.decision == Decision.ESCALATE:
    gw.approvals.decide(result.approval_id, by="proc-manager@corp", approve=True)
    gw.execute_approved(result.approval_id)  # re-checks policy; single use
else:
    ...  # blocked; result.reason explains why
```

## Production notes

- **Enforcement.** Call tools through `govern()`. `authorize()` only reports a decision; a caller that ignores it can still perform the action. Before deployment, `admit_tool()` screens an MCP-style manifest for hidden instructions, schema drift, and a changed server id.
- **Persistence.** The audit log and approval queue are in memory by default. Pass a file path to `AuditLog` for an append-only JSONL chain, and call `verify_disk()` from a process that still holds the log. Ship that file to an external or write-once sink.
- **Configurable values.** Thresholds, rate limits, the 24-hour approval TTL, tier sign-off counts and review intervals are illustrative defaults. Set them from your own risk appetite. `GovernanceGateway(..., tripwire=False)` leaves drift as a report only.
- **Approved actions.** Approvals are single-use and bound to a digest of the request. The default lifetime is 24 hours (`approval_ttl`). `execute_approved()` consumes the approval (its status moves to `executed`) only after a fresh policy check. It cannot release while the agent is suspended, decommissioned, past its authority period, or after the payload or the charter has changed in a way the charter now denies. A consumed approval cannot be replayed.
- **Identity.** `credential_id` is a label here. Integrate with your IAM so the gateway controls real credential issuance and revocation. Peer trust is a name allow-list supplied by the caller.
- **Drift review.** The tripwire suspends a deployed agent when `drift.report()` finds a high deny rate, a high escalation rate, or a tool outside the baseline (after at least 20 decisions). Resume still requires the accountable executive. Reassess permissions periodically, since drift often appears as expanding authority rather than changing outputs.

## Alignment with standards

This code is an educational reference, not a certified implementation of any of these. The list below is the set of documents the lifecycle is written against. Clause-level mappings for NIST, ISO and the EU AI Act are left to the deploying organisation.

- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [ISO/IEC 42001:2023](https://www.iso.org/standard/42001) (AI management systems)
- [ISO/IEC 42005](https://www.iso.org/standard/42005) (AI impact assessment)
- [ISO/IEC 23894](https://www.iso.org/standard/77304.html) (AI risk management)
- [EU AI Act](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications)

### OWASP Top 10 for Agentic Applications (2026)

Status is **Enforced** (the control in this package addresses the risk for an in-process tool call), **Partial** (a control exists and a material gap remains), or **Out of scope** (this package does not implement that control). Nothing here is a third-party assessment.

| ID | Risk | Status | What this package does |
|---|---|---|---|
| ASI01 | Agent goal hijack | Partial | The gateway does not trust the prompt. `admit_tool()` rejects hidden instructions and stealth Unicode in a tool description. User prompts and tool results are not classified. |
| ASI02 | Tool misuse and exploitation | Partial | Allow-list, prohibitions, validators, numeric ceilings, and `govern()`, which runs the function only after `ALLOW`. Tool output is not inspected. |
| ASI03 | Identity and privilege abuse | Partial | Per-agent credential flag, data-class boundary, least-privilege actions. `credential_id` is a label, not a verified identity, and decommission does not revoke a real credential. |
| ASI04 | Agentic supply chain | Partial | Admission screens hidden instructions, schema drift, and server-id changes, and refuses admission after deployment. There is no SBOM or dependency scan. |
| ASI05 | Unexpected code execution | Out of scope | Sandboxing and command denylists belong to the host that runs the tool. |
| ASI06 | Memory and context poisoning | Out of scope | Memory and retrieval writes are not on the gateway path. |
| ASI07 | Insecure inter-agent communication | Partial | Peer agents must be on `allowed_peer_agents`. The name is whatever the caller puts on the request; there is no authentication, integrity check, or replay protection. |
| ASI08 | Cascading failures | Partial | Per-tool rate limit, and a drift tripwire that suspends the agent. There is no circuit breaker across agents. |
| ASI09 | Human-agent trust exploitation | Partial | Approvals are bound to a request digest, expire (default 24 hours), enforce separation of duties, and are re-checked against the charter on release. There is no operator interface that presents the consequences of the action. |
| ASI10 | Rogue agents | Partial | After 20 decisions, a high deny rate, a high escalation rate, or an off-baseline tool suspends the agent. That is a tripwire for this agent, not a quarantine of its peers. |

## Disclaimer

This is an educational reference implementation, not legal, compliance or security advice. Review and adapt it to your own environment and regulatory obligations before relying on it.