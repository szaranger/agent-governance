"""Step 8: drift monitoring against baseline behaviour."""
from __future__ import annotations

from collections import Counter, deque

from .types import Decision


class DriftMonitor:
    """
    Compares recent behaviour with the baseline captured during testing/early operation.
    Watches the things the article calls out: expanding authority, new tools,
    rising deny/escalation rates - not just output quality.
    """

    def __init__(self, baseline_tools: set[str], window: int = 200,
                 deny_rate_alert: float = 0.15, escalation_rate_alert: float = 0.30):
        self.baseline_tools = baseline_tools
        self.recent: deque[tuple[str, Decision]] = deque(maxlen=window)
        self.deny_rate_alert = deny_rate_alert
        self.escalation_rate_alert = escalation_rate_alert

    def observe(self, tool: str, decision: Decision) -> None:
        self.recent.append((tool, decision))

    def report(self) -> list[str]:
        findings: list[str] = []
        if len(self.recent) < 20:
            return findings
        n = len(self.recent)
        c = Counter(d for _, d in self.recent)
        if c[Decision.DENY] / n > self.deny_rate_alert:
            findings.append(f"deny rate {c[Decision.DENY]/n:.0%}: agent is repeatedly reaching past its authority")
        if c[Decision.ESCALATE] / n > self.escalation_rate_alert:
            findings.append(f"escalation rate {c[Decision.ESCALATE]/n:.0%}: scope or thresholds may no longer fit the work")
        new_tools = {t for t, _ in self.recent} - self.baseline_tools
        if new_tools:
            findings.append(f"tools not in baseline: {sorted(new_tools)}")
        return findings