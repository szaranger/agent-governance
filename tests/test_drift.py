import unittest

from agent_governance import Decision, DriftMonitor


class DriftMonitorTests(unittest.TestCase):
    def test_small_sample_returns_no_findings(self):
        m = DriftMonitor(baseline_tools={"erp"})
        for _ in range(5):
            m.observe("erp", Decision.ALLOW)
        self.assertEqual(m.report(), [])

    def test_no_drift_on_normal_flow(self):
        m = DriftMonitor(baseline_tools={"erp"})
        for _ in range(100):
            m.observe("erp", Decision.ALLOW)
        self.assertEqual(m.report(), [])

    def test_high_deny_rate_alerts(self):
        m = DriftMonitor(baseline_tools={"erp"}, window=100, deny_rate_alert=0.15)
        for _ in range(30):
            m.observe("erp", Decision.DENY)
        for _ in range(20):
            m.observe("erp", Decision.ALLOW)
        report = m.report()
        self.assertTrue(any("deny rate" in f for f in report))

    def test_high_escalation_rate_alerts(self):
        m = DriftMonitor(baseline_tools={"erp"}, window=100, escalation_rate_alert=0.30)
        for _ in range(40):
            m.observe("erp", Decision.ESCALATE)
        for _ in range(20):
            m.observe("erp", Decision.ALLOW)
        report = m.report()
        self.assertTrue(any("escalation rate" in f for f in report))

    def test_unknown_tool_alerts(self):
        m = DriftMonitor(baseline_tools={"erp"})
        for _ in range(30):
            m.observe("erp", Decision.ALLOW)
        m.observe("email", Decision.ALLOW)
        report = m.report()
        self.assertTrue(any("tools not in baseline" in f for f in report))


if __name__ == "__main__":
    unittest.main()