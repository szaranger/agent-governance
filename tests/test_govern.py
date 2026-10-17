import unittest

from agent_governance import (ActionRequest, Decision, GovernanceDenied, GovernanceEscalated,
                              GovernanceGateway, Lifecycle)

from helpers import make_assessment, make_charter


def deploy(gw: GovernanceGateway) -> None:
    gw.advance(Lifecycle.DEVELOPMENT, "eng")
    gw.advance(Lifecycle.TESTING, "eng")
    gw.attach_assessment(make_assessment())
    gw.advance(Lifecycle.DEPLOYED, "eng")


class GovernTests(unittest.TestCase):
    def setUp(self):
        self.gw = GovernanceGateway(make_charter())
        deploy(self.gw)
        self.calls: list[dict] = []

        def create_po(**params):
            self.calls.append(params)
            return {"po": params["amount"]}

        self.create_po = create_po
        self.safe = self.gw.govern(
            create_po, tool="erp", action="create_purchase_order",
            data_classes={"procurement"}, on_behalf_of="alice@corp",
        )

    def test_allow_invokes_the_tool(self):
        result = self.safe(amount=100, vendor_approved=True)
        self.assertEqual(result, {"po": 100})
        self.assertEqual(self.calls, [{"amount": 100, "vendor_approved": True}])

    def test_deny_does_not_invoke_the_tool(self):
        with self.assertRaises(GovernanceDenied) as caught:
            self.safe(amount=100, vendor_approved=False)
        self.assertEqual(caught.exception.result.decision, Decision.DENY)
        self.assertEqual(self.calls, [])

    def test_escalate_does_not_invoke_until_approved(self):
        with self.assertRaises(GovernanceEscalated) as caught:
            self.safe(amount=12_000, vendor_approved=True)
        self.assertEqual(self.calls, [])
        approval_id = caught.exception.result.approval_id
        self.gw.approvals.decide(approval_id, "proc-manager@corp", True)
        released = self.safe.call_approved(approval_id)
        self.assertEqual(released, {"po": 12_000})
        self.assertEqual(len(self.calls), 1)

    def test_positional_arguments_are_denied(self):
        with self.assertRaises(GovernanceDenied):
            self.safe(100, vendor_approved=True)
        self.assertEqual(self.calls, [])

    def test_call_approved_rejects_a_different_tool(self):
        other = self.gw.govern(self.create_po, tool="erp", action="read_purchase_request",
                               data_classes={"procurement"})
        with self.assertRaises(GovernanceEscalated) as caught:
            self.safe(amount=12_000, vendor_approved=True)
        self.gw.approvals.decide(caught.exception.result.approval_id, "proc-manager@corp", True)
        with self.assertRaises(GovernanceDenied):
            other.call_approved(caught.exception.result.approval_id)
        self.assertEqual(self.calls, [])

    def test_tripwire_blocks_the_call_that_suspends_the_agent(self):
        for _ in range(19):
            self.gw.authorize(ActionRequest(
                agent_id="procurement-agent-01", tool="erp", action="add_vendor",
                params={}, data_classes={"procurement"}))
        with self.assertRaises(GovernanceDenied):
            self.safe(amount=100, vendor_approved=True)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.gw.state, Lifecycle.SUSPENDED)


if __name__ == "__main__":
    unittest.main()
