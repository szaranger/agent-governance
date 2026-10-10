import unittest
from datetime import timedelta

from agent_governance import (ActionRequest, Decision, GovernanceError, GovernanceGateway,
                              Lifecycle, now)

from helpers import make_assessment, make_charter


def deploy(gw: GovernanceGateway) -> None:
    gw.advance(Lifecycle.DEVELOPMENT, "eng")
    gw.advance(Lifecycle.TESTING, "eng")
    gw.attach_assessment(make_assessment())
    gw.advance(Lifecycle.DEPLOYED, "eng")


class LifecycleGateTests(unittest.TestCase):
    def test_cannot_deploy_without_assessment(self):
        gw = GovernanceGateway(make_charter())
        gw.advance(Lifecycle.DEVELOPMENT, "eng")
        gw.advance(Lifecycle.TESTING, "eng")
        with self.assertRaises(GovernanceError):
            gw.advance(Lifecycle.DEPLOYED, "eng")

    def test_cannot_skip_testing(self):
        gw = GovernanceGateway(make_charter())
        gw.advance(Lifecycle.DEVELOPMENT, "eng")
        with self.assertRaises(GovernanceError):
            gw.advance(Lifecycle.DEPLOYED, "eng")

    def test_cannot_deploy_with_unsatisfied_assessment(self):
        gw = GovernanceGateway(make_charter())
        gw.advance(Lifecycle.DEVELOPMENT, "eng")
        gw.advance(Lifecycle.TESTING, "eng")
        gw.attach_assessment(make_assessment(simulation_passed=False))
        with self.assertRaises(GovernanceError):
            gw.advance(Lifecycle.DEPLOYED, "eng")

    def test_advance_cannot_suspend_or_decommission(self):
        gw = GovernanceGateway(make_charter())
        deploy(gw)
        for target in (Lifecycle.SUSPENDED, Lifecycle.DECOMMISSIONED):
            with self.assertRaises(GovernanceError):
                gw.advance(target, "anyone")
        self.assertEqual(gw.state, Lifecycle.DEPLOYED)


class EnforcementTests(unittest.TestCase):
    def setUp(self):
        self.gw = GovernanceGateway(make_charter())
        deploy(self.gw)

    def request(self, **kw) -> ActionRequest:
        defaults = dict(agent_id="procurement-agent-01", tool="erp",
                        action="create_purchase_order",
                        params={"amount": 100, "vendor_approved": True},
                        data_classes={"procurement"}, on_behalf_of="alice@corp")
        defaults.update(kw)
        return ActionRequest(**defaults)

    def test_routine_call_allowed(self):
        r = self.gw.authorize(self.request())
        self.assertEqual(r.decision, Decision.ALLOW)

    def test_identity_mismatch_denied(self):
        r = self.gw.authorize(self.request(agent_id="imposter"))
        self.assertEqual(r.decision, Decision.DENY)
        self.assertIn("identity", r.reason)

    def test_prohibited_action_denied(self):
        r = self.gw.authorize(self.request(action="add_vendor"))
        self.assertEqual(r.decision, Decision.DENY)

    def test_unknown_tool_denied(self):
        r = self.gw.authorize(self.request(tool="email", action="send", params={}))
        self.assertEqual(r.decision, Decision.DENY)

    def test_action_not_permitted_on_tool(self):
        r = self.gw.authorize(self.request(action="delete_purchase_order"))
        self.assertEqual(r.decision, Decision.DENY)

    def test_out_of_scope_data_denied(self):
        r = self.gw.authorize(self.request(data_classes={"hr_records"}))
        self.assertEqual(r.decision, Decision.DENY)

    def test_untrusted_peer_denied(self):
        r = self.gw.authorize(self.request(peer_agent="random-agent"))
        self.assertEqual(r.decision, Decision.DENY)

    def test_approved_peer_allowed(self):
        charter = make_charter(allowed_peer_agents={"peer-01"})
        gw = GovernanceGateway(charter)
        deploy(gw)
        r = gw.authorize(ActionRequest(agent_id="procurement-agent-01", tool="erp",
                                       action="create_purchase_order",
                                       params={"amount": 100, "vendor_approved": True},
                                       data_classes={"procurement"}, peer_agent="peer-01"))
        self.assertEqual(r.decision, Decision.ALLOW)

    def test_validator_failure_denied(self):
        r = self.gw.authorize(self.request(params={"amount": 100, "vendor_approved": False}))
        self.assertEqual(r.decision, Decision.DENY)
        self.assertIn("vendor", r.reason)

    def test_above_threshold_escalates(self):
        r = self.gw.authorize(self.request(params={"amount": 12_000, "vendor_approved": True}))
        self.assertEqual(r.decision, Decision.ESCALATE)
        self.assertIsNotNone(r.approval_id)

    def test_above_hard_limit_denied(self):
        r = self.gw.authorize(self.request(params={"amount": 80_000, "vendor_approved": True}))
        self.assertEqual(r.decision, Decision.DENY)
        self.assertIn("hard limit", r.reason)

    def test_missing_numeric_param_denied(self):
        r = self.gw.authorize(self.request(params={"vendor_approved": True}))
        self.assertEqual(r.decision, Decision.DENY)

    def test_non_finite_or_bool_amount_denied(self):
        for amount in (float("nan"), float("inf"), True):
            with self.subTest(amount=amount):
                r = self.gw.authorize(self.request(params={"amount": amount, "vendor_approved": True}))
                self.assertEqual(r.decision, Decision.DENY)
                self.assertIn("non-finite", r.reason)

    def test_raising_validator_denied_and_logged(self):
        def boom(params):
            raise KeyError("vendor_id")

        gw = GovernanceGateway(make_charter())
        gw.charter.tools["erp"].validators.append(boom)
        deploy(gw)
        r = gw.authorize(self.request())
        self.assertEqual(r.decision, Decision.DENY)
        self.assertIn("validator error", r.reason)
        last = gw.audit.entries[-1]
        self.assertEqual(last["event"], "action_decision")
        self.assertEqual(last["decision"], "deny")

    def test_lifecycle_denies_when_not_deployed(self):
        gw = GovernanceGateway(make_charter())
        r = gw.authorize(ActionRequest(agent_id="procurement-agent-01", tool="erp",
                                       action="create_purchase_order",
                                       params={"amount": 1, "vendor_approved": True}))
        self.assertEqual(r.decision, Decision.DENY)

    def test_expired_authority_denied(self):
        gw = GovernanceGateway(make_charter(review_interval_days=90))
        deploy(gw)
        gw.charter.authority_expires = now() - timedelta(days=1)
        r = gw.authorize(self.request())
        self.assertEqual(r.decision, Decision.DENY)
        self.assertIn("expired", r.reason)

    def test_rate_limit_denied(self):
        policy = self.gw.charter.tools["erp"]
        policy.max_calls_per_minute = 3
        for i in range(3):
            r = self.gw.authorize(self.request())
            self.assertEqual(r.decision, Decision.ALLOW)
        r = self.gw.authorize(self.request())
        self.assertEqual(r.decision, Decision.DENY)
        self.assertIn("rate limit", r.reason)


class ApprovalFlowTests(unittest.TestCase):
    def setUp(self):
        self.gw = GovernanceGateway(make_charter())
        deploy(self.gw)

    def test_escalated_action_released_after_approval(self):
        req = ActionRequest(agent_id="procurement-agent-01", tool="erp",
                            action="create_purchase_order",
                            params={"amount": 12_000, "vendor_approved": True},
                            data_classes={"procurement"}, on_behalf_of="alice@corp")
        result = self.gw.authorize(req)
        self.assertEqual(result.decision, Decision.ESCALATE)
        self.gw.approvals.decide(result.approval_id, "proc-manager@corp", True)
        released = self.gw.execute_approved(result.approval_id)
        self.assertEqual(released.decision, Decision.ALLOW)

    def test_execute_approved_denies_without_approval(self):
        r = self.gw.execute_approved("nonexistent-id")
        self.assertEqual(r.decision, Decision.DENY)

    def approved_id(self) -> str:
        result = self.gw.authorize(ActionRequest(
            agent_id="procurement-agent-01", tool="erp", action="create_purchase_order",
            params={"amount": 12_000, "vendor_approved": True},
            data_classes={"procurement"}, on_behalf_of="alice@corp"))
        self.gw.approvals.decide(result.approval_id, "proc-manager@corp", True)
        return result.approval_id

    def test_approval_cannot_be_replayed(self):
        aid = self.approved_id()
        self.assertEqual(self.gw.execute_approved(aid).decision, Decision.ALLOW)
        second = self.gw.execute_approved(aid)
        self.assertEqual(second.decision, Decision.DENY)

    def test_approval_not_released_while_suspended(self):
        aid = self.approved_id()
        self.gw.suspend("sec-oncall@corp", "investigating")
        r = self.gw.execute_approved(aid)
        self.assertEqual(r.decision, Decision.DENY)
        self.assertIn("not operational", r.reason)
        self.assertTrue(self.gw.approvals.is_approved(aid))


class KillSwitchTests(unittest.TestCase):
    def setUp(self):
        self.gw = GovernanceGateway(make_charter())
        deploy(self.gw)

    def request(self, **kw) -> ActionRequest:
        defaults = dict(agent_id="procurement-agent-01", tool="erp",
                        action="create_purchase_order",
                        params={"amount": 100, "vendor_approved": True},
                        data_classes={"procurement"})
        defaults.update(kw)
        return ActionRequest(**defaults)

    def test_suspend_revoke_and_resume(self):
        self.gw.suspend("sec-oncall@corp", "anomalous spend")
        self.assertEqual(self.gw.state, Lifecycle.SUSPENDED)
        r = self.gw.authorize(self.request())
        self.assertEqual(r.decision, Decision.DENY)

        self.gw.resume("cfo@corp", "investigated, benign")
        self.assertEqual(self.gw.state, Lifecycle.DEPLOYED)
        r = self.gw.authorize(self.request())
        self.assertEqual(r.decision, Decision.ALLOW)

    def test_suspend_requires_intervention_owner(self):
        with self.assertRaises(PermissionError):
            self.gw.suspend("cfo@corp", "unauthorised")

    def test_resume_requires_accountable_executive(self):
        self.gw.suspend("sec-oncall@corp", "reason")
        with self.assertRaises(PermissionError):
            self.gw.resume("sec-oncall@corp", "unauthorised")

    def test_resume_requires_suspended_state(self):
        with self.assertRaises(GovernanceError):
            self.gw.resume("cfo@corp", "not suspended")
        self.gw.decommission("cfo@corp")
        with self.assertRaises(GovernanceError):
            self.gw.resume("cfo@corp", "revive")
        self.assertEqual(self.gw.state, Lifecycle.DECOMMISSIONED)

    def test_suspend_requires_deployed_state(self):
        self.gw.decommission("cfo@corp")
        with self.assertRaises(GovernanceError):
            self.gw.suspend("sec-oncall@corp", "already gone")

    def test_decommission_requires_authorised_owner(self):
        with self.assertRaises(PermissionError):
            self.gw.decommission("intruder@corp")
        self.assertEqual(self.gw.state, Lifecycle.DEPLOYED)

    def test_decommission_twice_rejected(self):
        self.gw.decommission("sec-oncall@corp")
        with self.assertRaises(GovernanceError):
            self.gw.decommission("cfo@corp")

    def test_decommission_revokes_credential(self):
        self.gw.decommission("cfo@corp")
        self.assertFalse(self.gw.credential_active)
        self.assertEqual(self.gw.state, Lifecycle.DECOMMISSIONED)
        r = self.gw.authorize(self.request())
        self.assertEqual(r.decision, Decision.DENY)

    def test_attestation_renews_authority(self):
        self.gw.charter.authority_expires = now() - timedelta(days=1)
        self.gw.attest("cfo@corp")
        self.assertGreater(self.gw.charter.authority_expires, now())

    def test_attestation_requires_accountable_executive(self):
        with self.assertRaises(PermissionError):
            self.gw.attest("sec-oncall@corp")


class AuditIntegrationTests(unittest.TestCase):
    def test_gateway_records_and_chain_stays_intact(self):
        gw = GovernanceGateway(make_charter())
        deploy(gw)
        before = len(gw.audit.entries)
        gw.authorize(ActionRequest(agent_id="procurement-agent-01", tool="erp",
                                   action="create_purchase_order",
                                   params={"amount": 100, "vendor_approved": True},
                                   data_classes={"procurement"}))
        self.assertGreater(len(gw.audit.entries), before)
        self.assertTrue(gw.audit.verify())


if __name__ == "__main__":
    unittest.main()