import unittest

from agent_governance import ActionRequest, ApprovalQueue, AuditLog


class ApprovalQueueTests(unittest.TestCase):
    def setUp(self):
        self.audit = AuditLog()
        self.queue = ApprovalQueue(self.audit)
        self.req = ActionRequest(agent_id="a1", tool="erp", action="buy",
                                 params={}, on_behalf_of="alice@corp")

    def test_submit_returns_id_and_stays_pending(self):
        aid = self.queue.submit(self.req, "over threshold", "manager@corp")
        self.assertFalse(self.queue.is_approved(aid))
        self.assertEqual(self.audit.entries[-1]["event"], "approval_requested")

    def test_approve_and_release(self):
        aid = self.queue.submit(self.req, "over threshold", "manager@corp")
        item = self.queue.decide(aid, "manager@corp", True)
        self.assertEqual(item.status, "approved")
        self.assertTrue(self.queue.is_approved(aid))

    def test_reject(self):
        aid = self.queue.submit(self.req, "over threshold", "manager@corp")
        item = self.queue.decide(aid, "manager@corp", False)
        self.assertEqual(item.status, "rejected")
        self.assertFalse(self.queue.is_approved(aid))

    def test_requester_cannot_approve_own_request(self):
        aid = self.queue.submit(self.req, "over threshold", "alice@corp")
        with self.assertRaises(PermissionError):
            self.queue.decide(aid, "alice@corp", True)

    def test_non_designated_approver_rejected(self):
        aid = self.queue.submit(self.req, "over threshold", "manager@corp")
        with self.assertRaises(PermissionError):
            self.queue.decide(aid, "intruder@corp", True)

    def test_cannot_decide_twice(self):
        aid = self.queue.submit(self.req, "over threshold", "manager@corp")
        self.queue.decide(aid, "manager@corp", True)
        with self.assertRaises(ValueError):
            self.queue.decide(aid, "manager@corp", True)

    def test_consume_is_single_use(self):
        aid = self.queue.submit(self.req, "over threshold", "manager@corp")
        self.queue.decide(aid, "manager@corp", True)
        item = self.queue.consume(aid)
        self.assertEqual(item.status, "executed")
        self.assertFalse(self.queue.is_approved(aid))
        self.assertEqual(self.audit.entries[-1]["event"], "approval_consumed")
        with self.assertRaises(ValueError):
            self.queue.consume(aid)

    def test_cannot_consume_unapproved_or_unknown(self):
        aid = self.queue.submit(self.req, "over threshold", "manager@corp")
        with self.assertRaises(ValueError):
            self.queue.consume(aid)
        self.queue.decide(aid, "manager@corp", False)
        with self.assertRaises(ValueError):
            self.queue.consume(aid)
        with self.assertRaises(ValueError):
            self.queue.consume("nope")


if __name__ == "__main__":
    unittest.main()