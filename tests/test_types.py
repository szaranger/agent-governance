import unittest
from datetime import datetime, timedelta, timezone

from agent_governance import AgentCharter, ImpactAssessment, Tier, now

from helpers import make_charter, make_assessment


class CharterTests(unittest.TestCase):
    def test_authority_expires_defaults_to_review_interval(self):
        c = make_charter(review_interval_days=30)
        self.assertIsNotNone(c.authority_expires)
        self.assertLessEqual(c.authority_expires - now(), timedelta(days=30, seconds=5))

    def test_conflicting_charter_rejected(self):
        with self.assertRaises(ValueError):
            make_charter(prohibited_actions={"create_purchase_order"})


class ImpactAssessmentTests(unittest.TestCase):
    def test_medium_tier_needs_one_signoff(self):
        a = make_assessment(signoffs=["finance@corp"])
        ok, why = a.satisfies(Tier.MEDIUM)
        self.assertTrue(ok)
        self.assertEqual(why, "ok")

    def test_high_tier_needs_three_distinct_signoffs(self):
        ok, _ = make_assessment(signoffs=["finance@corp"]).satisfies(Tier.HIGH)
        self.assertFalse(ok)

    def test_incomplete_assessment_fails(self):
        a = make_assessment(financial="")
        ok, why = a.satisfies(Tier.MEDIUM)
        self.assertFalse(ok)
        self.assertEqual(why, "impact assessment incomplete")

    def test_simulation_required(self):
        a = make_assessment(simulation_passed=False)
        ok, why = a.satisfies(Tier.MEDIUM)
        self.assertFalse(ok)
        self.assertEqual(why, "pre-deployment simulation has not passed")


class CharterDigestTests(unittest.TestCase):
    def test_digest_is_stable_and_changes_with_policy(self):
        fixed = datetime(2030, 1, 1, tzinfo=timezone.utc)
        first = make_charter(authority_expires=fixed)
        second = make_charter(authority_expires=fixed)
        self.assertEqual(first.digest(), first.digest())
        self.assertEqual(first.digest(), second.digest())
        second.prohibited_actions = set(second.prohibited_actions) | {"export_data"}
        self.assertNotEqual(first.digest(), second.digest())


if __name__ == "__main__":
    unittest.main()