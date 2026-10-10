import unittest
from datetime import timedelta

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


if __name__ == "__main__":
    unittest.main()