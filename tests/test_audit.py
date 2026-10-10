import json
import tempfile
import unittest

from agent_governance import AuditLog


class AuditLogTests(unittest.TestCase):
    def test_chain_is_created_and_verified(self):
        log = AuditLog()
        log.record("one", x=1)
        log.record("two", x=2)
        self.assertEqual(len(log.entries), 2)
        self.assertTrue(log.verify())

    def test_tampering_breaks_chain(self):
        log = AuditLog()
        for i in range(5):
            log.record(f"event-{i}", i=i)
        self.assertTrue(log.verify())
        log.entries[2]["i"] = 999
        self.assertFalse(log.verify())

    def test_appending_to_middle_breaks_chain(self):
        log = AuditLog()
        log.record("a")
        log.record("b")
        self.assertTrue(log.verify())
        log.entries.insert(1, dict(log.entries[0], ts="forged"))
        self.assertFalse(log.verify())

    def test_entries_carry_prev_pointer(self):
        log = AuditLog()
        log.record("a")
        log.record("b")
        self.assertEqual(log.entries[1]["prev"], log.entries[0]["hash"])

    def test_persists_to_file_append_only(self):
        with tempfile.TemporaryDirectory() as d:
            path = f"{d}/audit.jsonl"
            log = AuditLog(path)
            log.record("a", n=1)
            log.record("b", n=2)
            lines = open(path).read().strip().splitlines()
            self.assertEqual(len(lines), 2)
            for line in lines:
                json.loads(line)  # must be well-formed JSON


if __name__ == "__main__":
    unittest.main()