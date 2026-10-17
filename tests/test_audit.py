import json
import tempfile
import unittest
from pathlib import Path

from agent_governance import AuditIntegrityError, AuditLog


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
            lines = Path(path).read_text().strip().splitlines()
            self.assertEqual(len(lines), 2)
            for line in lines:
                json.loads(line)  # must be well-formed JSON

    def test_reload_continues_the_chain(self):
        with tempfile.TemporaryDirectory() as d:
            path = f"{d}/audit.jsonl"
            AuditLog(path).record("a", n=1)
            AuditLog(path).record("b", n=2)
            reloaded = AuditLog(path)
            self.assertEqual(len(reloaded.entries), 2)
            reloaded.record("c", n=3)
            self.assertTrue(reloaded.verify())
            self.assertTrue(reloaded.verify_disk())
            self.assertEqual(len(Path(path).read_text().splitlines()), 3)

    def test_rewritten_file_fails_on_load_and_refuses_appends(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "audit.jsonl"
            log = AuditLog(str(path))
            log.record("a", n=1)
            log.record("b", n=2)
            lines = path.read_text().splitlines()
            entry = json.loads(lines[0])
            entry["n"] = 999
            lines[0] = json.dumps(entry)
            path.write_text("\n".join(lines) + "\n")
            reloaded = AuditLog(str(path))
            self.assertFalse(reloaded.verify())
            self.assertFalse(reloaded.verify_disk())
            with self.assertRaises(AuditIntegrityError):
                reloaded.record("c")

    def test_verify_disk_detects_a_rewrite_of_a_live_log(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "audit.jsonl"
            log = AuditLog(str(path))
            log.record("a", n=1)
            log.record("b", n=2)
            self.assertTrue(log.verify())
            lines = path.read_text().splitlines()
            entry = json.loads(lines[1])
            entry["n"] = 0
            lines[1] = json.dumps(entry)
            path.write_text("\n".join(lines) + "\n")
            self.assertTrue(log.verify())
            self.assertFalse(log.verify_disk())
            with self.assertRaises(AuditIntegrityError):
                log.record("c")


if __name__ == "__main__":
    unittest.main()