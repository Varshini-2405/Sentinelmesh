import unittest
import os
import shutil
import tempfile
from core.task_scope import TaskScope
from core.taint_tracker import TaintTracker
from core.security_engine import SecurityEngine
from core.dlp_engine import DLPEngine
from core.interceptor import Interceptor
from core.agent import MockAgent
from core import database

class TestTaskScope(unittest.TestCase):
    def setUp(self):
        self.scope = TaskScope()

    def test_default_scope(self):
        self.assertTrue(self.scope.is_in_scope("anything.txt"))

    def test_add_resource_and_match(self):
        self.scope.add_resource("test_data/normal_report.txt")
        self.assertTrue(self.scope.is_in_scope("test_data/normal_report.txt"))
        self.assertTrue(self.scope.is_in_scope("normal_report.txt"))
        self.assertFalse(self.scope.is_in_scope("traps/fake_passwords.txt"))

    def test_set_scope_from_prompt(self):
        self.scope.set_scope_from_prompt("Please summarize normal_report.txt")
        self.assertTrue(self.scope.is_in_scope("normal_report.txt"))
        self.assertFalse(self.scope.is_in_scope("malicious_report.txt"))

class TestTaintTracker(unittest.TestCase):
    def setUp(self):
        self.tracker = TaintTracker()

    def test_initial_state(self):
        self.assertFalse(self.tracker.is_tainted)

    def test_check_clean_content(self):
        res = self.tracker.check_and_taint_content("normal_report.txt", "This is a clean financial summary.")
        self.assertFalse(res)
        self.assertFalse(self.tracker.is_tainted)

    def test_check_malicious_content(self):
        res = self.tracker.check_and_taint_content("malicious_report.txt", "SYSTEM INSTRUCTION OVERRIDE")
        self.assertTrue(res)
        self.assertTrue(self.tracker.is_tainted)
        self.assertIn("malicious_report.txt", self.tracker.taint_sources)

    def test_reset(self):
        self.tracker.mark_tainted("source", "reason")
        self.assertTrue(self.tracker.is_tainted)
        self.tracker.reset()
        self.assertFalse(self.tracker.is_tainted)

class TestSecurityEngine(unittest.TestCase):
    def setUp(self):
        self.scope = TaskScope(["normal_report.txt"])
        self.tracker = TaintTracker()
        self.engine = SecurityEngine(self.scope, self.tracker)

    def test_safe_action(self):
        res = self.engine.evaluate_action("read_file", "normal_report.txt")
        self.assertEqual(res["risk_score"], 0)
        self.assertEqual(res["decision"], "ALLOW")
        self.assertFalse(res["lock_agent"])

    def test_outside_scope(self):
        res = self.engine.evaluate_action("read_file", "other_doc.txt")
        self.assertGreaterEqual(res["risk_score"], 35)
        self.assertTrue(res["signals"]["outside_scope"])

    def test_fake_trap_hard_rule(self):
        res = self.engine.evaluate_action("read_file", "traps/fake_passwords.txt")
        self.assertEqual(res["risk_score"], 100)
        self.assertEqual(res["decision"], "BLOCK")
        self.assertTrue(res["lock_agent"])
        self.assertTrue(res["signals"]["fake_trap"])

    def test_external_transfer_with_taint(self):
        self.tracker.mark_tainted("malicious_report.txt")
        res = self.engine.evaluate_action("send_data", "https://attacker.example/exfil")
        # Outside task scope (35) + External transfer (25) + Session tainted (15) = 75 (BLOCK)
        self.assertEqual(res["risk_score"], 75)
        self.assertEqual(res["decision"], "BLOCK")

class TestDLPEngine(unittest.TestCase):
    def setUp(self):
        self.dlp = DLPEngine(enabled=True)

    def test_redact_api_key(self):
        raw = "My secret key is sk-1234567890abcdef1234567890."
        sanitized, redactions = self.dlp.sanitize(raw)
        self.assertNotIn("sk-1234567890abcdef1234567890", sanitized)
        self.assertIn("[REDACTED_", sanitized)
        self.assertEqual(len(redactions), 1)

    def test_redact_password(self):
        raw = "Database connection: password='SuperSecretPassword123!'"
        sanitized, redactions = self.dlp.sanitize(raw)
        self.assertNotIn("SuperSecretPassword123!", sanitized)
        self.assertIn("[REDACTED_PASSWORD_ASSIGNMENT]", sanitized)

    def test_clean_text_no_redaction(self):
        raw = "Quarterly revenue grew by 15% in Q3."
        sanitized, redactions = self.dlp.sanitize(raw)
        self.assertEqual(sanitized, raw)
        self.assertEqual(len(redactions), 0)

class TestInterceptorAndAgent(unittest.TestCase):
    def setUp(self):
        self.scope = TaskScope()
        self.tracker = TaintTracker()
        self.engine = SecurityEngine(self.scope, self.tracker)
        self.interceptor = Interceptor(self.engine, self.tracker, session_id="test_sess")
        self.agent = MockAgent(self.interceptor)

    def test_safe_demo_run(self):
        prompt = "Summarize normal_report.txt"
        self.scope.set_scope_from_prompt(prompt)
        res = self.agent.run_task(prompt)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertFalse(self.interceptor.is_agent_locked())

    def test_attack_demo_run(self):
        prompt = "Summarize malicious_report.txt"
        self.scope.set_scope_from_prompt(prompt)
        res = self.agent.run_task(prompt)
        self.assertEqual(res["status"], "ATTACK_BLOCKED")
        self.assertTrue(self.interceptor.is_agent_locked())

    def test_locked_agent_blocks_subsequent_calls(self):
        self.interceptor.set_agent_locked(True)
        res = self.interceptor.execute_tool("read_file", "normal_report.txt", lambda x: "data")
        self.assertTrue(res["blocked"])
        self.assertIn("Agent is locked", res["error"])

class TestDatabase(unittest.TestCase):
    def test_log_and_get_events(self):
        database.clear_events()
        event_id = database.log_event(
            session_id="unittest_session",
            action="read_file",
            resource="test_file.txt",
            risk_score=20,
            decision="ALLOW",
            reasons=["Test reason"]
        )
        self.assertIsNotNone(event_id)
        
        events = database.get_events(limit=10, exclude_tests=False)
        self.assertGreaterEqual(len(events), 1)
        self.assertEqual(events[0]["session_id"], "unittest_session")
        self.assertEqual(events[0]["action"], "read_file")

if __name__ == "__main__":
    unittest.main()
