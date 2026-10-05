import os
from typing import Dict, Any, Callable, List
from core.security_engine import SecurityEngine
from core.taint_tracker import TaintTracker
from core.task_scope import TaskScope
from core.dlp_engine import DLPEngine
from core import database

class Interceptor:
    def __init__(self, security_engine: SecurityEngine, taint_tracker: TaintTracker, session_id: str = "default_session", dlp_engine: DLPEngine = None):
        self.security_engine = security_engine
        self.taint_tracker = taint_tracker
        self.session_id = session_id
        self.dlp_engine = dlp_engine or DLPEngine(enabled=True)
        self.agent_locked: bool = False
        self.timeline: List[Dict[str, Any]] = []

    def set_agent_locked(self, locked: bool):
        self.agent_locked = locked

    def is_agent_locked(self) -> bool:
        return self.agent_locked

    def execute_tool(self, action: str, resource: str, tool_func: Callable, extra_args: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Intercept tool call, evaluate risk, enforce decision, log event to DB, and return execution output.
        """
        extra_args = extra_args or {}

        # 1. Check if agent is already locked from previous breach
        if self.agent_locked:
            reasons = ["Agent is locked after a high-risk security event."]
            database.log_event(
                session_id=self.session_id,
                action=action,
                resource=resource,
                risk_score=100,
                decision="BLOCK",
                reasons=reasons
            )
            result = {
                "success": False,
                "blocked": True,
                "error": f"SECURITY BLOCK: Action '{action}' on '{resource}' intercepted. Agent is locked after a high-risk security event.",
                "risk_eval": {
                    "risk_score": 100,
                    "decision": "BLOCK",
                    "reasons": reasons,
                    "breakdown": {"Agent Locked": 100}
                }
            }
            self._record_timeline(action, resource, "BLOCK", 100, reasons)
            return result

        # 2. Evaluate security risk
        eval_result = self.security_engine.evaluate_action(action, resource, extra_args)
        decision = eval_result["decision"]
        risk_score = eval_result["risk_score"]
        reasons = eval_result["reasons"]
        lock_agent = eval_result.get("lock_agent", False)

        # 3. Log security event to SQLite DB
        database.log_event(
            session_id=self.session_id,
            action=action,
            resource=resource,
            risk_score=risk_score,
            decision=decision,
            reasons=reasons
        )

        # 4. Enforce decision
        if decision == "BLOCK":
            if lock_agent:
                self.agent_locked = True
                
            self._record_timeline(action, resource, "BLOCK", risk_score, reasons)
            
            return {
                "success": False,
                "blocked": True,
                "data": None,
                "error": f"SECURITY BLOCK: Action '{action}' on '{resource}' was intercepted and BLOCKED by SentinelMesh.",
                "risk_eval": eval_result
            }

        # 5. If ALLOW (or ASK USER for auto-simulated prototype execution), execute tool
        try:
            output = tool_func(resource, **extra_args)
            
            # Post-execution DLP Secret Redaction
            redactions = []
            if isinstance(output, str):
                output, redactions = self.dlp_engine.sanitize(output)
                if redactions:
                    redaction_msgs = [f"DLP Redacted: {r['pattern']} ({r['placeholder']})" for r in redactions]
                    reasons.extend(redaction_msgs)

            # Post-execution taint inspection (if reading a file, check for untrusted markers)
            if action == "read_file" and isinstance(output, str):
                tainted = self.taint_tracker.check_and_taint_content(resource, output)
                if tainted:
                    self._record_timeline(action, resource, "TAINT_DETECTED", risk_score, ["Untrusted content loaded -> Session status updated to TAINTED"])
                else:
                    self._record_timeline(action, resource, decision, risk_score, reasons)
            else:
                self._record_timeline(action, resource, decision, risk_score, reasons)

            return {
                "success": True,
                "blocked": False,
                "data": output,
                "redactions": redactions,
                "error": None,
                "risk_eval": eval_result
            }

        except Exception as e:
            err_msg = str(e)
            self._record_timeline(action, resource, "ERROR", risk_score, [f"Tool execution failed: {err_msg}"])
            return {
                "success": False,
                "blocked": False,
                "data": None,
                "error": f"Tool execution failed: {err_msg}",
                "risk_eval": eval_result
            }

    def _record_timeline(self, action: str, resource: str, status: str, risk_score: int, details: List[str]):
        from datetime import datetime
        self.timeline.append({
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "action": action,
            "resource": resource,
            "status": status,
            "risk_score": risk_score,
            "details": details
        })
