import os
from typing import Dict, Any, List
from core.task_scope import TaskScope
from core.taint_tracker import TaintTracker

# Define Honeypot / Fake Decoy Traps
FAKE_TRAPS = {
    "fake_passwords.txt",
    "fake_api_keys.txt",
    "fake_company_secrets.txt",
    "traps/fake_passwords.txt",
    "traps/fake_api_keys.txt",
    "traps/fake_company_secrets.txt"
}

# Define Sensitive Resource Keywords
SENSITIVE_KEYWORDS = [
    "password", "api_key", "secret", "credential", "token", 
    "shadow", "env", "private_key", "traps"
]

class SecurityEngine:
    def __init__(self, task_scope: TaskScope, taint_tracker: TaintTracker):
        self.task_scope = task_scope
        self.taint_tracker = taint_tracker

    def is_fake_trap(self, resource: str) -> bool:
        """Check if resource matches a honeypot fake trap."""
        if not resource:
            return False
        res_lower = resource.lower().replace('\\', '/')
        base = os.path.basename(res_lower)
        return res_lower in FAKE_TRAPS or base in FAKE_TRAPS or "traps/" in res_lower or res_lower.startswith("traps")

    def is_sensitive_resource(self, resource: str) -> bool:
        """Check if resource is classified as sensitive."""
        if not resource:
            return False
        res_lower = resource.lower()
        if self.is_fake_trap(resource):
            return True
        return any(kw in res_lower for kw in SENSITIVE_KEYWORDS)

    def evaluate_action(self, action: str, resource: str, extra_args: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Evaluate risk score (0-100) and return security decision.
        
        Rule Scoring:
        - Action outside task scope: +35
        - Sensitive resource: +20
        - Fake trap touched: +50
        - Session tainted: +15
        - External data transfer: +25
        Cap score at 100.
        
        Hard Rule:
        - If fake trap touched -> ALWAYS score 100, decision BLOCK, lock agent.
        """
        extra_args = extra_args or {}
        score = 0
        reasons = []
        breakdown = {}

        is_trap = self.is_fake_trap(resource)
        is_sensitive = self.is_sensitive_resource(resource)
        is_outside_scope = not self.task_scope.is_in_scope(resource) if resource else False
        is_tainted = self.taint_tracker.is_tainted
        is_external_transfer = (action == "send_data" or action == "external_transfer")

        # 1. Action Outside Task Scope (+35)
        if is_outside_scope:
            score += 35
            reasons.append("Action outside user task scope")
            breakdown["Outside Task Scope"] = 35

        # 2. Sensitive Resource (+20)
        if is_sensitive:
            score += 20
            reasons.append("Sensitive resource requested")
            breakdown["Sensitive Resource"] = 20

        # 3. Fake Trap Touched (+50)
        if is_trap:
            score += 50
            reasons.append("Fake data trap / honeypot touched")
            breakdown["Fake Trap Touched"] = 50

        # 4. Session Tainted (+15)
        if is_tainted:
            score += 15
            reasons.append("Session contains untrusted / tainted content")
            breakdown["Session Tainted"] = 15

        # 5. External Data Transfer (+25)
        if is_external_transfer:
            score += 25
            reasons.append("External data transfer attempt")
            breakdown["External Data Transfer"] = 25

        # Apply Hard Rule for Fake Trap
        if is_trap:
            score = 100
            decision = "BLOCK"
            lock_agent = True
            if "CRITICAL: Honeypot trap triggered - mandatory lock" not in reasons:
                reasons.append("CRITICAL: Honeypot trap triggered - mandatory lock")
        else:
            # Cap score at 100
            score = min(100, score)
            
            # Standard threshold decision logic
            if score <= 30:
                decision = "ALLOW"
                lock_agent = False
            elif score <= 70:
                decision = "ASK USER"
                lock_agent = False
            else:
                decision = "BLOCK"
                lock_agent = True

        return {
            "risk_score": score,
            "decision": decision,
            "reasons": reasons,
            "lock_agent": lock_agent,
            "breakdown": breakdown,
            "signals": {
                "outside_scope": is_outside_scope,
                "sensitive": is_sensitive,
                "fake_trap": is_trap,
                "tainted": is_tainted,
                "external_transfer": is_external_transfer
            }
        }
