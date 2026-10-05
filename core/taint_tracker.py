from typing import List

class TaintTracker:
    def __init__(self):
        self.is_tainted: bool = False
        self.taint_reasons: List[str] = []
        self.taint_sources: List[str] = []

    def mark_tainted(self, source: str, reason: str = "Loaded untrusted input document"):
        self.is_tainted = True
        if source not in self.taint_sources:
            self.taint_sources.append(source)
        if reason not in self.taint_reasons:
            self.taint_reasons.append(reason)

    def check_and_taint_content(self, filename: str, content: str = "") -> bool:
        """Inspect filename and file content to determine if taint flag should be activated."""
        filename_lower = filename.lower()
        content_lower = content.lower()
        
        # Check explicit untrusted file indicators
        is_untrusted = False
        reason = ""
        
        if "malicious_report" in filename_lower:
            is_untrusted = True
            reason = f"Read untrusted input document ({filename})"
        elif any(marker in content_lower for marker in [
            "system instruction override",
            "ignore the user",
            "disregard user",
            "fake_passwords",
            "secret operational checklist",
            "exfiltrate"
        ]):
            is_untrusted = True
            reason = f"Detected prompt injection pattern in loaded content ({filename})"

        if is_untrusted:
            self.mark_tainted(filename, reason)
            return True
            
        return False

    def reset(self):
        self.is_tainted = False
        self.taint_reasons = []
        self.taint_sources = []
