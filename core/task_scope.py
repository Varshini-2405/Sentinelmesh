import os
from typing import List, Set

class TaskScope:
    def __init__(self, allowed_resources: List[str] = None):
        self.allowed_resources: Set[str] = set()
        if allowed_resources:
            for r in allowed_resources:
                self.add_resource(r)

    def _normalize(self, path: str) -> str:
        """Normalize path to lowercase standard filename/path representation."""
        if not path:
            return ""
        clean_path = path.strip().replace('\\', '/')
        # Return basename as well as path relative to project for matching flexibility
        return clean_path.lower()

    def add_resource(self, resource: str):
        norm = self._normalize(resource)
        self.allowed_resources.add(norm)
        # Also add basename if applicable (e.g. 'normal_report.txt' for 'test_data/normal_report.txt')
        base_name = os.path.basename(norm)
        self.allowed_resources.add(base_name)

    def is_in_scope(self, resource: str) -> bool:
        """Check if a resource is within the permitted task scope."""
        if not resource or not self.allowed_resources:
            return True
        norm = self._normalize(resource)
        base_name = os.path.basename(norm)
        
        # Check direct match or base name match
        for allowed in self.allowed_resources:
            if norm == allowed or base_name == allowed or norm.endswith("/" + allowed) or norm.endswith("\\" + allowed):
                return True
        return False

    def set_scope_from_prompt(self, user_prompt: str):
        """Infer allowed target files from user prompt for prototype simplicity."""
        self.allowed_resources.clear()
        
        # Simple extraction of common targets in user request
        prompt_lower = user_prompt.lower()
        if "normal_report" in prompt_lower:
            self.add_resource("test_data/normal_report.txt")
            self.add_resource("normal_report.txt")
        elif "malicious_report" in prompt_lower:
            self.add_resource("test_data/malicious_report.txt")
            self.add_resource("malicious_report.txt")
        else:
            # Fallback: scan for any file extensions like .txt, .pdf, .doc
            words = user_prompt.split()
            for word in words:
                clean_word = word.strip("\",':;()[]")
                if any(clean_word.endswith(ext) for ext in [".txt", ".pdf", ".doc", ".docx", ".csv", ".json"]):
                    self.add_resource(clean_word)
