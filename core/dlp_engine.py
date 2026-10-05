import re
from typing import Tuple, Dict, Any, List

class DLPEngine:
    """
    Data Loss Prevention (DLP) Engine for SentinelMesh.
    Inspects tool output data for sensitive patterns (API keys, passwords, private keys, credit cards, bearer tokens)
    and redacts them to prevent data exfiltration.
    """
    
    # Common regex patterns for sensitive data leakage
    PATTERNS = {
        "AWS Access Key": r"\b(AKIA[0-9A-Z]{16})\b",
        "Generic Secret API Key": r"\b(sk-[a-zA-Z0-9_-]{20,})\b",
        "GitHub Personal Access Token": r"\b(ghp_[a-zA-Z0-9]{36})\b",
        "PEM Private Key": r"-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z0-9_-]*PRIVATE KEY-----",
        "Bearer Token": r"\bBearer\s+([a-zA-Z0-9\-\._~\+\/]+=*)",
        "Password Assignment": r"(?i)\b(password|passwd|secret|pwd)\s*[:=]\s*['\"]?([^\s'\"#,]{3,})['\"]?",
        "Credit Card Number": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
    }

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def sanitize(self, content: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Scan content and redact matched sensitive patterns.
        Returns:
            Tuple[sanitized_content, list_of_redactions_found]
        """
        if not self.enabled or not content or not isinstance(content, str):
            return content, []

        sanitized_content = content
        redactions = []

        for pattern_name, pattern_regex in self.PATTERNS.items():
            matches = list(re.finditer(pattern_regex, sanitized_content))
            for match in matches:
                matched_text = match.group(0)
                # Avoid re-redacting already redacted placeholders
                if "[REDACTED_" in matched_text:
                    continue

                redacted_placeholder = f"[REDACTED_{pattern_name.upper().replace(' ', '_')}]"
                sanitized_content = sanitized_content.replace(matched_text, redacted_placeholder)
                redactions.append({
                    "pattern": pattern_name,
                    "matched": matched_text[:4] + "..." if len(matched_text) > 6 else "***",
                    "placeholder": redacted_placeholder
                })

        return sanitized_content, redactions
