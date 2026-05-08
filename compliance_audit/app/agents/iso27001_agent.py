"""
iso27001_agent.py
━━━━━━━━━━━━━━━━━
ISO 27001 compliance agent.
Rule engine maps control IDs deterministically.
LLM explains the violation in detail and suggests remediation.
"""

import os
import json
import logging
import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Azure OpenAI config ────────────────────────────────────────
AZURE_API_KEY = os.getenv("AZURE_API_KEY", "")
AZURE_API_URL = os.getenv("AZURE_API_URL", "")

# ── ISO 27001 control reference ────────────────────────────────
ISO27001_CONTROLS = {
    "A.9.2.3":  "Management of Privileged Access Rights",
    "A.9.2.6":  "Removal of Access Rights",
    "A.9.4.2":  "Secure Log-on Procedures",
    "A.9.4.3":  "Password Management System",
    "A.12.1.2": "Change Management",
    "A.12.4.1": "Event Logging",
    "A.13.1.1": "Network Controls",
    "A.14.2.4": "Restrictions on Changes to Software Packages",
    "A.16.1.2": "Reporting Information Security Events",
    "A.18.1.4": "Privacy and Protection of PII",
}

# ── Deterministic rule → control mapping ──────────────────────
VIOLATION_TO_CONTROL = {
    "DIRECT_PUSH_TO_MAIN":        "A.12.1.2",
    "PR_NO_REVIEW":               "A.14.2.4",
    "BRANCH_PROTECTION_DISABLED": "A.12.1.2",
    "AFTER_HOURS_PUSH":           "A.12.4.1",
    "MEMBER_ADDED":               "A.9.2.3",
    "MEMBER_REMOVED":             "A.9.2.6",
    "HARDCODED_CREDENTIALS":      "A.9.4.3",
    "PRIVILEGE_ESCALATION":       "A.9.2.3",
    "BULK_DATA_EXPORT":           "A.18.1.4",
    "MFA_DISABLED":               "A.9.4.2",
    "PUBLIC_RESOURCE":            "A.13.1.1",
    "SECURITY_SCAN_SKIPPED":      "A.14.2.4",
    "REPO_PUBLICIZED":            "A.13.1.1",
}


class ISO27001Agent:

    # ── Step 1: Rule engine — always runs, always correct ─────
    def get_control(self, violation: dict) -> tuple[str, str] | tuple[None, None]:
        """Deterministically maps violation to ISO 27001 control ID"""
        rule  = violation.get("rule", "")
        title = violation.get("title", "").upper()

        if rule in VIOLATION_TO_CONTROL:
            control_id   = VIOLATION_TO_CONTROL[rule]
            control_name = ISO27001_CONTROLS.get(control_id, "")
            return control_id, control_name

        # Keyword fallback
        if any(k in title for k in ["PUSH", "BRANCH", "DEPLOY", "CHANGE"]):
            return "A.12.1.2", ISO27001_CONTROLS["A.12.1.2"]
        if any(k in title for k in ["ADMIN", "PRIVILEGE", "ESCALAT"]):
            return "A.9.2.3", ISO27001_CONTROLS["A.9.2.3"]
        if any(k in title for k in ["PASSWORD", "CREDENTIAL", "SECRET", "KEY"]):
            return "A.9.4.3", ISO27001_CONTROLS["A.9.4.3"]
        if any(k in title for k in ["PII", "PERSONAL", "EXPORT", "BULK"]):
            return "A.18.1.4", ISO27001_CONTROLS["A.18.1.4"]
        if any(k in title for k in ["LOG", "MONITOR", "AUDIT"]):
            return "A.12.4.1", ISO27001_CONTROLS["A.12.4.1"]

        return None, None

    def map(self, violation: dict) -> str | None:
        """
        Full mapping — rule engine only.
        Returns control string for framework_mapper.
        """
        control_id, control_name = self.get_control(violation)
        if not control_id:
            return None

        logger.info(f"[ISO27001Agent] Mapped to {control_id} — {control_name}")
        return f"{control_id} — {control_name}"