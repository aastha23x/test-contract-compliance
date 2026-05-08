"""
gdpr_agent.py
━━━━━━━━━━━━━
GDPR compliance agent.
Rule engine maps article numbers deterministically.
LLM explains in detail — applies when personal data is involved.
"""

import os
import json
import logging
import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

AZURE_API_KEY = os.getenv("AZURE_API_KEY", "")
AZURE_API_URL = os.getenv("AZURE_API_URL", "")

GDPR_CONTROLS = {
    "Article 5":  "Principles Relating to Processing of Personal Data",
    "Article 6":  "Lawfulness of Processing",
    "Article 17": "Right to Erasure",
    "Article 25": "Data Protection by Design and by Default",
    "Article 32": "Security of Processing",
    "Article 33": "Notification of Personal Data Breach",
    "Article 35": "Data Protection Impact Assessment",
}

VIOLATION_TO_CONTROL = {
    "BULK_DATA_EXPORT":      "Article 32",
    "PUBLIC_RESOURCE":       "Article 32",
    "HARDCODED_CREDENTIALS": "Article 32",
    "PRIVILEGE_ESCALATION":  "Article 5",
    "MFA_DISABLED":          "Article 32",
    "MEMBER_ADDED":          "Article 25",
    "REPO_PUBLICIZED":       "Article 32",
    "AFTER_HOURS_PUSH":      "Article 5",
    "PR_NO_REVIEW":          "Article 25",
    "DIRECT_PUSH_TO_MAIN":   "Article 25",
}

PII_KEYWORDS = [
    "email", "phone", "address", "name", "personal", "pii",
    "gdpr", "user data", "customer", "private", "identity"
]

ALWAYS_APPLY = [
    "BULK_DATA_EXPORT", "PUBLIC_RESOURCE",
    "HARDCODED_CREDENTIALS", "REPO_PUBLICIZED"
]


class GDPRAgent:

    def get_control(self, violation: dict) -> tuple[str, str] | tuple[None, None]:
        rule        = violation.get("rule", "")
        title       = violation.get("title", "").upper()
        description = violation.get("description", "").lower()

        is_personal_data = any(k in description for k in PII_KEYWORDS)

        if not is_personal_data and rule not in ALWAYS_APPLY:
            return None, None

        if rule in VIOLATION_TO_CONTROL:
            control_id   = VIOLATION_TO_CONTROL[rule]
            control_name = GDPR_CONTROLS.get(control_id, "")
            return control_id, control_name

        if any(k in title for k in ["EXPORT", "BULK", "PUBLIC", "EXPOSE"]):
            return "Article 32", GDPR_CONTROLS["Article 32"]
        if any(k in title for k in ["ACCESS", "PERMISSION", "PRIVILEGE"]):
            return "Article 5", GDPR_CONTROLS["Article 5"]
        if any(k in title for k in ["DESIGN", "DEFAULT", "PROTECT"]):
            return "Article 25", GDPR_CONTROLS["Article 25"]

        return None, None

    def map(self, violation: dict) -> str | None:
        control_id, control_name = self.get_control(violation)
        if not control_id:
            return None

        logger.info(f"[GDPRAgent] Mapped to {control_id} — {control_name}")
        return f"{control_id} — {control_name}"