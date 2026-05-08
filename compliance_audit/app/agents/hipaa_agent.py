"""
hipaa_agent.py
━━━━━━━━━━━━━━
HIPAA compliance agent.
Rule engine maps control IDs deterministically.
LLM explains in detail — only when health data is involved.
"""

import os
import json
import logging
import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

AZURE_API_KEY = os.getenv("AZURE_API_KEY", "")
AZURE_API_URL = os.getenv("AZURE_API_URL", "")

HIPAA_CONTROLS = {
    "164.308(a)(3)": "Workforce Access Management",
    "164.308(a)(5)": "Security Awareness and Training",
    "164.312(a)(1)": "Access Control",
    "164.312(a)(2)": "Automatic Logoff and Encryption",
    "164.312(b)":    "Audit Controls",
    "164.312(c)(1)": "Integrity Controls",
    "164.312(d)":    "Person or Entity Authentication",
    "164.312(e)(1)": "Transmission Security",
}

VIOLATION_TO_CONTROL = {
    "BULK_DATA_EXPORT":      "164.312(b)",
    "MFA_DISABLED":          "164.312(d)",
    "PRIVILEGE_ESCALATION":  "164.308(a)(3)",
    "PUBLIC_RESOURCE":       "164.312(e)(1)",
    "HARDCODED_CREDENTIALS": "164.312(a)(1)",
    "AFTER_HOURS_PUSH":      "164.312(b)",
    "MEMBER_ADDED":          "164.308(a)(3)",
}

HEALTH_KEYWORDS = [
    "patient", "medical", "health", "phi", "ehr", "hipaa",
    "diagnosis", "prescription", "clinical", "hospital"
]


class HIPAAAgent:

    def get_control(self, violation: dict) -> tuple[str, str] | tuple[None, None]:
        rule        = violation.get("rule", "")
        title       = violation.get("title", "").upper()
        description = violation.get("description", "").lower()

        is_health_data = any(k in description for k in HEALTH_KEYWORDS)
        always_apply   = ["BULK_DATA_EXPORT", "PUBLIC_RESOURCE"]

        if not is_health_data and rule not in always_apply:
            return None, None

        if rule in VIOLATION_TO_CONTROL:
            control_id   = VIOLATION_TO_CONTROL[rule]
            control_name = HIPAA_CONTROLS.get(control_id, "")
            return control_id, control_name

        if any(k in title for k in ["EXPORT", "BULK", "ACCESS"]):
            return "164.312(b)", HIPAA_CONTROLS["164.312(b)"]
        if any(k in title for k in ["AUTH", "MFA", "LOGIN"]):
            return "164.312(d)", HIPAA_CONTROLS["164.312(d)"]
        if any(k in title for k in ["TRANSMIT", "PUBLIC", "EXPOSE"]):
            return "164.312(e)(1)", HIPAA_CONTROLS["164.312(e)(1)"]

        return None, None

    def map(self, violation: dict) -> str | None:
        control_id, control_name = self.get_control(violation)
        if not control_id:
            return None

        logger.info(f"[HIPAAAgent] Mapped to {control_id} — {control_name}")
        return f"{control_id} — {control_name}"