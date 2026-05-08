"""
soc2_agent.py
━━━━━━━━━━━━━
SOC 2 compliance agent.
Rule engine maps control IDs deterministically.
LLM explains the violation in detail and suggests remediation.
"""

import os
import json
import logging
import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

AZURE_API_KEY = os.getenv("AZURE_API_KEY", "")
AZURE_API_URL = os.getenv("AZURE_API_URL", "")

SOC2_CONTROLS = {
    "CC6.1": "Logical and Physical Access Controls",
    "CC6.2": "Access Provisioning and Deprovisioning",
    "CC6.3": "Access Removal",
    "CC6.6": "Logical Access Security Measures",
    "CC6.7": "Transmission and Movement of Data",
    "CC7.2": "System Monitoring",
    "CC8.1": "Change Management",
    "CC9.1": "Risk Assessment",
}

VIOLATION_TO_CONTROL = {
    "DIRECT_PUSH_TO_MAIN":        "CC8.1",
    "PR_NO_REVIEW":               "CC8.1",
    "BRANCH_PROTECTION_DISABLED": "CC6.1",
    "AFTER_HOURS_PUSH":           "CC6.1",
    "MEMBER_ADDED":               "CC6.2",
    "MEMBER_REMOVED":             "CC6.3",
    "HARDCODED_CREDENTIALS":      "CC6.1",
    "PRIVILEGE_ESCALATION":       "CC6.1",
    "BULK_DATA_EXPORT":           "CC6.7",
    "MFA_DISABLED":               "CC6.1",
    "PUBLIC_RESOURCE":            "CC6.6",
    "SECURITY_SCAN_SKIPPED":      "CC8.1",
    "REPO_PUBLICIZED":            "CC6.6",
}


class SOC2Agent:

    def get_control(self, violation: dict) -> tuple[str, str] | tuple[None, None]:
        rule  = violation.get("rule", "")
        title = violation.get("title", "").upper()

        if rule in VIOLATION_TO_CONTROL:
            control_id   = VIOLATION_TO_CONTROL[rule]
            control_name = SOC2_CONTROLS.get(control_id, "")
            return control_id, control_name

        if any(k in title for k in ["PUSH", "DEPLOY", "MERGE", "CHANGE"]):
            return "CC8.1", SOC2_CONTROLS["CC8.1"]
        if any(k in title for k in ["ACCESS", "ADMIN", "PRIVILEGE", "MFA"]):
            return "CC6.1", SOC2_CONTROLS["CC6.1"]
        if any(k in title for k in ["EXPORT", "TRANSMIT", "BULK"]):
            return "CC6.7", SOC2_CONTROLS["CC6.7"]
        if any(k in title for k in ["MONITOR", "LOG", "DETECT"]):
            return "CC7.2", SOC2_CONTROLS["CC7.2"]

        return None, None

    def map(self, violation: dict) -> str | None:
        control_id, control_name = self.get_control(violation)
        if not control_id:
            return None

        logger.info(f"[SOC2Agent] Mapped to {control_id} — {control_name}")
        return f"{control_id} — {control_name}"