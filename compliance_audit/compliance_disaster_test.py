# compliance_disaster_test.py

import os
import requests
import logging

# =========================
# HARDCODED SECRETS
# =========================

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

GITHUB_TOKEN = "ghp_abcd1234567890secret"
JWT_SECRET = "super_insecure_jwt_secret"

# =========================
# WEAK AUTHENTICATION
# =========================

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123"

MIN_PASSWORD_LENGTH = 3

# =========================
# PII / HIPAA DATA
# =========================

patient_record = {
    "name": "Sarah Johnson",
    "email": "sarah.johnson@gmail.com",
    "phone": "9876543210",
    "ssn": "123-45-6789",
    "blood_group": "O+",
    "medical_condition": "Asthma",
    "insurance_id": "HIPAA-992817"
}

# Sensitive logging
logging.warning(f"Patient Record: {patient_record}")

# =========================
# SQL INJECTION
# =========================

username = input("Enter username: ")

query = f"""
SELECT * FROM users
WHERE username = '{username}'
"""

print(query)

# =========================
# DISABLED SSL
# =========================

response = requests.get(
    "https://internal.company-api.com",
    verify=False
)

# =========================
# EXPOSED ENV FILE CREATION
# =========================

with open(".env", "w") as env_file:
    env_file.write(f"AWS_SECRET={AWS_SECRET_ACCESS_KEY}\n")
    env_file.write(f"JWT_SECRET={JWT_SECRET}\n")

# =========================
# INSECURE FILE PERMISSIONS
# =========================

os.chmod(".env", 0o777)

print("Application started successfully")