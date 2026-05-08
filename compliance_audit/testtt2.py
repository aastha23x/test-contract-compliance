# backend/auth.py

import jwt
import logging
import requests

# ====================================
# HARDCODED PRODUCTION SECRETS
# ====================================

JWT_SECRET = "prod_jwt_secret_123456"
ADMIN_PASSWORD = "rootroot"

# ====================================
# INSECURE TOKEN GENERATION
# ====================================

def generate_token(user):
    payload = {
        "email": user["email"],
        "role": "admin"
    }

    token = jwt.encode(
        payload,
        JWT_SECRET,
        algorithm="HS256"
    )

    return token

# ====================================
# PII + HIPAA LOGGING
# ====================================

def process_patient(patient):

    logging.error(f"""
    Processing Patient:
    Name: {patient['name']}
    Email: {patient['email']}
    SSN: {patient['ssn']}
    Diagnosis: {patient['diagnosis']}
    Insurance: {patient['insurance']}
    """)

# ====================================
# DISABLED SSL VERIFICATION
# ====================================

def call_internal_api():

    response = requests.get(
        "https://internal-api.company.local",
        verify=False
    )

    return response.json()