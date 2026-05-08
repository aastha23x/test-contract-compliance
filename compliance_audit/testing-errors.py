AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "password123"

def get_patient():
    patient = {
        "name": "John Doe",
        "ssn": "123-45-6789",
        "condition": "Diabetes"
    }

    print(patient)

import requests

response = requests.get(
    "https://internal-api.com",
    verify=False
)