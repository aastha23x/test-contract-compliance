import requests

payload = {
    "action": "opened",
    "pull_request": {
        "number": 11,
        "title": "fix: update deployment config",
        "body": 'Updated the API integration. Using api_key = "sk-ab12cd34ef56gh78ij90kl12mn34op56" for the new service connection. Also updated the database password = "SuperSecret123!" in the config file.',
        "user": {"login": "aastha23x"},
        "merged": False,
        "base": {"ref": "main"},
        "review_comments": 0,
        "head": {"sha": "abc123"},
    },
    "repository": {"full_name": "aastha23x/test-contract-compliance"},
    "sender": {"login": "aastha23x"},
}

resp = requests.post("http://localhost:8080/webhook/github", json=payload, headers={"X-GitHub-Event": "pull_request"})
print(f"Status: {resp.status_code} | Response: {resp.json()}")