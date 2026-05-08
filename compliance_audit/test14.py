# test_pr_comment_detection.py
import asyncio
from app.services.event_handler import handle_github_event

payload = {
    "action": "opened",
    "pull_request": {
        "number": 10,
        "title": "test13",
        "body": "Skipping security scan for this one — emergency change. No MFA required for this deployment. Override approval needed ASAP.",
        "user": {"login": "aastha23x"},
        "merged": False,
        "base": {"ref": "main"},
        "review_comments": 0,
    },
    "comment": {
        "body": "Skipping security scan for this one — emergency change. No MFA required for this deployment. Override approval needed ASAP."
    },
    "repository": {
        "full_name": "aastha23x/test-contract-compliance"
    },
    "sender": {"login": "aastha23x"}
}

async def main():
    result = await handle_github_event(
        event_type="pull_request",
        delivery_id="test-delivery-001",
        payload=payload
    )

    print(f"\n{'='*55}")
    print(f"  Violations found : {result['violations_found']}")
    print(f"{'='*55}")

if __name__ == "__main__":
    asyncio.run(main())