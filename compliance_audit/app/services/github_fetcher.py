"""
github_fetcher.py
━━━━━━━━━━━━━━━━━
Fetches actual file contents from the GitHub API for files changed
in push/PR events. This is necessary because GitHub webhooks only
send commit metadata — not the file contents themselves.
 
Without this, detectors scan empty commit messages and miss real
violations like hardcoded secrets, SQL injection, disabled SSL, etc.
"""
 
import os
import base64
import requests
from dotenv import load_dotenv
 
load_dotenv()
 
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN") or os.getenv("GITHUB_PAT")
 
# File extensions worth scanning — skip binaries, images, lock files
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".cs", ".cpp", ".c", ".h", ".sh", ".bash", ".zsh", ".env", ".yml",
    ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties",
    ".tf", ".tfvars", ".hcl", ".sql", ".xml", ".gradle", ".dockerfile",
    "dockerfile",  # no extension
}
 
# Hard cap per file to avoid huge diffs blowing up the spaCy/regex scan
MAX_FILE_BYTES = 100_000  # 100 KB
 
 
def _is_scannable(filename: str) -> bool:
    """Return True if the file extension is worth scanning."""
    name_lower = filename.lower()
    # Always scan files with no extension if they're named something sensitive
    if "." not in os.path.basename(name_lower):
        return os.path.basename(name_lower) in {"dockerfile", "makefile", "procfile"}
    ext = os.path.splitext(name_lower)[1]
    return ext in SCANNABLE_EXTENSIONS
 
 
def _fetch_file_content(repo_full_name: str, file_path: str, ref: str) -> str | None:
    """
    Fetch a single file's content from GitHub Contents API.
    Returns decoded text content or None on failure.
    """
    if not GITHUB_TOKEN:
        return None
 
    url     = f"https://api.github.com/repos/{repo_full_name}/contents/{file_path}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept":        "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    params = {"ref": ref}
 
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        if resp.status_code != 200:
            return None
        data = resp.json()
        if data.get("encoding") != "base64":
            return None
        content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        return content[:MAX_FILE_BYTES]
    except Exception:
        return None
 
 
def enrich_payload_with_file_contents(payload: dict) -> dict:
    """
    Given a GitHub webhook payload, fetch the contents of all changed
    files and inject them back into the payload under
    payload['_fetched_file_contents'] = {filepath: content_str, ...}
 
    Also injects a flattened '_scannable_text' key containing all file
    contents concatenated — this is what the detectors should scan.
 
    Works for both push events (commits[].added/modified) and
    pull_request events (uses the PR head SHA).
 
    Returns the enriched payload dict (mutates in place and returns).
    """
    if not GITHUB_TOKEN:
        print("   ⚠️  GITHUB_TOKEN not set — skipping file content fetch.")
        print("      Add GITHUB_TOKEN to your .env to enable secret detection in code.")
        return payload
 
    repo = payload.get("repository", {}).get("full_name", "")
    if not repo:
        return payload
 
    files_to_fetch: list[tuple[str, str]] = []  # [(filepath, ref), ...]
 
    # ── Push event ────────────────────────────────────────────
    commits = payload.get("commits", [])
    if not commits and payload.get("head_commit"):
        commits = [payload["head_commit"]]
 
    after_sha = payload.get("after", "")
 
    for commit in commits:
        if not isinstance(commit, dict):
            continue
        changed = (
            commit.get("added",    []) +
            commit.get("modified", []) +
            commit.get("removed",  [])  # removed files can still be scanned at their last SHA
        )
        commit_sha = commit.get("id") or after_sha
        for filepath in changed:
            if _is_scannable(filepath):
                files_to_fetch.append((filepath, commit_sha or "HEAD"))
 
    # ── Pull request event ────────────────────────────────────
    pr = payload.get("pull_request", {})
    if isinstance(pr, dict) and pr.get("head", {}).get("sha"):
        head_sha = pr["head"]["sha"]
        # Fetch the PR file list via GitHub API
        pr_number = pr.get("number")
        if pr_number and GITHUB_TOKEN:
            files_url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files"
            headers   = {
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Accept":        "application/vnd.github.v3+json",
            }
            try:
                resp = requests.get(files_url, headers=headers, timeout=10)
                if resp.status_code == 200:
                    for f in resp.json():
                        filepath = f.get("filename", "")
                        if _is_scannable(filepath):
                            files_to_fetch.append((filepath, head_sha))
            except Exception:
                pass
 
    if not files_to_fetch:
        return payload
 
    # Deduplicate
    files_to_fetch = list({(fp, ref): None for fp, ref in files_to_fetch}.keys())
    # Cap at 20 files to avoid excessive API calls
    files_to_fetch = files_to_fetch[:20]
 
    print(f"   📄 Fetching {len(files_to_fetch)} changed file(s) from GitHub API...")
 
    fetched: dict[str, str] = {}
    for filepath, ref in files_to_fetch:
        content = _fetch_file_content(repo, filepath, ref)
        if content:
            fetched[filepath] = content
            print(f"      ✓ {filepath} ({len(content):,} chars)")
        else:
            print(f"      ✗ {filepath} (could not fetch)")
 
    if fetched:
        payload["_fetched_file_contents"] = fetched
        # Flat scannable text: filename + content for each file
        # Including the filename helps regex rules detect .env, SECURITY.md etc.
        scannable_parts = []
        for filepath, content in fetched.items():
            scannable_parts.append(f"# FILE: {filepath}\n{content}")
        payload["_scannable_text"] = "\n\n".join(scannable_parts)
        print(f"   ✅ File content enrichment complete — {len(fetched)} file(s) ready for scanning")
    else:
        print("   ⚠️  No file contents could be fetched")
 
    return payload