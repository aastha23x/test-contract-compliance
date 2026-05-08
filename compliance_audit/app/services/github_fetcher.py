"""
github_fetcher.py
━━━━━━━━━━━━━━━━━
Fetches actual file contents from the GitHub API for files changed
in push/PR events. GitHub webhooks only send commit metadata — not
the file contents themselves.
 
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
}
 
# Hard cap per file to avoid huge diffs blowing up the spaCy/regex scan
MAX_FILE_BYTES = 100_000  # 100 KB
 
 
def _is_scannable(filename: str) -> bool:
    """Return True if the file extension is worth scanning."""
    name_lower = filename.lower()
    basename   = os.path.basename(name_lower)
    if "." not in basename:
        return basename in {"dockerfile", "makefile", "procfile"}
    return os.path.splitext(name_lower)[1] in SCANNABLE_EXTENSIONS
 
 
def _fetch_file_content(repo_full_name: str, file_path: str, ref: str) -> tuple[str, str] | tuple[None, None]:
    """
    Fetch a single file's content from GitHub Contents API.
 
    Tries the path as-is first. If 404, strips the first directory
    component and retries once. This handles the common case where
    the repo contains a project subfolder with the same name, e.g.:
        webhook sends: compliance_audit/test_multi_secrets.py
        API needs:     test_multi_secrets.py
 
    Returns (content_text, actual_path_used) or (None, None) on failure.
    """
    if not GITHUB_TOKEN:
        return None, None
 
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept":        "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
 
    # Build list of paths to try: original first, then stripped variant
    paths_to_try = [file_path]
    parts = file_path.split("/", 1)
    if len(parts) == 2:
        paths_to_try.append(parts[1])  # e.g. compliance_audit/foo.py → foo.py
 
    for path in paths_to_try:
        url = f"https://api.github.com/repos/{repo_full_name}/contents/{path}"
        try:
            resp = requests.get(url, headers=headers, params={"ref": ref}, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("encoding") == "base64":
                    content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
                    return content[:MAX_FILE_BYTES], path
            # 404 or other error → try next path variant
        except Exception:
            pass
 
    return None, None
 
 
def enrich_payload_with_file_contents(payload: dict) -> dict:
    """
    Given a GitHub webhook payload, fetch the contents of all changed
    files and inject them back into the payload under:
      payload['_fetched_file_contents'] = {filepath: content_str, ...}
      payload['_scannable_text']        = flat concat of all file contents
 
    _scannable_text is then read by both regex_detector.py and
    spacy_detector.py as a top-level field — enabling code-level
    detection of secrets, SQL injection, PII, etc.
 
    Works for both push events (commits[].added/modified) and
    pull_request events (uses the PR head SHA + pulls file list via API).
 
    Returns the enriched payload dict (mutates in place and returns).
    """
    if not GITHUB_TOKEN:
        print("   ⚠️  GITHUB_TOKEN not set — skipping file content fetch.")
        print("      Add GITHUB_TOKEN to your .env to enable code-level scanning.")
        return payload
 
    repo = payload.get("repository", {}).get("full_name", "")
    if not repo:
        return payload
 
    files_to_fetch: list[tuple[str, str]] = []  # [(filepath, ref), ...]
 
    # ── Push event ────────────────────────────────────────────
    commits   = payload.get("commits", [])
    after_sha = payload.get("after", "HEAD")
 
    for commit in commits:
        if not isinstance(commit, dict):
            continue
        changed    = (
            commit.get("added",    []) +
            commit.get("modified", []) +
            commit.get("removed",  [])
        )
        commit_sha = commit.get("id") or after_sha
        for filepath in changed:
            if _is_scannable(filepath):
                files_to_fetch.append((filepath, commit_sha))
 
    # ── Pull request event ────────────────────────────────────
    pr = payload.get("pull_request", {})
    if isinstance(pr, dict) and pr.get("head", {}).get("sha"):
        head_sha  = pr["head"]["sha"]
        pr_number = pr.get("number")
        if pr_number:
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
 
    # Deduplicate and cap at 20 files
    seen       = set()
    unique_files = []
    for fp, ref in files_to_fetch:
        if fp not in seen:
            seen.add(fp)
            unique_files.append((fp, ref))
    unique_files = unique_files[:20]
 
    print(f"   📄 Fetching {len(unique_files)} changed file(s) from GitHub API...")
 
    fetched: dict[str, str] = {}
    for filepath, ref in unique_files:
        content, actual_path = _fetch_file_content(repo, filepath, ref)
        if content:
            fetched[actual_path] = content
            print(f"      ✓ {actual_path} ({len(content):,} chars)")
        else:
            print(f"      ✗ {filepath} (could not fetch — check GITHUB_TOKEN permissions)")
 
    if fetched:
        payload["_fetched_file_contents"] = fetched
        # Flat scannable text: filename header + content for each file.
        # Including the filename helps RX011 detect .env, secrets.yml etc.
        scannable_parts = []
        for filepath, content in fetched.items():
            scannable_parts.append(f"# FILE: {filepath}\n{content}")
        payload["_scannable_text"] = "\n\n".join(scannable_parts)
        print(f"   ✅ Fetched {len(fetched)} file(s) — ready for scanning")
    else:
        print("   ⚠️  No file contents could be fetched")
 
    return payload