"""
github_fetcher.py
━━━━━━━━━━━━━━━━━
Fetches actual file contents from the GitHub API for files changed
in push/PR events. GitHub webhooks only send commit metadata — not
the file contents themselves.
"""
 
import os
import base64
import requests
from dotenv import load_dotenv
 
load_dotenv()
 
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN") or os.getenv("GITHUB_PAT")
 
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".cs", ".cpp", ".c", ".h", ".sh", ".bash", ".zsh", ".env", ".yml",
    ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties",
    ".tf", ".tfvars", ".hcl", ".sql", ".xml", ".gradle",
}
 
MAX_FILE_BYTES = 100_000
 
 
def _is_scannable(filename: str) -> bool:
    name_lower = filename.lower()
    basename   = os.path.basename(name_lower)
    if "." not in basename:
        return basename in {"dockerfile", "makefile", "procfile"}
    return os.path.splitext(name_lower)[1] in SCANNABLE_EXTENSIONS
 
 
def _strip_repo_prefix(filepath: str, repo_name: str) -> str:
    """
    GitHub webhooks from repos with subdirectories include the full
    path relative to the repo root, e.g.:
        compliance_audit/test_multi_secrets.py
 
    The GitHub Contents API expects the path WITHOUT any leading
    project folder if the file is nested. We try the path as-is first,
    and if that 404s we strip the first path component and retry.
 
    This handles the common case where the repo contains a subfolder
    with the same name as the project (e.g. compliance_audit/compliance_audit/).
    """
    return filepath  # returned as-is; stripping handled in _fetch_file_content
 
 
def _fetch_file_content(repo_full_name: str, file_path: str, ref: str) -> tuple[str, str] | tuple[None, None]:
    """
    Fetch a single file's content from GitHub Contents API.
    Tries the path as-is first; if 404, strips the first path component
    and retries once (handles compliance_audit/file.py → file.py).
    Returns (content_text, actual_path_used) or (None, None) on failure.
    """
    if not GITHUB_TOKEN:
        return None, None
 
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept":        "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
 
    paths_to_try = [file_path]
 
    # If path has a leading directory component, also try without it
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
            # 404 → try next path variant
        except Exception:
            pass
 
    return None, None
 
 
def enrich_payload_with_file_contents(payload: dict) -> dict:
    """
    Fetches contents of all changed files and injects them into the
    payload under:
      payload['_fetched_file_contents'] = {filepath: content_str}
      payload['_scannable_text']        = flat concat of all file contents
 
    Works for both push events and pull_request events.
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
    commits  = payload.get("commits", [])
    after_sha = payload.get("after", "HEAD")
 
    for commit in commits:
        if not isinstance(commit, dict):
            continue
        changed    = (commit.get("added", []) +
                      commit.get("modified", []) +
                      commit.get("removed", []))
        commit_sha = commit.get("id") or after_sha
        for filepath in changed:
            if _is_scannable(filepath):
                files_to_fetch.append((filepath, commit_sha))
 
    # ── Pull request event ────────────────────────────────────
    pr = payload.get("pull_request", {})
    if isinstance(pr, dict) and pr.get("head", {}).get("sha"):
        head_sha = pr["head"]["sha"]
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
 
    # Deduplicate and cap
    seen = set()
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
        scannable_parts = []
        for filepath, content in fetched.items():
            scannable_parts.append(f"# FILE: {filepath}\n{content}")
        payload["_scannable_text"] = "\n\n".join(scannable_parts)
        print(f"   ✅ Fetched {len(fetched)} file(s) — ready for scanning")
    else:
        print("   ⚠️  No file contents could be fetched")
 
    return payload