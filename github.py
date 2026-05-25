import requests
import base64
import re
from urllib.parse import urlparse
from patterns import PATTERNS
from local import scan_file_lines

GITHUB_API_URL = "https://api.github.com"
DEFAULT_EXCLUDES = {'.git', 'node_modules', 'venv', '.venv', '__pycache__', 'tests', 'test', '__tests__', 'spec', 'specs', 'dist', 'build', 'out', 'coverage', '.next', '.nuxt', '.idea', '.vscode', 'vendor', 'tmp', 'temp', 'logs'}

def parse_github_url(url):
    """
    Extracts owner and repo from a GitHub URL or string like 'owner/repo'.
    """
    owner, repo = None, None
    # If it's a full URL
    if url.startswith("http"):
        parsed = urlparse(url)
        path_parts = parsed.path.strip('/').split('/')
        if len(path_parts) >= 2:
            owner, repo = path_parts[0], path_parts[1]
    # If it's just 'owner/repo'
    else:
        parts = url.strip('/').split('/')
        if len(parts) == 2:
            owner, repo = parts[0], parts[1]
            
    if repo and repo.endswith('.git'):
        repo = repo[:-4]
        
    return owner, repo

def check_rate_limit(headers):
    """
    Checks rate limit from response headers and prints a warning if it's low.
    """
    remaining = headers.get('X-RateLimit-Remaining')
    limit = headers.get('X-RateLimit-Limit')
    if remaining and limit:
        remaining = int(remaining)
        if remaining < 10:
            print(f"\n[WARNING] GitHub API rate limit is low! ({remaining}/{limit} remaining).")
            print("Consider using a Personal Access Token (--token) to increase your limit to 5000/hr.")

def get_headers(token):
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    return headers

def fetch_repo_tree(owner, repo, token):
    """
    Fetches the recursive file tree for the repository's default branch.
    """
    headers = get_headers(token)
    
    # Get default branch first
    repo_url = f"{GITHUB_API_URL}/repos/{owner}/{repo}"
    resp = requests.get(repo_url, headers=headers)
    if resp.status_code != 200:
        if resp.status_code == 403 or resp.status_code == 404:
            print(f"Failed to access repository. If it's private, you must provide a valid --token.")
            print(f"Status Code: {resp.status_code}, Response: {resp.json().get('message')}")
        else:
            print(f"Error fetching repo info: {resp.status_code} - {resp.text}")
        return []
    
    check_rate_limit(resp.headers)
    default_branch = resp.json().get('default_branch', 'main')
    
    # Get tree
    tree_url = f"{GITHUB_API_URL}/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1"
    tree_resp = requests.get(tree_url, headers=headers)
    
    if tree_resp.status_code != 200:
        print(f"Error fetching repo tree: {tree_resp.status_code} - {tree_resp.text}")
        return []

    check_rate_limit(tree_resp.headers)
    
    return tree_resp.json().get('tree', [])

def scan_github_repo(repo_url, token=None, excludes=None, full_scan=False):
    """
    Scans a GitHub repository.
    """
    owner, repo = parse_github_url(repo_url)
    if not owner or not repo:
        print(f"Invalid GitHub URL or format: {repo_url}")
        return [], 0
        
    print(f"Scanning GitHub Repository: {owner}/{repo}")
    if not token:
        print("[INFO] No token provided. Rate limit is 60 requests/hour. Scanning private repos will fail.")
    else:
        print("[INFO] Token provided. Rate limit is 5000 requests/hour.")

    if excludes is None:
        excludes = []
        
    exclude_dirs = DEFAULT_EXCLUDES.union(set(excludes))
    
    tree = fetch_repo_tree(owner, repo, token)
    
    all_findings = []
    files_scanned = 0
    headers = get_headers(token)
    
    for item in tree:
        if item['type'] != 'blob':
            continue
            
        path = item['path']
        
        # Check exclusion logic
        path_parts = path.split('/')
        skip = False
        for part in path_parts[:-1]: # Check directories
            if part in exclude_dirs:
                skip = True
                break
            if not full_scan:
                d_lower = part.lower()
                if d_lower in {'test', 'tests', '__tests__', 'spec', 'specs', 'e2e', 'cypress', 'load_tests'}:
                    skip = True
                    break
                if d_lower.endswith('_tests') or d_lower.endswith('_test') or d_lower.startswith('test_'):
                    skip = True
                    break
        
        if skip:
            continue
            
        filename = path_parts[-1]
        if filename in excludes:
            continue
            
        # Skip common test files by name
        if not full_scan:
            f_lower = filename.lower()
            if f_lower.startswith('test_') or f_lower.endswith(('_test.py', '_test.go', '_test.rb', '.test.js', '.test.jsx', '.test.ts', '.test.tsx', '.spec.js', '.spec.jsx', '.spec.ts', '.spec.tsx')):
                continue
            
        # Skip binary extensions
        if filename.endswith(('.exe', '.dll', '.so', '.dylib', '.png', '.jpg', '.jpeg', '.gif', '.pdf', '.svg', '.ico', '.mp4', '.mp3', '.wav', '.zip', '.tar', '.gz', '.lock', '.sum')):
            continue

        # Fetch file content
        content_url = item['url'] # Git Data API URL for the blob
        blob_resp = requests.get(content_url, headers=headers)
        if blob_resp.status_code != 200:
            continue
            
        check_rate_limit(blob_resp.headers)
        
        blob_data = blob_resp.json()
        if blob_data.get('encoding') == 'base64':
            try:
                content = base64.b64decode(blob_data['content']).decode('utf-8', errors='ignore')
            except Exception:
                continue # Skip if decode fails
        else:
            continue # We only handle base64 text for now
            
        # Optional: very rudimentary binary check on decoded content
        if '\0' in content[:1024]:
            continue

        files_scanned += 1
        lines = content.split('\n')
        all_findings.extend(scan_file_lines(path, lines))
        
    return all_findings, files_scanned
