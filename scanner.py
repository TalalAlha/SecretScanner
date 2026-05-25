import argparse
import sys
from local import scan_local_path
from github import scan_github_repo
from report import print_terminal_report, export_json, export_html
from patterns import CRITICAL, WARNING, INFO

def main():
    parser = argparse.ArgumentParser(description="Secret Scanner CLI: Scan codebases for accidentally committed secrets.")
    
    # Scanning Modes
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--local', type=str, help='Scan a local folder recursively. Provide the path.')
    group.add_argument('--github', type=str, help='Scan a public GitHub repo. Provide the repo URL or owner/repo format.')
    
    # GitHub Specific
    parser.add_argument('--token', type=str, help='GitHub Personal Access Token (PAT) for scanning private repos and increasing rate limit.')
    
    # Extra Features
    parser.add_argument('--severity', type=str, choices=[CRITICAL, WARNING, INFO], help='Minimum severity level to report. (e.g. CRITICAL, WARNING, INFO)')
    parser.add_argument('--output', type=str, choices=['terminal', 'json', 'html'], default='terminal', help='Output format (terminal, json, html).')
    parser.add_argument('--output-file', type=str, help='File path for JSON or HTML output. Defaults to report.json or report.html in current directory.')
    parser.add_argument('--exclude', type=str, help='Comma-separated list of files or directories to exclude.')
    parser.add_argument('--full', action='store_true', help='Perform a full scan by including all files and directories with "test" or "spec" in their names (default: skipped).')

    args = parser.parse_args()

    # Parse excludes
    excludes = []
    if args.exclude:
        excludes = [x.strip() for x in args.exclude.split(',')]

    print("Initializing Secret Scanner...")

    findings = []
    files_scanned = 0

    if args.local:
        print(f"Scanning Local Path: {args.local}")
        findings, files_scanned = scan_local_path(args.local, excludes=excludes, full_scan=args.full)
    elif args.github:
        findings, files_scanned = scan_github_repo(args.github, token=args.token, excludes=excludes, full_scan=args.full)

    # Filter by severity if specified
    if args.severity:
        severity_levels = {INFO: 1, WARNING: 2, CRITICAL: 3}
        min_level = severity_levels[args.severity]
        filtered_findings = [f for f in findings if severity_levels[f['severity']] >= min_level]
        findings = filtered_findings

    # Output
    if args.output == 'terminal':
        print_terminal_report(findings, files_scanned)
    elif args.output == 'json':
        out_file = args.output_file or "report.json"
        export_json(findings, files_scanned, out_file)
    elif args.output == 'html':
        out_file = args.output_file or "report.html"
        export_html(findings, files_scanned, out_file)
        
if __name__ == "__main__":
    main()
