import json
import os
from colorama import init, Fore, Style
from jinja2 import Environment, FileSystemLoader
from patterns import CRITICAL, WARNING, INFO, redact_secret

# Initialize colorama
init(autoreset=True)

def print_terminal_report(findings, files_scanned):
    """
    Prints a colorful report to the terminal.
    """
    print(f"\n{Style.BRIGHT}--- Secret Scanner Results ---{Style.RESET_ALL}")
    
    if not findings:
        print(f"{Fore.GREEN}No secrets found! Checked {files_scanned} files.{Style.RESET_ALL}")
        return

    severity_counts = {CRITICAL: 0, WARNING: 0, INFO: 0}
    
    for f in findings:
        severity_counts[f['severity']] += 1
        
        # Determine color based on severity
        color = Fore.WHITE
        if f['severity'] == CRITICAL:
            color = Fore.RED
        elif f['severity'] == WARNING:
            color = Fore.YELLOW
        elif f['severity'] == INFO:
            color = Fore.BLUE
            
        redacted = redact_secret(f['secret'])
        
        print(f"{color}[{f['severity']}] {f['type']} found in {f['file']} (Line {f['line']})")
        print(f"    Secret: {redacted}")
    
    print(f"\n{Style.BRIGHT}--- Scan Summary ---{Style.RESET_ALL}")
    print(f"Files Scanned: {files_scanned}")
    print(f"Total Secrets Found: {len(findings)}")
    print(f"{Fore.RED}Critical: {severity_counts[CRITICAL]}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Warning: {severity_counts[WARNING]}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}Info: {severity_counts[INFO]}{Style.RESET_ALL}")


def export_json(findings, files_scanned, output_path):
    """
    Exports findings to a JSON file.
    """
    # Redact secrets before exporting to avoid saving plaintext secrets
    export_data = []
    for f in findings:
        f_copy = f.copy()
        f_copy['secret'] = redact_secret(f['secret'])
        export_data.append(f_copy)

    report = {
        "summary": {
            "files_scanned": files_scanned,
            "total_secrets": len(findings)
        },
        "findings": export_data
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=4)
        
    print(f"\n{Fore.GREEN}JSON report saved to {output_path}{Style.RESET_ALL}")

def export_html(findings, files_scanned, output_path):
    """
    Exports findings to an HTML file using Jinja2.
    """
    # Redact secrets
    export_data = []
    severity_counts = {CRITICAL: 0, WARNING: 0, INFO: 0}
    
    for f in findings:
        severity_counts[f['severity']] += 1
        f_copy = f.copy()
        f_copy['secret'] = redact_secret(f['secret'])
        export_data.append(f_copy)
        
    # Setup Jinja2 environment
    template_dir = os.path.join(os.path.dirname(__file__), 'templates')
    if not os.path.exists(template_dir):
        print(f"{Fore.RED}Error: templates directory not found!{Style.RESET_ALL}")
        return

    env = Environment(loader=FileSystemLoader(template_dir))
    
    try:
        template = env.get_template('report.html')
        html_content = template.render(
            findings=export_data,
            files_scanned=files_scanned,
            total_secrets=len(findings),
            severity_counts=severity_counts
        )
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        print(f"\n{Fore.GREEN}HTML report saved to {output_path}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error generating HTML report: {e}{Style.RESET_ALL}")
