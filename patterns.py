import re

# Severity Levels
CRITICAL = "CRITICAL"
WARNING = "WARNING"
INFO = "INFO"

# Define patterns to scan for
# Structure: "Name": (Compiled Regex, Severity)
PATTERNS = {
    "AWS Access Key": (
        re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
        CRITICAL
    ),
    "GitHub Token": (
        re.compile(r'\b(gh[pousr]_[a-zA-Z0-9]{36,})\b'),
        CRITICAL
    ),
    "Stripe Secret Key": (
        re.compile(r'\b(sk_(?:live|test)_[0-9a-zA-Z]{24,})\b'),
        CRITICAL
    ),
    "Google API Key": (
        re.compile(r'\b(AIza[0-9A-Za-z\\-_]{35})\b'),
        WARNING
    ),
    "Private Key (RSA/SSH)": (
        re.compile(r'-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----'),
        CRITICAL
    ),
    "JWT Token": (
        re.compile(r'\b(ey[a-zA-Z0-9_-]{15,}\.ey[a-zA-Z0-9_-]{15,}\.[a-zA-Z0-9_-]{15,})\b'),
        INFO
    ),
    "Hardcoded Password": (
        re.compile(r'(?i)(?:password|passwd|pwd)\s*[:=]\s*[\'"](?!<[^>]+>|\[[^\]]+\])([^\'"\s]{6,64})[\'"]'),
        WARNING
    ),
    "Generic Token/Secret/API Key": (
        re.compile(r'(?i)(?:api_?key|secret|token)\s*[:=]\s*[\'"](?!<[^>]+>|\[[^\]]+\])([^\'"\s]{8,64})[\'"]'),
        WARNING
    ),
    "Authorization Bearer Token": (
        re.compile(r'(?i)bearer\s+([a-zA-Z0-9_\-\.]{15,})'),
        WARNING
    ),
    "Database Connection String": (
        re.compile(r'(?i)(?:postgres|mysql|mongodb|redis)(?:ql)?:\/\/[^:\s]+:([^@\s]+)@'),
        CRITICAL
    )
}

def redact_secret(secret_str):
    """
    Redacts a secret, showing only the first 4 and last 4 characters.
    If the secret is 8 characters or shorter, masks everything but the first and last character.
    """
    if not secret_str:
        return ""
    length = len(secret_str)
    if length <= 8:
        if length <= 2:
            return "*" * length
        return secret_str[0] + ("*" * (length - 2)) + secret_str[-1]
    
    return secret_str[:4] + ("*" * (length - 8)) + secret_str[-4:]
