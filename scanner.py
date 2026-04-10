import re
import math
from github import Github
from datetime import datetime

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
    "Generic API Key": r"(?i)(api_key|apikey|api-key).{0,10}['\"][a-zA-Z0-9]{20,}['\"]",
    "Private Key": r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
    "Database URL": r"(?i)(mysql|postgresql|mongodb|redis):\/\/[^\s]+:[^\s]+@[^\s]+",
    "Stripe Key": r"sk_live_[a-zA-Z0-9]{24,}",
    "Slack Token": r"xox[baprs]-[a-zA-Z0-9-]+",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Twilio Key": r"SK[a-zA-Z0-9]{32}",
    "SendGrid Key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
    "JWT Token": r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    "Password in URL": r"(?i)password=[^\s&]+",
    "Generic Secret": r"(?i)(secret|password|passwd|pwd).{0,10}['\"][a-zA-Z0-9!@#$%^&*]{8,}['\"]",
}

SEVERITY = {
    "AWS Access Key": "Critical",
    "AWS Secret Key": "Critical",
    "Private Key": "Critical",
    "Database URL": "Critical",
    "Stripe Key": "Critical",
    "GitHub Token": "High",
    "Slack Token": "High",
    "Google API Key": "High",
    "Twilio Key": "High",
    "SendGrid Key": "High",
    "Generic API Key": "Medium",
    "JWT Token": "Medium",
    "Password in URL": "Medium",
    "Generic Secret": "Low",
    "High Entropy String": "Medium",
}

RISK_CONTEXT = {
    "AWS Access Key": {
        "impact": "Full AWS account compromise. Attacker can access S3 buckets, spin up EC2 instances, exfiltrate data, or rack up thousands in charges.",
        "attack": "Attacker runs aws sts get-caller-identity to confirm key is valid, then enumerates IAM permissions and pivots to sensitive resources.",
        "remediation": "Immediately rotate the key in AWS IAM console. Run aws iam delete-access-key. Enable GuardDuty to detect future abuse. Audit CloudTrail for unauthorized API calls.",
    },
    "AWS Secret Key": {
        "impact": "Same as AWS Access Key — full account access when paired with an access key ID.",
        "attack": "Used alongside an AWS Access Key ID to sign API requests. Together they grant complete programmatic AWS access.",
        "remediation": "Rotate both the access key and secret key together. Never commit .env files — use AWS Secrets Manager or Parameter Store instead.",
    },
    "GitHub Token": {
        "impact": "Access to all repositories the token was scoped to. Attacker can read private code, push malicious commits, or steal CI/CD secrets.",
        "attack": "Attacker calls GET /user to confirm token works, then lists all accessible repos and clones private ones.",
        "remediation": "Revoke the token immediately in GitHub Settings > Developer Settings > Personal Access Tokens. Audit recent repository activity for unauthorized access.",
    },
    "Private Key": {
        "impact": "Attacker can impersonate the server, decrypt historical traffic, or authenticate as the key owner to any system that trusts it.",
        "attack": "RSA/EC private keys can be used to sign JWT tokens, authenticate over SSH, or decrypt TLS traffic if the key secures a web server.",
        "remediation": "Revoke the key everywhere it is trusted. Generate a new key pair. Never commit private keys — use a secrets manager or environment variables.",
    },
    "Database URL": {
        "impact": "Direct database access with embedded credentials. Attacker can read, modify, or delete all data.",
        "attack": "Connection string contains username, password, host, and database name. Attacker connects directly using any compatible database client.",
        "remediation": "Rotate the database password immediately. Use environment variables for connection strings. Consider VPC-restricted database access so credentials alone are not enough.",
    },
    "Stripe Key": {
        "impact": "Full access to Stripe account. Attacker can issue refunds, access customer payment data, or create fraudulent charges.",
        "attack": "Live secret keys grant write access to the Stripe API. Attacker can retrieve customer card data, create payouts, or drain the account.",
        "remediation": "Roll the key immediately in the Stripe Dashboard. Review recent API activity for unauthorized requests. Switch to restricted keys with minimal permissions.",
    },
    "GitHub Token": {
        "impact": "Access to repositories, potentially including private code and CI/CD secrets.",
        "attack": "Token used to clone repos, read Actions secrets, or push malicious code.",
        "remediation": "Revoke token in GitHub Settings immediately.",
    },
    "Slack Token": {
        "impact": "Read access to Slack workspace messages and files. Attacker can exfiltrate internal communications.",
        "attack": "Bot tokens can call conversations.history to read channel messages, users.list to enumerate team members, and files.list to access shared files.",
        "remediation": "Revoke the token in the Slack API dashboard. Audit workspace activity for unusual bot behavior.",
    },
    "Google API Key": {
        "impact": "Unauthorized use of Google Cloud services — Maps, Vision, Translation — billed to the account owner.",
        "attack": "Attacker uses the key to make API calls at scale, potentially racking up large bills or accessing restricted APIs.",
        "remediation": "Delete the key in Google Cloud Console. Create a new key with API restrictions and HTTP referrer or IP restrictions.",
    },
    "Generic API Key": {
        "impact": "Depends on the service — could allow unauthorized access to third-party data or paid API tiers.",
        "attack": "Attacker identifies the service from surrounding code and uses the key to make authenticated API calls.",
        "remediation": "Rotate the key with the relevant service. Use environment variables to store API credentials, never hardcode them.",
    },
    "JWT Token": {
        "impact": "If the token is still valid, attacker can authenticate as the user it represents without knowing their password.",
        "attack": "Attacker decodes the JWT at jwt.io to read claims, then uses it to make authenticated API requests until it expires.",
        "remediation": "Invalidate the token server-side if your auth system supports token blacklisting. Shorten token expiry times. Rotate the signing secret.",
    },
    "Database URL": {
        "impact": "Direct database access with credentials.",
        "attack": "Attacker connects directly to the database using the embedded credentials.",
        "remediation": "Rotate database credentials and use environment variables.",
    },
    "Password in URL": {
        "impact": "Plaintext password exposed in logs, browser history, and HTTP referer headers.",
        "attack": "Passwords in URLs appear in server logs and browser history. Anyone with log access can retrieve them.",
        "remediation": "Never pass passwords in URLs. Use POST request bodies or authorization headers instead.",
    },
    "Generic Secret": {
        "impact": "Variable — depends on what system this secret authenticates.",
        "attack": "Attacker identifies the service from variable name context and tests the secret against it.",
        "remediation": "Rotate this secret and move it to a secrets manager or environment variable.",
    },
    "High Entropy String": {
        "impact": "Likely a secret, key, or token based on its randomness — warrants manual review.",
        "attack": "High entropy strings often represent API keys, tokens, or passwords that were not matched by a known pattern.",
        "remediation": "Review in context. If it is a credential, rotate it and move to environment variables.",
    },
    "Twilio Key": {
        "impact": "Unauthorized access to Twilio account — attacker can send SMS/calls billed to your account or access message history.",
        "attack": "Key used to authenticate Twilio API requests, send messages, or retrieve call logs.",
        "remediation": "Revoke key in Twilio Console and generate a new one with minimum required permissions.",
    },
    "SendGrid Key": {
        "impact": "Attacker can send bulk emails from your domain, damaging your sender reputation and potentially phishing your users.",
        "attack": "Full API keys allow sending emails, accessing contact lists, and modifying account settings.",
        "remediation": "Delete the key in SendGrid Settings. Create a restricted key with only the permissions your app needs.",
    },
}

# Shannon entropy measures how random/unpredictable a string is.
# A truly random 40-char string scores ~5.8 bits/char.
# English text scores ~3-4. Secrets score high because they are random by design.
# Threshold of 4.5 catches most secrets while minimizing false positives.
ENTROPY_THRESHOLD = 4.5
MIN_ENTROPY_LENGTH = 20

# Characters commonly found in secrets/tokens
SECRET_CHARSET = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=_-")

def calculate_entropy(string):
    if not string:
        return 0
    freq = {}
    for char in string:
        freq[char] = freq.get(char, 0) + 1
    length = len(string)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

def find_high_entropy_strings(content, filename):
    findings = []
    lines = content.split("\n")

    # Skip files that are unlikely to contain secrets
    skip_files = [".min.js", ".lock", "package-lock.json", ".map", "yarn.lock"]
    if any(filename.endswith(ext) for ext in skip_files):
        return findings

    for line_num, line in enumerate(lines, 1):
        # Skip comment lines and very long lines (minified code)
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//") or len(line) > 500:
            continue

        # Look for assignment patterns — secret = "value" or secret: "value"
        assignment_pattern = r'(?:=|:)\s*["\']?([a-zA-Z0-9+/=_\-]{20,})["\']?'
        matches = re.findall(assignment_pattern, line)

        for match in matches:
            # Only check strings that look like they could be secrets
            if not all(c in SECRET_CHARSET for c in match):
                continue
            entropy = calculate_entropy(match)
            if entropy >= ENTROPY_THRESHOLD:
                findings.append({
                    "secret_type": "High Entropy String",
                    "severity": "Medium",
                    "filename": filename,
                    "line_number": line_num,
                    "line_preview": line.strip()[:120],
                    "entropy_score": round(entropy, 2),
                    "detection_method": "entropy",
                })
    return findings

def scan_content(content, filename):
    findings = []
    lines = content.split("\n")

    # Pattern-based detection
    for line_num, line in enumerate(lines, 1):
        for secret_type, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, line)
            if matches:
                findings.append({
                    "secret_type": secret_type,
                    "severity": SEVERITY[secret_type],
                    "filename": filename,
                    "line_number": line_num,
                    "line_preview": line.strip()[:120],
                    "detection_method": "pattern",
                    "entropy_score": None,
                })

    # Entropy-based detection (catches secrets patterns miss)
    entropy_findings = find_high_entropy_strings(content, filename)

    # Deduplicate — if a line already has a pattern finding, skip entropy finding for same line
    pattern_lines = {f["line_number"] for f in findings}
    for ef in entropy_findings:
        if ef["line_number"] not in pattern_lines:
            findings.append(ef)

    return findings

def scan_repo(token, repo_full_name):
    g = Github(token)
    findings = []
    repo_info = {}

    try:
        repo = g.get_repo(repo_full_name)
        repo_info = {
            "name": repo.full_name,
            "description": repo.description or "No description",
            "stars": repo.stargazers_count,
            "language": repo.language or "Unknown",
            "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "url": repo.html_url,
        }

        contents = repo.get_contents("")
        files_scanned = 0
        queue = list(contents)

        while queue:
            file = queue.pop(0)
            if file.type == "dir":
                try:
                    queue.extend(repo.get_contents(file.path))
                except Exception:
                    continue
            else:
                skip_extensions = [
                    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                    ".pdf", ".zip", ".tar", ".gz", ".exe", ".bin",
                    ".mp4", ".mp3", ".woff", ".ttf", ".eot", ".webp",
                ]
                if any(file.name.endswith(ext) for ext in skip_extensions):
                    continue
                try:
                    if file.size > 500000:
                        continue
                    content = file.decoded_content.decode("utf-8", errors="ignore")
                    file_findings = scan_content(content, file.path)
                    for f in file_findings:
                        f["repo"] = repo_full_name
                        f["file_url"] = file.html_url
                        # Attach risk context
                        ctx = RISK_CONTEXT.get(f["secret_type"], {})
                        f["impact"] = ctx.get("impact", "Review this finding manually.")
                        f["attack"] = ctx.get("attack", "Context dependent on the service.")
                        f["remediation"] = ctx.get("remediation", "Rotate this credential and move to environment variables.")
                    findings.extend(file_findings)
                    files_scanned += 1
                except Exception:
                    continue

        repo_info["files_scanned"] = files_scanned

    except Exception as e:
        return [], {"error": str(e)}

    return findings, repo_info

def scan_user(token, username, max_repos=10):
    g = Github(token)
    all_findings = []
    all_repo_info = []

    try:
        user = g.get_user(username)
        repos = list(user.get_repos())[:max_repos]

        for repo in repos:
            if repo.private:
                continue
            findings, repo_info = scan_repo(token, repo.full_name)
            all_findings.extend(findings)
            all_repo_info.append(repo_info)

    except Exception as e:
        return [], [{"error": str(e)}]

    return all_findings, all_repo_info