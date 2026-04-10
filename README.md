# SecretScan

Scans public GitHub repositories for accidentally committed credentials using two detection layers: regex pattern matching and Shannon entropy analysis.

[Live App](https://git-scanner.streamlit.app) · [GitHub](https://github.com/ZainRizvi9/github-secret-scanner)

---

## Overview

Exposed credentials in public GitHub repositories are one of the most common causes of cloud breaches. Attackers scrape GitHub continuously looking for API keys, database passwords, and AWS credentials committed by developers. This tool automates the detection process using the same methodology as commercial products like GitGuardian and TruffleHog.

Each finding includes the affected file and line number, severity rating, real-world impact, the exact attack vector an attacker would use, and step-by-step remediation guidance.

---

## Detection Methods

**Pattern Matching**

Regex patterns tuned for 14 known credential formats. Each pattern targets the structural signature of a specific secret type.

- AWS Access Key: AKIA[0-9A-Z]{16}
- GitHub Token: ghp_[a-zA-Z0-9]{36}
- Stripe Live Key: sk_live_[a-zA-Z0-9]{24,}
- Private Key: -----BEGIN (RSA/EC/DSA/OPENSSH) PRIVATE KEY-----
- Database URL: (mysql|postgresql|mongodb)://user:pass@host
- JWT Token: eyJ[header].[payload].[signature]

Pattern matching is precise but limited to secrets with known formats. A randomly generated API key with no recognizable prefix will evade pattern detection entirely.

**Shannon Entropy Analysis**

Shannon entropy measures how random or unpredictable a string is. The formula sums `-p * log2(p)` across all unique characters, where p is each character's frequency. The result is bits per character.

- Normal English text: ~3.0 to 4.0 bits/char (letters repeat predictably)
- Source code identifiers: ~3.5 to 4.2 bits/char
- API keys and tokens: ~4.5 to 6.0 bits/char (designed to be unpredictable)
- True random base64: ~6.0 bits/char

The threshold of 4.5 bits was chosen to minimize false positives from normal source code while catching the majority of real credentials. Any string longer than 20 characters scoring above this threshold is flagged for manual review.

This catches secrets that pattern matching misses. A developer who generates a random 40-character password and hardcodes it has no recognizable prefix, but the entropy gives it away.

The two methods complement each other. Pattern matching catches known formats with high precision. Entropy analysis catches unknown formats with broader recall. Together they reduce the blind spots of either approach alone.

---

## Secret Types Detected

| Type | Severity | Detection |
|------|----------|-----------|
| AWS Access Key | Critical | Pattern |
| AWS Secret Key | Critical | Pattern |
| Private Key (RSA/EC/DSA) | Critical | Pattern |
| Database URL with credentials | Critical | Pattern |
| Stripe Live Key | Critical | Pattern |
| GitHub Personal Access Token | High | Pattern |
| Google API Key | High | Pattern |
| Slack Token | High | Pattern |
| Twilio API Key | High | Pattern |
| SendGrid API Key | High | Pattern |
| Generic API Key | Medium | Pattern |
| JWT Token | Medium | Pattern |
| Password in URL | Medium | Pattern |
| Generic Secret Assignment | Low | Pattern |
| High Entropy String | Medium | Entropy |

---

## Each Finding Includes

- Severity rating (Critical, High, Medium, Low)
- Detection method (pattern or entropy with score)
- Exact file path and line number with direct GitHub link
- Real-world impact of the exposed credential
- Attack vector describing what an attacker would actually do with it
- Remediation steps to fix the exposure

---

## Stack

Python, PyGithub, Streamlit, Plotly

---

## Running Locally

```bash
git clone https://github.com/ZainRizvi9/github-secret-scanner.git
cd github-secret-scanner
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

You will need a GitHub personal access token with public repository read access. Generate one at github.com/settings/tokens.

---

## Limitations

Scans public repositories only. Binary files, images, and minified JavaScript are skipped to reduce false positives. Files over 500KB are skipped to avoid timeouts. The entropy threshold may produce false positives on compressed data or base64-encoded content so all entropy findings should be reviewed in context before acting on them.

---

## Disclaimer

Built for educational and security research purposes only. Only scan repositories you own or have explicit permission to scan.

---

*Not affiliated with GitHub, GitGuardian, or TruffleHog*
