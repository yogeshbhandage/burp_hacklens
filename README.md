# HackLens — Burp Suite Secret Scanner

Passive Burp Suite extension that scans HTTP responses for exposed secrets, API keys, and hardcoded credentials automatically as you browse.

## Requirements

- Burp Suite (Community or Pro)
- [Jython 2.7 standalone JAR](https://www.jython.org/download)

## Installation

1. Download `burp_hacklens.py`
2. Burp → `Extender > Options > Python Environment` → select Jython JAR
3. Burp → `Extender > Extensions > Add` → Type: **Python** → select `burp_hacklens.py`
4. **HackLens** tab appears in Burp

## Usage

Set Burp as proxy → browse the target → findings appear in the HackLens tab automatically.

| Action | How |
|---|---|
| View detail | Single-click row |
| View request / response | Double-click row |
| Send to Repeater | Select row → **Send to Repeater** |
| Export | **Export to Output** |
| Reset | **Clear All** |

## Detects

AWS, Azure, GCP, GitHub, GitLab, Stripe, PayPal, Slack, Discord, Twilio, SendGrid, JWT, OAuth tokens, private keys, database credentials, hardcoded default credentials, and more — **125+ patterns** with false positive filtering.

## Disclaimer

For authorized security testing and bug bounty programs only.

## Author

[@yogeshbhandage](https://yogeshbhandage.com)
