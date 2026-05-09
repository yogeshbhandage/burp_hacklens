# HackLens — Burp Suite Secret Scanner

A passive Burp Suite extension that automatically scans HTTP responses for exposed secrets, API keys, credentials, and sensitive tokens.

---

## Features

- **122+ regex patterns** — AWS, Google, GitHub, Stripe, Slack, JWT, private keys, database credentials, and more
- **Passive scanning** — hooks into every proxy response automatically (no active scanning needed)
- **Zero duplicates** — same secret on same URL is never shown twice per session
- **False positive filtering** — skips placeholder values like `changeme`, `xxxxxx`, sequential chars
- **HackLens tab** — sortable findings table with detail pane
- **Send to Repeater** — one click to send the request to Burp Repeater
- **Double-click popup** — view full request + response with matched value highlighted
- **Burp Scanner issues** — findings also appear in the native Scanner Issues tab with full advisory

---

## Requirements

- Burp Suite Pro
- [Jython 2.7 standalone JAR](https://www.jython.org/download)

---

## Installation

1. Download `burp_hacklens.py`
2. In Burp → `Extender > Options > Python Environment` → select the Jython JAR
3. In Burp → `Extender > Extensions > Add`
   - Extension type: **Python**
   - Select `burp_hacklens.py`
4. The **HackLens** tab will appear in Burp

---

## Usage

```
1. Set Burp as your proxy
2. Browse the target normally
3. HackLens scans every response in the background
4. Check the HackLens tab for findings
```

| Action | How |
|---|---|
| View finding detail | Single-click any row |
| View request / response | Double-click any row |
| Send to Repeater | Select row → click **Send to Repeater** |
| Export findings | Click **Export to Output** |
| Reset session | Click **Clear All** |

---

## Pattern Coverage

| Category | Examples |
|---|---|
| Cloud | AWS keys, Azure secrets, GCP service accounts, Firebase |
| Version Control | GitHub PAT, GitLab tokens, GitHub Actions |
| Payments | Stripe, PayPal, Square, Braintree |
| Messaging | Slack, Discord, Twilio, SendGrid, Mailgun |
| Databases | MongoDB URI, PostgreSQL, MySQL, Redis (with credentials) |
| Auth | JWT, OAuth tokens, Bearer tokens, Session secrets |
| Crypto | AES keys, RSA/EC/DSA/PGP private keys |
| App secrets | Django/Flask secret keys, JWT secrets, signing keys |
| Infra | Vault tokens, Kubernetes secrets, Databricks, npm tokens |
| Monitoring | Sentry DSN, Datadog, New Relic |

---

## Disclaimer

For authorized security testing and bug bounty programs only. Always obtain proper permission before testing any target.

---

## Author

[@yogeshbhandage](https://github.com/yogeshbhandage)
