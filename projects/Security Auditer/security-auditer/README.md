# Security Auditer

Passive-oriented Chrome extension for recon, headers/DOM/network analysis, and reporting.

## Features
- Recon: robots.txt, sitemap fetch (lightweight). Placeholders ready for subdomain/ASN if APIs are added.
- Headers & CSP: missing/weak headers, CSP simulation hints.
- Cookies: Secure/HttpOnly/SameSite checks.
- DOM/JS: inline scripts, eval/new Function, dynamic HTML writes, HTTP forms.
- Storage: detects JWT-like tokens and secret-ish values.
- Network: flags cleartext requests and permissive CORS with credentials.
- Reporting: JSON/Markdown export; print-friendly PDF view; stores findings with timestamps.
- UI: Dark dashboard, category tabs, search, severity filters, counts.

## Install
1. Chrome -> `chrome://extensions/` -> enable Developer Mode.
2. Load unpacked -> select this folder `security-auditer`.

## Notes
- Active vulnerability scanning (SQLi/XSS injection, etc.) is **not** performed to avoid intrusive behavior. Add external scanners via APIs if desired.
- Tab capture permission is included for future screenshot integration; current PDF export uses print view.
