
# Phishing Email Analysis Toolkit

A small Python tool and checklist to analyze suspicious emails (.eml files)
and flag common phishing red flags.

Built while learning phishing analysis on TryHackMe (Phishing Analysis
Fundamentals, Phishing Emails in Action).

## What it checks
- From vs Return-Path domain mismatch
- Reply-To mismatch
- SPF, DKIM, DMARC results from headers
- Urgency language in the body
- Shortened URLs (bit.ly, is.gd, etc.)
- Risky attachment types (.exe, .docm, .zip, etc.)
- Extracts all URLs and prints them defanged (safe to share)

## Usage
```bash
python3 analyze_email.py samples/sample.eml
```
Save a suspicious email as .eml (Show original / Download message) and run
the same command on it.

## Example output
```
Subject    : Your Receipt for Payment
From       : service@paypal.com
[!] From domain (paypal.com) != Return-Path domain (random-site.com)
[!] SPF result: fail
[!] Shortened URL: hxxps://is[.]gd/abc123
Verdict: HIGH RISK (5 red flags)
```

## Files
| File | Purpose |
|---|---|
| analyze_email.py | The analyzer script |
| checklist.md | Manual analysis checklist |
| samples/sample.eml | Fake test email |

## Disclaimer
Educational project. Never open links or attachments from real phishing
emails. Use a sandbox or online scanners (VirusTotal, URLScan) for deeper checks.

## Defense recap
MFA, email filtering, SPF/DKIM/DMARC, user awareness training.
