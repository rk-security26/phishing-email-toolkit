# Manual Phishing Analysis Checklist

## Header
- [ ] From address matches the real sender domain?
- [ ] Return-Path and Reply-To match From?
- [ ] SPF / DKIM / DMARC = pass?
- [ ] Originating IP looks normal? (check on AbuseIPDB / VirusTotal)

## Body
- [ ] Urgency or threats?
- [ ] Generic greeting ("Dear Customer")?
- [ ] Hover links: real URL matches the text?
- [ ] Shortened URL? Expand it with WhereGoes (do not click)

## Attachments
- [ ] Risky type (.exe, .zip, macro docs)?
- [ ] Hash checked on VirusTotal?

## Actions
- [ ] Block sender and URL
- [ ] Delete from all inboxes
- [ ] Reset password if clicked
- [ ] Report to security team
