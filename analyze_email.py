#!/usr/bin/env python3
"""Phishing Email Analyzer: reads a .eml file and flags common red flags."""
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "is.gd", "tinyurl.com", "t.co", "goo.gl",
              "ow.ly", "cutt.ly", "rb.gy"}
RISKY_EXT = (".exe", ".scr", ".js", ".vbs", ".zip", ".iso", ".docm", ".xlsm")
URGENCY = ("urgent", "immediately", "act now", "suspended", "verify your",
           "unauthorized", "account will be", "within 24 hours", "cancel the order")
URL_RE = re.compile(r'https?://[^\s"\'<>)]+', re.I)


def domain_of(addr):
    return parseaddr(addr or "")[1].rpartition("@")[2].lower()


def defang(url):
    return url.replace("http", "hxxp").replace(".", "[.]")


def get_body(msg):
    part = msg.get_body(preferencelist=("html", "plain"))
    try:
        return part.get_content() if part else ""
    except Exception:
        return ""


def analyze(path):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    flags = []
    from_d = domain_of(msg.get("From"))
    rp_d = domain_of(msg.get("Return-Path"))
    reply_d = domain_of(msg.get("Reply-To"))

    print(f"Subject    : {msg.get('Subject')}")
    print(f"From       : {msg.get('From')}")
    print(f"Return-Path: {msg.get('Return-Path')}")
    print(f"Reply-To   : {msg.get('Reply-To')}\n")

    if rp_d and from_d != rp_d:
        flags.append(f"From domain ({from_d}) != Return-Path domain ({rp_d})")
    if reply_d and from_d != reply_d:
        flags.append(f"From domain ({from_d}) != Reply-To domain ({reply_d})")

    auth = " ".join(msg.get_all("Authentication-Results", [])).lower()
    for check in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{check}=(\w+)", auth)
        result = m.group(1) if m else "none"
        print(f"{check.upper():6}: {result}")
        if result != "pass":
            flags.append(f"{check.upper()} result: {result}")

    body = get_body(msg)
    low = body.lower()
    hits = [w for w in URGENCY if w in low]
    if hits:
        flags.append(f"Urgency language: {', '.join(hits)}")

    urls = sorted({u.rstrip(".,;") for u in URL_RE.findall(body)})
    print("\nURLs found (defanged):")
    for u in urls:
        print("  ", defang(u))
        if (urlparse(u).hostname or "") in SHORTENERS:
            flags.append(f"Shortened URL: {defang(u)}")

    for part in msg.iter_attachments():
        name = (part.get_filename() or "").lower()
        if name.endswith(RISKY_EXT):
            flags.append(f"Risky attachment: {name}")

    print("\nRed flags:")
    for f in flags:
        print("  [!]", f)
    level = "HIGH" if len(flags) >= 4 else "MEDIUM" if len(flags) >= 2 else "LOW"
    print(f"\nVerdict: {level} RISK ({len(flags)} red flags)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 analyze_email.py <file.eml>")
    analyze(sys.argv[1])
