# 🛰️ PhantomRecon

**OSINT Reconnaissance Aggregator** — WHOIS, DNS records, subdomain
enumeration, HTTP fingerprinting, and public email discovery for a
target domain. Passive reconnaissance only.

Day 6 of the Phantom Security toolkit. Extends the DNS/subdomain
patterns from your earlier PhantomAuthor tool with raw protocol-level
implementations and a full web UI + CLI.

---

## Responsible use

Everything here is **passive, publicly available OSINT**: WHOIS records,
DNS, certificate transparency logs, and content already published on the
target's own pages. This is the standard reconnaissance phase used in
authorized penetration testing and bug bounty programs — it doesn't
exploit, brute-force, or access anything non-public. Always have
authorization before running this against a domain you don't own.

---

## Built from scratch: DNS and WHOIS at the protocol level

Two of the six modules are hand-built network clients rather than wrapping
a library — consistent with the Day 1 packet sniffer's philosophy of
understanding protocols at the wire level:

- **`dns_recon.py`** — a complete DNS client built from RFC 1035: crafts
  query packets by hand, sends raw UDP to a public resolver, and parses
  the response including **name compression** (pointer-following), the
  trickiest part of the DNS wire format. Supports A, AAAA, MX, TXT, NS,
  SOA, CAA, PTR.
- **`whois_lookup.py`** — the WHOIS protocol (RFC 3912) from scratch over
  raw TCP port 43, with the standard referral chain: IANA bootstrap → TLD
  registry → registrar.

## Testing notes — what was live-tested vs. sample-tested

This sandbox's outbound network turned out to be an **allowlist-based
proxy** (confirmed via the `x-deny-reason: host_not_allowed` response
header) — only Anthropic's own API infrastructure is reachable over
HTTP/HTTPS. Raw UDP DNS on port 53, however, is *not* intercepted by that
proxy and works freely.

**Live-tested against real, production infrastructure:**
- The entire DNS module — every record type (A, AAAA, MX, TXT, NS, SOA,
  CAA, PTR) verified against real answers from Google/Cloudflare/gmail.com,
  including correctly decompressed names in MX records
  (`alt2.gmail-smtp-in.l.google.com`) and a full SOA record parse
- Active subdomain enumeration (DNS-based) — found real subdomains
  (`api.google.com`, `mail.google.com`, etc.) with real IPs
- Reverse DNS — `8.8.8.8` → `dns.google`, `1.1.1.1` → `one.one.one.one`
- NXDOMAIN and malformed-response handling

**Blocked by the sandbox, tested against realistic sample/mocked data
matching the real service's exact schema instead:**
- WHOIS (port 43 blocked) — field extraction tested against real
  Verisign-format response text, referral-chasing tested against both
  gTLD-style and IANA-style referral formats, privacy-protection
  detection tested against both redacted and non-redacted samples
- crt.sh certificate transparency search — JSON parsing tested against
  a realistic mocked response including multi-line `name_value` fields
  and wildcard (`*.`) entries
- HTTP fingerprinting — technology detection tested against a mocked
  WordPress+Nginx response, correctly identifying both from headers and
  HTML content
- IP geolocation (ip-api.com) — tested against ip-api.com's real known
  JSON schema, including the "private IP" failure case

All of the above will work normally against real-world targets on any
machine with unrestricted outbound access — see the code comments in
each module for the specific "note on testing" where relevant.

---

## Features

| Feature | Web UI | CLI |
|---|---|---|
| Raw DNS client (A/AAAA/MX/TXT/NS/SOA/CAA/PTR) | ✅ | ✅ |
| Raw WHOIS client with referral chasing | ✅ | ✅ |
| Subdomain enumeration (crt.sh + active DNS scan) | ✅ | ✅ |
| HTTP fingerprinting (tech stack, security headers, well-known files) | ✅ | ✅ |
| Public email discovery (with de-obfuscation) | ✅ | ✅ |
| IP geolocation + ASN + reverse DNS | ✅ | ✅ |
| Unified exposure findings report | ✅ | ✅ |
| `--json` output for scripting | — | ✅ |

---

## Setup

```bash
pip install -r requirements.txt

# Web UI → http://127.0.0.1:5055
python3 app.py

# CLI
python3 cli.py --help
```

---

## CLI Usage

```bash
# Full reconnaissance report
python3 cli.py recon example.com

# Skip specific modules for a faster/lighter run
python3 cli.py recon example.com --no-whois --passive-only

# Individual lookups
python3 cli.py dns example.com --all
python3 cli.py dns example.com --type MX
python3 cli.py whois example.com --raw
python3 cli.py subdomains example.com --limit 100
python3 cli.py ip 8.8.8.8

# JSON output for scripting
python3 cli.py recon example.com --json | jq '.exposure_findings'
python3 cli.py dns example.com --all --json | jq '.MX.records'
```

---

## Exposure Findings — what they mean

Not a security "grade" — a plain-language list of what an outside
observer (or attacker doing reconnaissance) would learn about the
domain, so the owner can see their own attack surface from outside in.

| Finding | Why it matters |
|---|---|
| WHOIS privacy not enabled | Registrant contact info is publicly visible |
| No SPF record | Easier to spoof emails appearing to come from this domain |
| Sensitive subdomains live | Forgotten staging/dev/admin systems shouldn't be public |
| Missing security headers | Reduced protection against clickjacking/XSS |
| No security.txt | No clear channel for researchers to report vulnerabilities |
| Emails found on public pages | Shows what a phishing campaign would target first |

---

## Project Structure

```
phantomrecon/
├── app.py                    ← Flask web UI
├── cli.py                    ← CLI (same modules as web UI)
├── requirements.txt
├── modules/
│   ├── dns_recon.py          ← Hand-built DNS client (RFC 1035, raw UDP)
│   ├── whois_lookup.py       ← Hand-built WHOIS client (RFC 3912, raw TCP)
│   ├── subdomain_enum.py     ← crt.sh + active DNS wordlist enumeration
│   ├── http_fingerprint.py   ← Tech stack detection, security headers, well-known files
│   ├── email_harvest.py      ← Public email extraction with de-obfuscation
│   ├── ip_intel.py           ← Geolocation + ASN + reverse DNS
│   └── report.py             ← Unified report + exposure findings
├── templates/
│   ├── base.html
│   ├── index.html            ← Full Recon (main workflow)
│   └── reference.html        ← Methodology + responsible use
└── static/
    ├── css/style.css
    └── js/
        ├── app.js
        └── matrix.js
```

---

