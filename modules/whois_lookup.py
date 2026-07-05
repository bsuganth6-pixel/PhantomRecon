"""
PhantomRecon — WHOIS Client
═══════════════════════════════════════════════════════════════
Implements the WHOIS protocol from scratch per RFC 3912 — it's
about as simple as network protocols get: open a TCP connection to
port 43, send "domain\\r\\n", read until the server closes the
connection. The hard part isn't the protocol; it's that WHOIS
response TEXT FORMAT is not standardized across registries, so
field extraction is necessarily heuristic (regex-based).

Server discovery uses the standard bootstrap chain:
  1. Check a hardcoded map of common TLD -> WHOIS server (fast path)
  2. Otherwise, query whois.iana.org for a referral to the right
     registry server for that TLD
  3. If the registry response itself contains a "Registrar WHOIS
     Server:" referral (common for gTLDs like .com/.net where
     Verisign is the registry but the registrar holds full details),
     follow that referral once more

NOTE ON TESTING: raw TCP port 43 is blocked in the sandboxed dev
environment this was built in (only ports 80/443 are reachable there).
The protocol implementation below is standard RFC 3912 and was
verified by parsing REAL, complete WHOIS response text (captured
from known-format registry outputs) rather than live queries. It
will connect normally on any machine with unrestricted outbound
access — see README for what was and wasn't live-tested.
"""

import socket
import re

IANA_WHOIS_SERVER = "whois.iana.org"

COMMON_TLD_SERVERS = {
    "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
    "org": "whois.pir.org", "info": "whois.afilias.net",
    "io": "whois.nic.io", "dev": "whois.nic.google",
    "app": "whois.nic.google", "co": "whois.nic.co",
    "me": "whois.nic.me", "biz": "whois.nic.biz",
    "us": "whois.nic.us", "xyz": "whois.nic.xyz",
    "in": "whois.registry.in", "uk": "whois.nic.uk",
    "ai": "whois.nic.ai", "tv": "whois.nic.tv",
}

REFERRAL_PATTERNS = [
    re.compile(r"Registrar WHOIS Server:\s*(\S+)", re.IGNORECASE),
    re.compile(r"whois:\s*(\S+)", re.IGNORECASE),
    re.compile(r"ReferralServer:\s*(?:whois://)?(\S+)", re.IGNORECASE),
]

FIELD_PATTERNS = {
    "registrar": [r"Registrar:\s*(.+)", r"Sponsoring Registrar:\s*(.+)"],
    "creation_date": [r"Creation Date:\s*(.+)", r"Created On:\s*(.+)", r"Registered on:\s*(.+)", r"created:\s*(.+)"],
    "expiry_date": [r"Registry Expiry Date:\s*(.+)", r"Expiration Date:\s*(.+)", r"Registry Expiration Date:\s*(.+)"],
    "updated_date": [r"Updated Date:\s*(.+)", r"Last Modified:\s*(.+)", r"changed:\s*(.+)"],
    "registrant_org": [r"Registrant Organization:\s*(.+)", r"Registrant:\s*(.+)"],
    "registrant_country": [r"Registrant Country:\s*(.+)"],
    "domain_status": [r"Domain Status:\s*(.+)", r"Status:\s*(.+)"],
    "dnssec": [r"DNSSEC:\s*(.+)"],
}


def _query_server(server: str, query_str: str, timeout: float = 10.0) -> str:
    sock = socket.create_connection((server, 43), timeout=timeout)
    sock.sendall((query_str.strip() + "\r\n").encode("utf-8", errors="ignore"))
    chunks = []
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    finally:
        sock.close()
    return b"".join(chunks).decode("utf-8", errors="replace")


def _find_referral(text: str) -> str:
    for pattern in REFERRAL_PATTERNS:
        m = pattern.search(text)
        if m:
            candidate = m.group(1).strip().rstrip("/")
            if candidate and "." in candidate:
                return candidate
    return None


def _extract_fields(text: str) -> dict:
    fields = {}
    for field_name, patterns in FIELD_PATTERNS.items():
        for pattern in patterns:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                value = m.group(1).strip()
                if value and value.lower() not in ("redacted for privacy", ""):
                    fields[field_name] = value
                    break
        fields.setdefault(field_name, None)

    ns_matches = re.findall(r"Name Server:\s*(\S+)", text, re.IGNORECASE)
    fields["name_servers"] = sorted(set(ns.lower().rstrip(".") for ns in ns_matches))

    status_matches = re.findall(r"Domain Status:\s*(\S+)", text, re.IGNORECASE)
    fields["all_statuses"] = sorted(set(status_matches))

    return fields


def _is_privacy_protected(text: str) -> bool:
    privacy_markers = [
        "redacted for privacy", "privacy protect", "whoisguard",
        "domains by proxy", "perfect privacy", "contact privacy",
        "data protected", "not disclosed",
    ]
    lower = text.lower()
    return any(marker in lower for marker in privacy_markers)


def lookup(domain: str, timeout: float = 10.0, max_referrals: int = 2) -> dict:
    domain = domain.strip().lower().rstrip(".")
    tld = domain.rsplit(".", 1)[-1] if "." in domain else domain
    servers_queried = []

    server = COMMON_TLD_SERVERS.get(tld)
    if not server:
        try:
            iana_response = _query_server(IANA_WHOIS_SERVER, tld, timeout=timeout)
            servers_queried.append(IANA_WHOIS_SERVER)
            server = _find_referral(iana_response)
        except (socket.timeout, OSError, ConnectionError) as e:
            return {"success": False, "raw_text": "", "fields": {}, "privacy_protected": False,
                    "servers_queried": servers_queried, "error": f"Could not reach IANA WHOIS bootstrap: {e}"}

    if not server:
        return {"success": False, "raw_text": "", "fields": {}, "privacy_protected": False,
                "servers_queried": servers_queried,
                "error": f"No WHOIS server known for TLD '.{tld}'. This TLD may use RDAP only, "
                        f"or IANA did not return a referral."}

    try:
        text = _query_server(server, domain, timeout=timeout)
        servers_queried.append(server)
    except socket.timeout:
        return {"success": False, "raw_text": "", "fields": {}, "privacy_protected": False,
                "servers_queried": servers_queried, "error": f"Timed out connecting to {server}:43"}
    except (OSError, ConnectionError) as e:
        return {"success": False, "raw_text": "", "fields": {}, "privacy_protected": False,
                "servers_queried": servers_queried, "error": f"Could not connect to {server}:43 - {e}"}

    referral = _find_referral(text)
    if referral and referral != server and max_referrals > 0:
        try:
            referral_text = _query_server(referral, domain, timeout=timeout)
            servers_queried.append(referral)
            if len(referral_text.strip()) > len(text.strip()) * 0.5:
                text = referral_text
        except (socket.timeout, OSError, ConnectionError):
            pass

    fields = _extract_fields(text)
    return {
        "success": True, "raw_text": text, "fields": fields,
        "privacy_protected": _is_privacy_protected(text),
        "servers_queried": servers_queried, "error": None,
    }
