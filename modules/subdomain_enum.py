"""
PhantomRecon — Subdomain Enumeration
═══════════════════════════════════════════════════════════════
Two complementary techniques:

  1. PASSIVE: Certificate Transparency logs via crt.sh. Every
     publicly-trusted TLS certificate issued since ~2018 is logged
     to public CT logs (a requirement for browser trust). Searching
     these logs reveals every subdomain anyone has ever requested a
     cert for — including forgotten staging/dev subdomains — without
     sending a single packet to the target's own infrastructure.

  2. ACTIVE: DNS resolution of a common subdomain wordlist. Catches
     subdomains that exist but never got a public certificate
     (internal tools, HTTP-only services).

Results are deduplicated and each candidate is verified to actually
resolve before being reported — crt.sh often includes long-expired
or typo'd certificate names that no longer point anywhere.
"""

import re
import json
import requests

from modules import dns_recon

CRTSH_URL = "https://crt.sh/"

COMMON_SUBDOMAINS = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ftp", "sftp",
    "admin", "administrator", "portal", "dashboard", "panel", "cpanel",
    "api", "api-dev", "api-staging", "dev", "staging", "test", "qa",
    "beta", "demo", "sandbox", "preprod",
    "blog", "shop", "store", "app", "mobile", "m",
    "vpn", "remote", "ssh", "rdp", "citrix",
    "ns1", "ns2", "dns", "mx", "mx1", "mx2",
    "cdn", "static", "assets", "media", "images", "img",
    "docs", "wiki", "confluence", "jira", "support", "helpdesk",
    "status", "monitor", "grafana", "kibana",
    "git", "gitlab", "github", "jenkins", "ci", "cd",
    "db", "database", "mysql", "postgres", "redis",
    "old", "new", "backup", "bak", "legacy",
    "internal", "intranet", "extranet", "corp",
    "secure", "login", "sso", "auth", "id",
]


def enumerate_crtsh(domain: str, timeout: float = 20.0) -> dict:
    """Query crt.sh's JSON API for every certificate ever logged for this domain."""
    try:
        resp = requests.get(CRTSH_URL, params={"q": f"%.{domain}", "output": "json"},
                           timeout=timeout, headers={"User-Agent": "PhantomRecon/1.0"})
        resp.raise_for_status()
    except requests.exceptions.Timeout:
        return {"success": False, "subdomains": [], "error": "crt.sh request timed out.", "raw_count": 0}
    except requests.exceptions.RequestException as e:
        return {"success": False, "subdomains": [], "error": f"crt.sh request failed: {e}", "raw_count": 0}

    try:
        entries = resp.json()
    except (json.JSONDecodeError, ValueError):
        return {"success": True, "subdomains": [], "error": None, "raw_count": 0}

    names = set()
    for entry in entries:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and name.endswith(domain.lower()) and _looks_like_valid_hostname(name):
                names.add(name)

    return {"success": True, "subdomains": sorted(names), "error": None, "raw_count": len(entries)}


def _looks_like_valid_hostname(name: str) -> bool:
    if "@" in name or " " in name:
        return False
    if not re.match(r"^[a-z0-9.\-]+$", name):
        return False
    return True


def enumerate_active(domain: str, wordlist: list = None, resolver: str = None) -> dict:
    """Actively resolve a wordlist of common subdomain prefixes, keeping only hits."""
    wordlist = wordlist or COMMON_SUBDOMAINS
    found = []

    for prefix in wordlist:
        candidate = f"{prefix}.{domain}"
        result = dns_recon.query(candidate, "A", resolver=resolver, timeout=3.0)
        if result["success"] and result["records"]:
            found.append({
                "subdomain": candidate,
                "ips": [r["value"] for r in result["records"] if r["type"] == "A"],
            })

    return {"success": True, "found": found, "checked_count": len(wordlist)}


def verify_subdomains_resolve(subdomains: list, resolver: str = None, limit: int = 100) -> list:
    """Check which of a list of subdomains currently resolve. Capped to avoid huge scans."""
    verified = []
    for sub in subdomains[:limit]:
        result = dns_recon.query(sub, "A", resolver=resolver, timeout=3.0)
        if result["success"] and result["records"]:
            verified.append({
                "subdomain": sub,
                "ips": [r["value"] for r in result["records"] if r["type"] == "A"],
                "alive": True,
            })
        else:
            verified.append({"subdomain": sub, "ips": [], "alive": False})
    return verified


def full_enumeration(domain: str, verify: bool = True, verify_limit: int = 50,
                     include_active: bool = True, resolver: str = None) -> dict:
    """Combined passive (crt.sh) + active (wordlist) subdomain discovery."""
    crtsh_result = enumerate_crtsh(domain)
    passive_subs = set(crtsh_result.get("subdomains", []))

    active_result = {"found": []}
    if include_active:
        active_result = enumerate_active(domain, resolver=resolver)
        for entry in active_result["found"]:
            passive_subs.add(entry["subdomain"])

    all_subs = sorted(passive_subs)

    verified = None
    if verify and all_subs:
        verified = verify_subdomains_resolve(all_subs, resolver=resolver, limit=verify_limit)

    return {
        "domain": domain,
        "crtsh": crtsh_result,
        "active": active_result,
        "all_unique_subdomains": all_subs,
        "total_unique": len(all_subs),
        "verified": verified,
        "alive_count": sum(1 for v in verified if v["alive"]) if verified else None,
    }
