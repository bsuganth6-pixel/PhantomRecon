"""
PhantomRecon — Unified Report Builder
═══════════════════════════════════════════════════════════════
Runs every recon module against one target domain and assembles a
single report, plus an "exposure findings" list — not a security
grade like PhantomShield's header checker, but a plain-language
list of what an attacker doing reconnaissance would learn and find
useful, so the domain owner can see their own attack surface the
way an outsider would.
"""

from modules import dns_recon, whois_lookup, subdomain_enum, http_fingerprint, email_harvest, ip_intel


def run_full_recon(domain: str, options: dict = None) -> dict:
    """
    Runs WHOIS, DNS, subdomain enum, HTTP fingerprint, email harvest,
    and IP intel for `domain`, returning one combined dict.

    options: {
        "skip_whois": bool, "skip_subdomains": bool, "skip_http": bool,
        "skip_emails": bool, "skip_ip_intel": bool, "skip_active_subdomain_scan": bool,
        "subdomain_verify_limit": int, "resolver": str,
    }
    """
    opts = options or {}
    domain = domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = domain.split("://", 1)[1]
    domain = domain.split("/")[0]

    resolver = opts.get("resolver")
    result = {"domain": domain}

    result["dns"] = dns_recon.full_lookup(domain, resolver=resolver)

    result["whois"] = None if opts.get("skip_whois") else whois_lookup.lookup(domain)

    result["subdomains"] = None if opts.get("skip_subdomains") else subdomain_enum.full_enumeration(
        domain, include_active=not opts.get("skip_active_subdomain_scan", False),
        verify_limit=opts.get("subdomain_verify_limit", 50), resolver=resolver)

    result["http"] = None if opts.get("skip_http") else http_fingerprint.fetch_and_fingerprint(domain)

    result["common_paths"] = None if opts.get("skip_http") else http_fingerprint.check_common_paths(domain)

    result["emails"] = None if opts.get("skip_emails") else email_harvest.harvest_from_multiple_pages(domain)

    result["ip_intel"] = None if opts.get("skip_ip_intel") else ip_intel.report_for_domain(domain, resolver=resolver)

    result["exposure_findings"] = build_exposure_findings(result)

    return result


def build_exposure_findings(result: dict) -> list:
    """
    Translates raw recon data into plain-language "here's what's
    exposed" findings — informational by nature (OSINT reconnaissance
    findings, not vulnerabilities), each with a severity used only to
    sort by how noteworthy it is.
    """
    findings = []

    # ── WHOIS exposure ──
    whois = result.get("whois")
    if whois and whois.get("success"):
        if not whois.get("privacy_protected"):
            findings.append({
                "severity": "medium", "category": "whois",
                "title": "WHOIS Privacy Not Enabled",
                "detail": "Registrant information is publicly visible in WHOIS. Consider enabling "
                         "registrar privacy/proxy protection if this domain is personally owned.",
            })
        fields = whois.get("fields", {})
        if fields.get("expiry_date"):
            findings.append({
                "severity": "info", "category": "whois",
                "title": "Domain Expiry Date Found",
                "detail": f"Registered until {fields['expiry_date']}. Set a renewal reminder — "
                         f"expired domains are a common takeover vector.",
            })

    # ── DNS / email security exposure ──
    dns = result.get("dns", {})
    txt = dns.get("TXT", {})
    if txt.get("success"):
        txt_values = " ".join(r["value"] for r in txt.get("records", []))
        has_spf = "v=spf1" in txt_values
        has_dmarc_hint = False  # DMARC lives at _dmarc.domain, checked separately below if desired
        if not has_spf:
            findings.append({
                "severity": "medium", "category": "email_security",
                "title": "No SPF Record Found",
                "detail": "Without an SPF record, it's easier for attackers to spoof emails "
                         "appearing to come from this domain.",
            })

    # ── Subdomain exposure ──
    subs = result.get("subdomains")
    if subs and subs.get("total_unique", 0) > 0:
        findings.append({
            "severity": "info", "category": "subdomains",
            "title": f"{subs['total_unique']} Unique Subdomains Discovered",
            "detail": f"Found via certificate transparency logs and/or active DNS resolution. "
                     f"Review for forgotten staging/dev/admin subdomains that shouldn't be public.",
        })
        if subs.get("verified"):
            interesting_keywords = ["staging", "dev", "test", "admin", "internal", "backup", "old", "vpn"]
            interesting = [v["subdomain"] for v in subs["verified"]
                          if v["alive"] and any(k in v["subdomain"] for k in interesting_keywords)]
            if interesting:
                findings.append({
                    "severity": "high", "category": "subdomains",
                    "title": "Potentially Sensitive Subdomains Are Live",
                    "detail": f"These resolve and look like internal/non-production systems: "
                             f"{', '.join(interesting[:10])}. Verify they're intentionally public.",
                })

    # ── HTTP / tech stack exposure ──
    http = result.get("http")
    if http and http.get("success"):
        sec_headers = http.get("security_headers_present", {})
        missing = [h for h, present in sec_headers.items() if not present]
        if missing:
            findings.append({
                "severity": "low", "category": "http",
                "title": f"{len(missing)} Security Header(s) Missing",
                "detail": f"Missing: {', '.join(missing)}. These headers harden against clickjacking, "
                         f"XSS, and downgrade attacks.",
            })
        if http.get("technologies"):
            findings.append({
                "severity": "info", "category": "http",
                "title": "Technology Stack Fingerprinted",
                "detail": f"Detected: {', '.join(http['technologies'])}. Version-specific banners "
                         f"can help attackers target known CVEs for that exact version.",
            })

    common_paths = result.get("common_paths")
    if common_paths:
        exposed_sensitive = [p["path"] for p in common_paths
                             if p["exists"] and p["path"] in ("/.well-known/security.txt",)]
        # security.txt existing is GOOD (responsible disclosure contact), not a finding against them
        missing_security_txt = not any(p["exists"] for p in common_paths
                                       if p["path"] == "/.well-known/security.txt")
        if missing_security_txt:
            findings.append({
                "severity": "low", "category": "http",
                "title": "No security.txt Found",
                "detail": "No /.well-known/security.txt — researchers who find a vulnerability "
                         "have no clear, safe channel to report it to you.",
            })

    # ── Email exposure ──
    emails = result.get("emails")
    if emails and emails.get("total_found", 0) > 0:
        findings.append({
            "severity": "info", "category": "emails",
            "title": f"{emails['total_found']} Email Address(es) Found on Public Pages",
            "detail": f"{', '.join(emails['all_emails'][:10])} — these are already public but "
                     f"consolidating them here shows what a phishing campaign would target first.",
        })

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 5))
    return findings
