#!/usr/bin/env python3
"""
PhantomRecon CLI — OSINT Reconnaissance Aggregator
═══════════════════════════════════════════════════════════════
USAGE
  python3 cli.py recon <domain>                 Full reconnaissance report
  python3 cli.py dns <domain> [--type A]        Single DNS record type query
  python3 cli.py dns <domain> --all             All common record types
  python3 cli.py whois <domain>                 WHOIS lookup only
  python3 cli.py subdomains <domain>            Subdomain enumeration only
  python3 cli.py ip <ip-address>                IP geolocation + reverse DNS
  python3 cli.py --help

Passive OSINT only. Always have authorization before running
reconnaissance against a domain you don't own.
"""

import os
import sys
import json
import argparse

from modules import dns_recon, whois_lookup, subdomain_enum, http_fingerprint, email_harvest, ip_intel, report

_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
def _c(code): return code if _COLOR else ""
R=_c("\033[0m"); BOLD=_c("\033[1m"); DIM=_c("\033[2m")
RED=_c("\033[91m"); GRN=_c("\033[92m"); YLW=_c("\033[93m")
CYN=_c("\033[96m"); VIO=_c("\033[95m"); ORG=_c("\033[38;5;208m")

SEP = f"{DIM}{'─'*76}{R}"


def banner():
    print(f"""{CYN}{BOLD}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
  {DIM}OSINT Reconnaissance Aggregator{R}
  {YLW}Passive OSINT only. Have authorization before scanning a domain you don't own.{R}
""")


def err(msg):  print(f"{RED}✗ {msg}{R}", file=sys.stderr)
def ok(msg):   print(f"{GRN}✓ {msg}{R}")
def info(msg): print(f"{CYN}ℹ {msg}{R}")
def warn(msg): print(f"{YLW}⚠ {msg}{R}")


def sev_color(sev):
    return {"critical": RED, "high": ORG, "medium": YLW, "low": CYN, "info": GRN}.get(sev, R)


# ════════════════════════════════════════════════════════════════
#  DISPLAY
# ════════════════════════════════════════════════════════════════

def print_dns_section(dns_results):
    print(SEP)
    print(f"  {BOLD}DNS RECORDS{R}")
    print(SEP)
    for rtype, result in dns_results.items():
        if result["success"] and result["records"]:
            print(f"  {VIO}{rtype}{R}")
            for rec in result["records"]:
                print(f"    {rec['value']}  {DIM}(TTL {rec['ttl']}s){R}")
    print()


def print_whois_section(whois):
    print(SEP)
    print(f"  {BOLD}WHOIS{R}")
    print(SEP)
    if not whois["success"]:
        print(f"  {DIM}{whois['error']}{R}")
    else:
        f = whois["fields"]
        print(f"  {DIM}Registrar:{R}    {f.get('registrar') or '—'}")
        print(f"  {DIM}Created:{R}      {f.get('creation_date') or '—'}")
        print(f"  {DIM}Expires:{R}      {f.get('expiry_date') or '—'}")
        print(f"  {DIM}Updated:{R}      {f.get('updated_date') or '—'}")
        print(f"  {DIM}Name Servers:{R} {', '.join(f.get('name_servers', [])) or '—'}")
        priv = "Yes" if whois["privacy_protected"] else f"{YLW}No — registrant info may be public{R}"
        print(f"  {DIM}Privacy:{R}      {priv}")
    print()


def print_subdomains_section(subs):
    print(SEP)
    print(f"  {BOLD}SUBDOMAINS{R} {DIM}({subs['total_unique']} unique found){R}")
    print(SEP)
    if not subs["crtsh"]["success"]:
        print(f"  {DIM}(passive crt.sh lookup unavailable: {subs['crtsh']['error']}){R}")
    sensitive_kw = ["staging","dev","test","admin","internal","backup","old","vpn"]
    verified = subs.get("verified") or [{"subdomain": s, "alive": None} for s in subs["all_unique_subdomains"]]
    for v in verified:
        is_sensitive = any(k in v["subdomain"] for k in sensitive_kw)
        if v["alive"] is False:
            print(f"  {DIM}✗ {v['subdomain']} (does not resolve){R}")
        elif is_sensitive:
            print(f"  {ORG}⚠ {v['subdomain']}{R}")
        else:
            print(f"  {GRN}✓ {v['subdomain']}{R}")
    print()


def print_http_section(http, common_paths):
    print(SEP)
    print(f"  {BOLD}HTTP FINGERPRINT{R}")
    print(SEP)
    if not http["success"]:
        print(f"  {DIM}{http['error']}{R}")
    else:
        print(f"  {DIM}URL:{R}       {http['final_url']}")
        print(f"  {DIM}Status:{R}    {http['status_code']}")
        print(f"  {DIM}Title:{R}     {http.get('title') or '—'}")
        print(f"  {DIM}Server:{R}    {http.get('server_header') or '—'}")
        if http["technologies"]:
            print(f"  {DIM}Tech:{R}      {', '.join(http['technologies'])}")
    if common_paths:
        found = [p["path"] for p in common_paths if p["exists"]]
        if found:
            print(f"  {DIM}Well-known files found:{R} {', '.join(found)}")
    print()


def print_emails_section(emails):
    print(SEP)
    print(f"  {BOLD}PUBLIC EMAIL ADDRESSES{R} {DIM}({emails['total_found']} found){R}")
    print(SEP)
    for e in emails["all_emails"]:
        print(f"  {CYN}{e}{R}")
    print()


def print_ip_intel_section(ip_intel_result):
    print(SEP)
    print(f"  {BOLD}IP INTELLIGENCE{R}")
    print(SEP)
    if not ip_intel_result["success"]:
        print(f"  {DIM}{ip_intel_result['error']}{R}")
    else:
        for rep in ip_intel_result["reports"]:
            print(f"  {VIO}{rep['ip']}{R}")
            print(f"    {DIM}Reverse DNS:{R} {rep['reverse_dns'] or '—'}")
            if rep["geolocation"]["success"]:
                g = rep["geolocation"]
                print(f"    {DIM}Location:{R}    {g['city']}, {g['region']}, {g['country']}")
                print(f"    {DIM}ISP/Org:{R}     {g['isp']}")
                print(f"    {DIM}ASN:{R}         {g['asn']}")
            else:
                print(f"    {DIM}Geolocation:{R} {rep['geolocation']['error']}")
    print()


def print_findings_section(findings):
    print(SEP)
    print(f"  {BOLD}EXPOSURE FINDINGS{R} {DIM}({len(findings)}){R}")
    print(SEP)
    if not findings:
        ok("No notable exposure findings.")
    for f in findings:
        c = sev_color(f["severity"])
        print(f"  {c}[{f['severity'].upper():<8}]{R} {BOLD}{f['title']}{R}")
        print(f"  {DIM}{'':<10} {f['detail']}{R}")
    print()


# ════════════════════════════════════════════════════════════════
#  COMMANDS
# ════════════════════════════════════════════════════════════════

def cmd_recon(args):
    options = {
        "skip_whois": args.no_whois, "skip_subdomains": args.no_subdomains,
        "skip_http": args.no_http, "skip_emails": args.no_emails,
        "skip_ip_intel": args.no_ip_intel, "skip_active_subdomain_scan": args.passive_only,
        "subdomain_verify_limit": args.subdomain_limit,
    }

    if not args.json:
        info(f"Running full reconnaissance on {args.domain}...")

    result = report.run_full_recon(args.domain, options=options)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return

    print()
    print_findings_section(result["exposure_findings"])
    print_dns_section(result["dns"])
    if result["whois"] is not None:
        print_whois_section(result["whois"])
    if result["subdomains"] is not None:
        print_subdomains_section(result["subdomains"])
    if result["http"] is not None:
        print_http_section(result["http"], result["common_paths"])
    if result["emails"] is not None:
        print_emails_section(result["emails"])
    if result["ip_intel"] is not None:
        print_ip_intel_section(result["ip_intel"])


def cmd_dns(args):
    if args.all:
        results = dns_recon.full_lookup(args.domain)
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print_dns_section(results)
    else:
        result = dns_recon.query(args.domain, args.type)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if not result["success"]:
                err(result["error"]); sys.exit(1)
            print()
            for rec in result["records"]:
                print(f"  {rec['type']:<8} {rec['value']}  {DIM}(TTL {rec['ttl']}s){R}")
            print()


def cmd_whois(args):
    result = whois_lookup.lookup(args.domain)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_whois_section(result)
        if args.raw and result["success"]:
            print(SEP)
            print(result["raw_text"])
    sys.exit(0 if result["success"] else 1)


def cmd_subdomains(args):
    if not args.json:
        info(f"Enumerating subdomains for {args.domain} (this may take a moment)...")
    result = subdomain_enum.full_enumeration(args.domain, verify_limit=args.limit,
                                             include_active=not args.passive_only)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print()
        print_subdomains_section(result)


def cmd_ip(args):
    result = ip_intel.full_ip_report(args.ip)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print()
        print(f"  {VIO}{result['ip']}{R}")
        print(f"  {DIM}Reverse DNS:{R} {result['reverse_dns'] or '—'}")
        if result["geolocation"]["success"]:
            g = result["geolocation"]
            print(f"  {DIM}Location:{R}    {g['city']}, {g['region']}, {g['country']}")
            print(f"  {DIM}ISP/Org:{R}     {g['isp']}")
            print(f"  {DIM}ASN:{R}         {g['asn']}")
        else:
            print(f"  {DIM}Geolocation:{R} {result['geolocation']['error']}")
        print()


# ════════════════════════════════════════════════════════════════
#  ARGPARSE
# ════════════════════════════════════════════════════════════════

def build_parser():
    p = argparse.ArgumentParser(
        prog="cli.py", description="PhantomRecon — OSINT Reconnaissance Aggregator",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("recon", help="Full reconnaissance report")
    sp.add_argument("domain")
    sp.add_argument("--no-whois", action="store_true")
    sp.add_argument("--no-subdomains", action="store_true")
    sp.add_argument("--no-http", action="store_true")
    sp.add_argument("--no-emails", action="store_true")
    sp.add_argument("--no-ip-intel", action="store_true")
    sp.add_argument("--passive-only", action="store_true", help="Skip active DNS subdomain scanning")
    sp.add_argument("--subdomain-limit", type=int, default=50, help="Max subdomains to verify-resolve")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_recon)

    sp = sub.add_parser("dns", help="DNS record lookup")
    sp.add_argument("domain")
    sp.add_argument("--type", default="A", help="Record type: A, AAAA, MX, TXT, NS, SOA, CAA, CNAME")
    sp.add_argument("--all", action="store_true", help="Query all common record types")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_dns)

    sp = sub.add_parser("whois", help="WHOIS lookup (exit 0=success, 1=failed)")
    sp.add_argument("domain")
    sp.add_argument("--raw", action="store_true", help="Also print the raw WHOIS response text")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_whois)

    sp = sub.add_parser("subdomains", help="Subdomain enumeration (crt.sh + active DNS)")
    sp.add_argument("domain")
    sp.add_argument("--passive-only", action="store_true")
    sp.add_argument("--limit", type=int, default=50, help="Max subdomains to verify-resolve")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_subdomains)

    sp = sub.add_parser("ip", help="IP geolocation + reverse DNS")
    sp.add_argument("ip")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_ip)

    return p


def main():
    if len(sys.argv) == 1:
        banner()
        build_parser().print_help()
        return
    args = build_parser().parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print(); info("Cancelled.")
        sys.exit(130)


if __name__ == "__main__":
    main()
