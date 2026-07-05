"""
PhantomRecon — Email Harvesting
═══════════════════════════════════════════════════════════════
Extracts email addresses that appear in ALREADY-PUBLICLY-PUBLISHED
page content (HTML, mailto: links, meta tags). This does NOT guess
or generate likely addresses (info@, admin@, etc.) — only what the
domain owner has actually put on their own public pages. This is
standard, non-invasive OSINT practice: the same information any
visitor sees by viewing the page source.

Also decodes simple email obfuscation patterns site owners commonly
use to deter basic scrapers: "user [at] domain [dot] com" and
similar text substitutions, plus mailto: links which are often
present even when the visible text is obfuscated.
"""

import re
import requests

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
MAILTO_RE = re.compile(r'mailto:([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})', re.IGNORECASE)

# Common de-obfuscation substitutions, applied before the main regex
OBFUSCATION_SUBS = [
    (re.compile(r"\s*\[\s*at\s*\]\s*", re.IGNORECASE), "@"),
    (re.compile(r"\s*\(\s*at\s*\)\s*", re.IGNORECASE), "@"),
    (re.compile(r"\s+at\s+", re.IGNORECASE), "@"),
    (re.compile(r"\s*\[\s*dot\s*\]\s*", re.IGNORECASE), "."),
    (re.compile(r"\s*\(\s*dot\s*\)\s*", re.IGNORECASE), "."),
    (re.compile(r"\s+dot\s+", re.IGNORECASE), "."),
]

# Filenames/extensions and false-positive patterns that look like emails but aren't
FALSE_POSITIVE_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".webp")


def _deobfuscate(text: str) -> str:
    for pattern, replacement in OBFUSCATION_SUBS:
        text = pattern.sub(replacement, text)
    return text


def extract_emails_from_text(text: str) -> set:
    """Pure text-processing function — no network. Testable in isolation."""
    found = set()

    for m in MAILTO_RE.finditer(text):
        found.add(m.group(1).lower())

    deobfuscated = _deobfuscate(text)
    for m in EMAIL_RE.finditer(deobfuscated):
        email = m.group(0).lower()
        if not any(email.endswith(suffix) for suffix in FALSE_POSITIVE_SUFFIXES):
            found.add(email)

    return found


def harvest_from_url(url: str, timeout: float = 10.0) -> dict:
    """Fetches one URL and extracts any email addresses present in its content."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        resp = requests.get(url, timeout=timeout,
                           headers={"User-Agent": "Mozilla/5.0 (compatible; PhantomRecon/1.0)"})
    except requests.exceptions.RequestException as e:
        return {"success": False, "emails": [], "error": str(e), "url": url}

    emails = extract_emails_from_text(resp.text)
    return {"success": True, "emails": sorted(emails), "url": resp.url, "error": None,
            "status_code": resp.status_code}


def harvest_from_multiple_pages(base_domain: str, paths: list = None, timeout: float = 10.0) -> dict:
    """
    Checks several common pages likely to list contact emails
    (homepage, /contact, /about, /team) and aggregates results.
    """
    paths = paths or ["/", "/contact", "/contact-us", "/about", "/about-us", "/team", "/support"]
    base = base_domain if base_domain.startswith(("http://", "https://")) else "https://" + base_domain
    base = base.rstrip("/")

    all_emails = set()
    per_page = []

    for path in paths:
        result = harvest_from_url(base + path, timeout=timeout)
        if result["success"] and result["emails"]:
            all_emails.update(result["emails"])
            per_page.append({"path": path, "emails": result["emails"]})
        elif not result["success"]:
            per_page.append({"path": path, "emails": [], "error": result["error"]})

    return {
        "domain": base_domain, "all_emails": sorted(all_emails),
        "total_found": len(all_emails), "per_page": per_page,
    }
