"""
PhantomRecon — HTTP Fingerprinting
═══════════════════════════════════════════════════════════════
Fetches a target site and extracts technology fingerprints from
response headers and HTML content — the same passive signals a
browser's "view source" reveals, aggregated and pattern-matched.
"""

import re
import requests

COMMON_PATHS_TO_CHECK = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/humans.txt", "/.well-known/change-password",
]

# (regex on header value or html content, technology label)
TECH_SIGNATURES = [
    (r"wordpress", "WordPress", "html"),
    (r"wp-content|wp-includes", "WordPress", "html"),
    (r"Drupal", "Drupal", "html"),
    (r"Joomla", "Joomla", "html"),
    (r"shopify", "Shopify", "html"),
    (r"wix\.com", "Wix", "html"),
    (r"squarespace", "Squarespace", "html"),
    (r"react", "React", "html"),
    (r"__next", "Next.js", "html"),
    (r"ng-version", "Angular", "html"),
    (r"vue", "Vue.js", "html"),
    (r"laravel_session", "Laravel", "cookie"),
    (r"django", "Django", "cookie"),
    (r"express", "Express.js", "header"),
    (r"nginx", "Nginx", "header"),
    (r"apache", "Apache", "header"),
    (r"cloudflare", "Cloudflare", "header"),
    (r"cf-ray", "Cloudflare", "header"),
    (r"varnish", "Varnish Cache", "header"),
    (r"php", "PHP", "header"),
    (r"asp\.net", "ASP.NET", "header"),
    (r"iis", "Microsoft IIS", "header"),
]


def fetch_and_fingerprint(url: str, timeout: float = 10.0) -> dict:
    """
    Fetches the target URL (adding https:// if no scheme given) and
    extracts headers, detected technologies, and common well-known paths.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True,
                           headers={"User-Agent": "Mozilla/5.0 (compatible; PhantomRecon/1.0)"})
    except requests.exceptions.SSLError:
        # Retry over plain HTTP if HTTPS isn't available
        try:
            url = url.replace("https://", "http://")
            resp = requests.get(url, timeout=timeout, allow_redirects=True,
                               headers={"User-Agent": "Mozilla/5.0 (compatible; PhantomRecon/1.0)"})
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": f"Could not connect over HTTP or HTTPS: {e}"}
    except requests.exceptions.Timeout:
        return {"success": False, "error": f"Request timed out after {timeout}s"}
    except requests.exceptions.ConnectionError as e:
        return {"success": False, "error": f"Connection failed: {e}"}
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": str(e)}

    headers = dict(resp.headers)
    html = resp.text[:100_000]  # cap for very large pages
    cookies = "; ".join(f"{c.name}" for c in resp.cookies)

    technologies = _detect_technologies(headers, html, cookies)
    meta_generator = _extract_meta_generator(html)
    if meta_generator and meta_generator not in technologies:
        technologies.append(meta_generator)

    title = _extract_title(html)
    security_headers_present = _check_security_headers(headers)

    return {
        "success": True, "final_url": resp.url, "status_code": resp.status_code,
        "title": title, "server_header": headers.get("Server"),
        "powered_by": headers.get("X-Powered-By"),
        "technologies": sorted(set(technologies)),
        "security_headers_present": security_headers_present,
        "all_headers": headers,
        "redirected": resp.url != url,
    }


def _detect_technologies(headers: dict, html: str, cookies: str) -> list:
    found = []
    header_blob = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    html_lower = html.lower()

    for pattern, label, source in TECH_SIGNATURES:
        haystack = {"header": header_blob, "html": html_lower, "cookie": cookies.lower()}[source]
        if re.search(pattern, haystack, re.IGNORECASE):
            found.append(label)
    return found


def _extract_meta_generator(html: str) -> str:
    m = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
    return m.group(1) if m else None


def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
    return m.group(1).strip() if m else None


def _check_security_headers(headers: dict) -> dict:
    checks = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
             "X-Content-Type-Options", "Referrer-Policy"]
    return {h: h in headers for h in checks}


def check_common_paths(base_url: str, timeout: float = 8.0) -> list:
    """Check for the presence of common well-known files (robots.txt, sitemap.xml, security.txt)."""
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    base_url = base_url.rstrip("/")

    results = []
    for path in COMMON_PATHS_TO_CHECK:
        try:
            resp = requests.get(base_url + path, timeout=timeout, allow_redirects=True,
                               headers={"User-Agent": "Mozilla/5.0 (compatible; PhantomRecon/1.0)"})
            results.append({
                "path": path, "exists": resp.status_code == 200,
                "status_code": resp.status_code,
                "preview": resp.text[:200] if resp.status_code == 200 else None,
            })
        except requests.exceptions.RequestException:
            results.append({"path": path, "exists": False, "status_code": None, "preview": None})

    return results
