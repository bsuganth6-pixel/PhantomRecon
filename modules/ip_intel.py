"""
PhantomRecon — IP Intelligence
═══════════════════════════════════════════════════════════════
Given an IP address, reports geolocation, hosting organization/ASN,
and reverse DNS. Uses ip-api.com's free tier (no key required,
45 req/min limit) for geolocation/ASN, plus our own DNS module for
the PTR lookup — so even if the geolocation API is unreachable, we
still get reverse-DNS hostname info independently.
"""

import requests
from modules import dns_recon

IP_API_URL = "http://ip-api.com/json/{ip}"
IP_API_FIELDS = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"


def geolocate(ip: str, timeout: float = 8.0) -> dict:
    """Query ip-api.com for geolocation + ASN/org info on a single IP."""
    try:
        resp = requests.get(IP_API_URL.format(ip=ip), params={"fields": IP_API_FIELDS}, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        return {"success": False, "error": "Geolocation request timed out."}
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"Geolocation request failed: {e}"}
    except ValueError:
        return {"success": False, "error": "Geolocation API returned invalid JSON."}

    if data.get("status") != "success":
        return {"success": False, "error": data.get("message", "Geolocation lookup failed.")}

    return {
        "success": True, "ip": data.get("query"),
        "country": data.get("country"), "country_code": data.get("countryCode"),
        "region": data.get("regionName"), "city": data.get("city"),
        "zip": data.get("zip"), "lat": data.get("lat"), "lon": data.get("lon"),
        "timezone": data.get("timezone"), "isp": data.get("isp"),
        "org": data.get("org"), "asn": data.get("as"),
    }


def full_ip_report(ip: str, resolver: str = None) -> dict:
    """Combines geolocation + reverse DNS for a complete picture of one IP."""
    geo = geolocate(ip)
    ptr = dns_recon.reverse_lookup(ip, resolver=resolver)
    hostname = ptr["records"][0]["value"] if ptr["success"] and ptr["records"] else None

    return {"ip": ip, "geolocation": geo, "reverse_dns": hostname, "ptr_raw": ptr}


def report_for_domain(domain: str, resolver: str = None) -> dict:
    """Resolves a domain to its IP(s) and runs full_ip_report on each."""
    a_result = dns_recon.query(domain, "A", resolver=resolver)
    if not a_result["success"]:
        return {"success": False, "error": a_result["error"], "ips": []}

    ips = [r["value"] for r in a_result["records"]]
    reports = [full_ip_report(ip, resolver=resolver) for ip in ips]
    return {"success": True, "domain": domain, "ips": ips, "reports": reports}
