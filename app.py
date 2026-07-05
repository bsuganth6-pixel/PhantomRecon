#!/usr/bin/env python3
"""
PhantomRecon — OSINT Reconnaissance Aggregator
Tabs: Full Recon | Detection Reference
"""

import os
import secrets
from flask import Flask, render_template, request, jsonify

from modules import dns_recon, whois_lookup, subdomain_enum, http_fingerprint, email_harvest, ip_intel, report

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))


@app.route("/")
def index():
    return render_template("index.html", active="recon")


@app.route("/reference")
def reference_page():
    return render_template("reference.html", active="reference")


@app.route("/api/recon", methods=["POST"])
def api_recon():
    data = request.get_json(force=True)
    domain = (data.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "No domain provided."}), 400

    options = {
        "skip_whois": data.get("skip_whois", False),
        "skip_subdomains": data.get("skip_subdomains", False),
        "skip_active_subdomain_scan": data.get("skip_active_subdomain_scan", False),
        "skip_http": data.get("skip_http", False),
        "skip_emails": data.get("skip_emails", False),
        "skip_ip_intel": data.get("skip_ip_intel", False),
        "subdomain_verify_limit": int(data.get("subdomain_verify_limit", 50)),
    }

    result = report.run_full_recon(domain, options=options)
    return jsonify(result)


@app.route("/api/dns", methods=["POST"])
def api_dns():
    data = request.get_json(force=True)
    domain = (data.get("domain") or "").strip()
    record_type = data.get("record_type", "A")
    if not domain:
        return jsonify({"error": "No domain provided."}), 400
    result = dns_recon.query(domain, record_type)
    return jsonify(result)


@app.route("/api/whois", methods=["POST"])
def api_whois():
    data = request.get_json(force=True)
    domain = (data.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "No domain provided."}), 400
    return jsonify(whois_lookup.lookup(domain))


@app.route("/api/subdomains", methods=["POST"])
def api_subdomains():
    data = request.get_json(force=True)
    domain = (data.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "No domain provided."}), 400
    result = subdomain_enum.full_enumeration(
        domain, verify_limit=int(data.get("verify_limit", 50)),
        include_active=not data.get("skip_active", False))
    return jsonify(result)


@app.route("/api/status")
def api_status():
    return jsonify({"ok": True})


if __name__ == "__main__":
    print(r"""
   ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
   ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
        R E C O N  —  OSINT Reconnaissance Aggregator
        http://127.0.0.1:5055
    """)
    app.run(debug=True, host="127.0.0.1", port=5055)
