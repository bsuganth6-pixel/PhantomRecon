// PhantomRecon — Shared frontend utilities

const PR = {
  esc(s) { if(s==null) return ""; return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); },

  async postJSON(url, body) {
    const r = await fetch(url, { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body||{}) });
    return r.json();
  },
  setLoading(loader, btn, on) { if(loader) loader.classList.toggle("active", on); if(btn) btn.disabled = on; },

  toast(msg, type="info", ms=4000) {
    const c = document.getElementById("toast-container"); if(!c) return;
    const el = document.createElement("div"); el.className = `toast ${type}`;
    const icon = type==="success"?"circle-check":type==="error"?"circle-exclamation":"circle-info";
    el.innerHTML = `<i class="fa-solid fa-${icon}"></i><span>${this.esc(msg)}</span>`;
    c.appendChild(el);
    setTimeout(()=>{ el.style.animation="toastOut 0.2s ease forwards"; setTimeout(()=>el.remove(),200); }, ms);
  },

  sevIcon(sev) {
    return {critical:"circle-exclamation", high:"triangle-exclamation",
            medium:"circle-exclamation", low:"circle-info", info:"circle-check"}[sev] || "circle-info";
  },

  finding(f) {
    return `
      <div class="finding sev-${f.severity}">
        <div class="finding-icon"><i class="fa-solid fa-${this.sevIcon(f.severity)}"></i></div>
        <div class="finding-body">
          <strong>${this.esc(f.title)}<span class="sev-badge ${f.severity}">${f.severity}</span></strong>
          <span>${this.esc(f.detail)}</span>
        </div>
      </div>`;
  },

  statusPill(success, skipped) {
    if (skipped) return `<span class="section-status skip"><i class="fa-solid fa-minus"></i> Skipped</span>`;
    return success
      ? `<span class="section-status ok"><i class="fa-solid fa-check"></i> OK</span>`
      : `<span class="section-status fail"><i class="fa-solid fa-xmark"></i> Failed</span>`;
  },

  // ── DNS records grouped display ──
  renderDnsRecords(dnsResult) {
    let html = "";
    for (const [type, result] of Object.entries(dnsResult)) {
      if (!result.success || !result.records.length) continue;
      html += `<div class="dns-group">
        <div class="dns-group-title"><i class="fa-solid fa-tag"></i> ${type} (${result.records.length})</div>
        ${result.records.map(r => `<div class="dns-record">${this.esc(r.value)}<span class="rec-ttl">TTL ${r.ttl}s</span></div>`).join("")}
      </div>`;
    }
    return html || `<div class="empty-state"><i class="fa-solid fa-circle-info"></i><p style="font-size:12px">No DNS records resolved.</p></div>`;
  },
};
