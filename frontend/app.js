const API = location.hostname === "localhost" || location.hostname === "127.0.0.1" ? "http://localhost:8000/api" : "/api";
let data = null;
const pages = ["overview", "sessions", "crypto", "ai", "certs", "reports"];
const titles = { overview: "Security Posture", sessions: "Reconstructed Sessions", crypto: "Cryptographic Analysis", ai: "AI Security Findings", certs: "Certificate Intelligence", reports: "Reports & Evidence" };

document.querySelectorAll("nav button").forEach((b) => {
  b.onclick = () => {
    document.querySelectorAll(".page").forEach((p) => p.classList.toggle("active", p.id === b.dataset.page));
    document.querySelectorAll("nav button").forEach((x) => x.classList.toggle("active", x === b));
    document.querySelector("#title").textContent = titles[b.dataset.page];
  };
});

function esc(x) {
  return String(x ?? "").replace(/[&<>"']/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));
}

function riskLabel(score) {
  if (score >= 80) return "LOW RISK";
  if (score >= 50) return "MEDIUM RISK";
  return "HIGH RISK";
}

function emptyResult() {
  return {
    summary: { posture_score: 0, risk: "HIGH RISK", session_count: 0, high_count: 0, medium_count: 0, certificate_count: 0, protocols: {}, tls_versions: {}, anomalies: 0, forward_secrecy_percent: "N/A" },
    sessions: [],
    findings: [],
    certificates: [],
    debug: {}
  };
}

function followFindings(list) {
  return list.slice(0, 5).map((f) => ({ level: f.severity === "HIGH" ? "red" : "yellow", text: `${f.title} — ${f.severity}` }));
}

function render(d) {
  data = d || emptyResult();
  const s = data.summary || emptyResult().summary;
  const score = Number(s.posture_score ?? 0);
  const sessionTotal = Number(s.session_count || 0);
  const tlsVersions = s.tls_versions || {};
  const protocolEntries = Object.entries(s.protocols || {}).filter(([, v]) => Number(v) > 0);
  const tlsEntries = Object.entries(s.tls_versions || {}).filter(([, v]) => Number(v) > 0);

  document.querySelector("#score").textContent = score;
  document.querySelector("#risk").textContent = riskLabel(score);
  document.querySelector("#sessions").textContent = sessionTotal;
  document.querySelector("#high").textContent = s.high_count ?? 0;
  document.querySelector("#medium").textContent = s.medium_count ?? 0;
  document.querySelector("#fs").textContent = s.forward_secrecy_percent === "N/A" ? "N/A" : `${s.forward_secrecy_percent}%`;

  if (protocolEntries.length) {
    document.querySelector("#protocols").innerHTML = protocolEntries.map(([k, v]) => `<div class=bar><b>${esc(k)}</b><div><i style="width:${sessionTotal ? (v / sessionTotal) * 100 : 0}%"></i></div><span>${v}</span></div>`).join("");
  } else {
    document.querySelector("#protocols").innerHTML = '<div class="finding"><p>No email sessions detected.</p></div>';
  }

  if (tlsEntries.length) {
    document.querySelector("#tls").innerHTML = tlsEntries.map(([k, v]) => `<div class=bar><b>TLS ${esc(k)}</b><div><i style="width:${sessionTotal ? (v / sessionTotal) * 100 : 0}%"></i></div><span>${v}</span></div>`).join("");
  } else {
    document.querySelector("#tls").innerHTML = '<div class="finding"><p>No TLS sessions detected.</p></div>';
  }

  const findings = data.findings || [];
  document.querySelector("#findings").innerHTML = findings.length
    ? findings.map((f) => `<div class=finding><b class="${f.severity === "HIGH" ? "red" : "yellow"}">${esc(f.severity)}</b> ${esc(f.title)}<p>${esc(f.description || f.detail || "")}${f.recommendation ? ` ${esc(f.recommendation)}` : ""}</p></div>`).join("")
    : '<div class="finding"><p>No findings generated for the uploaded PCAP.</p></div>';

  document.querySelector("#sessionRows").innerHTML = (data.sessions || []).map((x) => `<tr><td><span class="badge ${x.risk === "HIGH" || x.risk === "CRITICAL" ? "high" : x.risk === "MEDIUM" ? "med" : "low"}">${esc(x.risk || "LOW")}</span></td><td>${esc(x.protocol || "UNKNOWN")}</td><td>${esc(x.source || "—")} → ${esc(x.destination || "—")}</td><td>${esc(x.tls_version || "—")}</td><td>${esc(x.cipher || "—")}</td><td>${esc(x.key_exchange || "—")}</td><td>${esc(x.starttls || "—")}</td></tr>`).join("") || '<tr><td colspan=7>No sessions were extracted from the capture.</td></tr>';

  const modern = (Number(tlsVersions["1.3"] || 0) + Number(tlsVersions["1.2"] || 0));
  const modernPct = sessionTotal ? Math.round((modern / sessionTotal) * 100) : 0;
  document.querySelector("#modern").textContent = sessionTotal ? `${modernPct}%` : "0%";
  document.querySelector("#modernbar").style.width = `${sessionTotal ? modernPct : 0}%`;

  const fsValue = s.forward_secrecy_percent;
  const fsPct = fsValue === "N/A" ? null : Number(fsValue);
  document.querySelector("#fscore").textContent = fsPct === null ? "N/A" : `${fsPct}%`;
  document.querySelector("#fsbar").style.width = fsPct === null ? "0%" : `${fsPct}%`;
  document.querySelector("#legacy").textContent = (Number(tlsVersions["1.0"] || 0) + Number(tlsVersions["1.1"] || 0));
  document.querySelector("#aiscore").textContent = score;
  const aiMetricValues = document.querySelectorAll("#ai .metric b");
  const aiProgressBars = document.querySelectorAll("#ai .progress i");
  const anomalyConfidence = Number(s.anomaly_confidence_percent || 0);
  if (aiMetricValues[0]) aiMetricValues[0].textContent = `${score}%`;
  if (aiMetricValues[1]) aiMetricValues[1].textContent = `${anomalyConfidence}%`;
  if (aiProgressBars[0]) aiProgressBars[0].style.width = `${score}%`;
  if (aiProgressBars[1]) aiProgressBars[1].style.width = `${anomalyConfidence}%`;

  const cipher = {};
  (data.sessions || []).forEach((x) => {
    const key = x.cipher || "Unknown";
    cipher[key] = (cipher[key] || 0) + 1;
  });
  document.querySelector("#cipherList").innerHTML = Object.entries(cipher).length
    ? Object.entries(cipher).map(([k, v]) => `<div class=finding><b>${esc(k)}</b><p>${v} session(s) • ${/3DES|RC4|NULL|EXPORT|CBC/.test(k) ? "Review for weakness" : "Modern/acceptable based on configured policy"}</p></div>`).join("")
    : '<div class="finding"><p>No cipher suites were detected.</p></div>';

  const certs = data.certificates || [];
  const certValid = certs.filter((c) => String(c.status).toUpperCase() === "VALID").length;
  const certExpiring = certs.filter((c) => String(c.status).toUpperCase() === "EXPIRING_SOON").length;
  const certWeak = certs.filter((c) => ["WEAK", "INVALID", "EXPIRED"].includes(String(c.status).toUpperCase())).length;
  const certBlocks = document.querySelectorAll("#certs .bigmetric");
  certBlocks[0].textContent = certValid;
  certBlocks[1].textContent = certExpiring;
  certBlocks[2].textContent = certWeak;
  document.querySelector("#certRows").innerHTML = certs.length
    ? certs.map((c) => `<tr><td>${esc(c.subject || "—")}</td><td>${esc(c.issuer || "—")}</td><td>${esc(c.valid_until || "—")}</td><td>${esc(c.public_key || "—")}</td><td>${esc(c.signature || "—")}</td><td>${esc(c.status || "—")}</td></tr>`).join("")
    : '<tr><td colspan=6>No certificate objects were present in the capture.</td></tr>';

  const timeline = document.querySelector("#aiTimeline");
  if (timeline) {
    const events = followFindings(findings);
    timeline.innerHTML = events.length ? events.map((item) => `<p><span class="${item.level}">●</span> ${esc(item.text)}</p>`).join("") : '<p>No events recorded yet.</p>';
  }

  const alertBox = document.querySelector("#ai .panel.alert");
  if (alertBox) {
    const first = findings[0];
    if (first) {
      alertBox.innerHTML = `<b>${first.severity} — ${esc(first.title)}</b><p>${esc(first.description || first.title)}</p>${first.evidence && first.evidence.length ? `<strong>Evidence:</strong> <span>${esc(first.evidence.join(" | "))}</span>` : ""}`;
    } else {
      alertBox.innerHTML = '<b>Analysis pending</b><p>Upload a PCAP to generate findings.</p>';
    }
  }

  const debugContent = document.querySelector("#debugContent");
  if (debugContent) {
    const debug = data.debug || {};
    const entries = [
      ["Total packets", debug.total_packets ?? 0],
      ["TCP packets", debug.tcp_packets ?? 0],
      ["UDP packets", debug.udp_packets ?? 0],
      ["TCP streams", debug.tcp_streams ?? 0],
      ["SMTP streams", debug.smtp_streams ?? 0],
      ["IMAP streams", debug.imap_streams ?? 0],
      ["POP3 streams", debug.pop3_streams ?? 0],
      ["TLS sessions", debug.tls_sessions ?? 0],
      ["TLS 1.0 sessions", debug.tls_1_0_sessions ?? 0],
      ["TLS 1.1 sessions", debug.tls_1_1_sessions ?? 0],
      ["TLS 1.2 sessions", debug.tls_1_2_sessions ?? 0],
      ["TLS 1.3 sessions", debug.tls_1_3_sessions ?? 0],
      ["Certificates extracted", debug.certificates_extracted ?? 0],
      ["Findings generated", debug.findings_generated ?? 0]
    ];
    debugContent.innerHTML = "<ul>" + entries.map(([label, val]) => `<li><strong>${esc(label)}:</strong> ${val}</li>`).join("") + "</ul>";
  }
}

async function load() {
  try {
    const r = await fetch(API + "/demo");
    if (!r.ok) throw new Error("Demo data unavailable");
    render(await r.json());
  } catch (err) {
    render(emptyResult());
    toast("Demo data unavailable");
  }
}

load();

document.querySelector("#pcap").onchange = async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  document.querySelector("#fname").textContent = f.name;
  const fd = new FormData();
  fd.append("file", f);
  toast("Analyzing PCAP…");
  try {
    render(emptyResult());
    const r = await fetch(API + "/analyze", { method: "POST", body: fd });
    if (!r.ok) throw new Error(await r.text());
    render(await r.json());
    toast("PCAP analysis complete");
  } catch (err) {
    toast("PCAP analysis failed: " + err.message);
  }
};

function toast(t) {
  const x = document.querySelector("#toast");
  x.textContent = t;
  x.classList.add("show");
  setTimeout(() => x.classList.remove("show"), 3000);
}

document.querySelector("#jsonBtn").onclick = () => {
  if (!data) return;
  const b = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(b);
  a.download = "mail-vault-report.json";
  a.click();
};

document.querySelector("#htmlBtn").onclick = async () => {
  if (!data) return;
  const r = await fetch(API + "/report/html", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });
  const b = await r.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(b);
  a.download = "mail-vault-report.html";
  a.click();
};

document.querySelector("#pdfBtn").onclick = async () => {
  if (!data) return;
  const r = await fetch(API + "/report/pdf", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });
  const b = await r.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(b);
  a.download = "mail-vault-report.pdf";
  a.click();
};
