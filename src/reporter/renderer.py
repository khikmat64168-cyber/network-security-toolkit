"""
Pure HTML renderer.

render(data) → str   — the only public symbol.

The returned string is a complete, self-contained HTML5 document with
all CSS inlined.  No external CDN, no images, no fonts to fetch —
safe to open offline and share as a single file.
"""
from __future__ import annotations

from html import escape

from src.reporter.models import InterfaceInfo, ReportData, TLSFinding

# ── Inline CSS ────────────────────────────────────────────────────────────────

_CSS = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:         #0d1117;
  --surface:    #161b22;
  --surface2:   #1c2128;
  --border:     #30363d;
  --text:       #c9d1d9;
  --muted:      #8b949e;
  --accent:     #58a6ff;
  --ok:         #3fb950;
  --warning:    #e3b341;
  --high:       #ff7b72;
  --critical:   #ff4040;
  --error:      #d2a8ff;
}

body {
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  font-size: 14px;
  line-height: 1.6;
}

/* ── Header ─────────────────────────────────────────────────────── */
header {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 20px 0;
}
.hdr-inner {
  max-width: 1080px;
  margin: 0 auto;
  padding: 0 20px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
.logo {
  font-size: 20px;
  font-weight: 700;
  color: var(--accent);
  letter-spacing: -0.3px;
}
.logo em { color: var(--muted); font-style: normal; font-weight: 400; }
.meta    { color: var(--muted); font-size: 12px; text-align: right; line-height: 1.8; }
.meta strong { color: var(--text); }

/* ── Layout ──────────────────────────────────────────────────────── */
.wrap { max-width: 1080px; margin: 0 auto; padding: 28px 20px 48px; }

/* ── Summary cards ───────────────────────────────────────────────── */
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin-bottom: 36px;
}
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 18px 12px;
  text-align: center;
}
.card .val   { font-size: 34px; font-weight: 700; line-height: 1; margin-bottom: 5px; }
.card .lbl   { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.6px; }
.c-ok   .val { color: var(--ok); }
.c-warn .val { color: var(--warning); }
.c-high .val { color: var(--high); }
.c-crit .val { color: var(--critical); border-color: #600; }
.c-acc  .val { color: var(--accent); }

/* ── Section ─────────────────────────────────────────────────────── */
.section { margin-bottom: 36px; }
.section-hdr {
  display: flex;
  align-items: baseline;
  gap: 10px;
  border-bottom: 1px solid var(--border);
  padding-bottom: 8px;
  margin-bottom: 16px;
}
.section-hdr h2 { font-size: 15px; font-weight: 600; }
.section-hdr .cnt { color: var(--muted); font-size: 12px; }

/* ── Table ───────────────────────────────────────────────────────── */
.tbl-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 6px; }
table  { width: 100%; border-collapse: collapse; }
thead th {
  background: var(--surface);
  color: var(--muted);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  padding: 8px 14px;
  text-align: left;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}
tbody td {
  padding: 9px 14px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover td { background: rgba(255,255,255,0.025); }
.mono { font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', monospace; font-size: 12px; }

/* ── Severity badge ──────────────────────────────────────────────── */
.badge {
  display: inline-block;
  padding: 2px 9px;
  border-radius: 20px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.4px;
  white-space: nowrap;
}
.b-ok   { background: #1a3a1a; color: var(--ok); }
.b-warn { background: #3a2a00; color: var(--warning); }
.b-high { background: #3a1a1a; color: var(--high); }
.b-crit { background: #2a0000; color: var(--critical); border: 1px solid #600; }
.b-err  { background: #2a1a3a; color: var(--error); }

/* ── Issues list ─────────────────────────────────────────────────── */
.issues    { list-style: none; }
.issues li { font-size: 12px; color: var(--muted); padding: 1px 0; }
.issues li::before { content: "⚠ "; color: var(--warning); }

/* ── Star (default interface) ────────────────────────────────────── */
.star { color: var(--warning); }

/* ── Empty state ─────────────────────────────────────────────────── */
.empty { color: var(--muted); text-align: center; padding: 28px; }

/* ── Footer ──────────────────────────────────────────────────────── */
footer {
  margin-top: 48px;
  padding-top: 16px;
  border-top: 1px solid var(--border);
  color: var(--muted);
  font-size: 12px;
  text-align: center;
}
"""


# ── Severity helpers ──────────────────────────────────────────────────────────

def _badge(severity: str) -> str:
    cls = {
        "ok":       "b-ok",
        "warning":  "b-warn",
        "high":     "b-high",
        "critical": "b-crit",
        "error":    "b-err",
    }.get(severity, "b-warn")
    label = {
        "ok":       "OK",
        "warning":  "WARNING",
        "high":     "HIGH",
        "critical": "CRITICAL",
        "error":    "ERROR",
    }.get(severity, severity.upper())
    return f'<span class="badge {cls}">{label}</span>'


def _expiry_cell(days: int | None, error: bool) -> str:
    if error:
        return '<span class="badge b-err">N/A</span>'
    if days is None:
        return "—"
    if days < 0:
        return f'<span class="badge b-crit">Expired {abs(days)}d ago</span>'
    if days <= 14:
        return f'<span class="badge b-crit">{days}d</span>'
    if days <= 30:
        return f'<span class="badge b-warn">{days}d</span>'
    return f'<span style="color:var(--ok)">{days}d</span>'


# ── Section renderers ─────────────────────────────────────────────────────────

def _render_cards(data: ReportData) -> str:
    tls_total = len(data.tls_findings)
    iface_total = len(data.interfaces)
    return f"""
<div class="cards">
  <div class="card c-acc">
    <div class="val">{tls_total}</div>
    <div class="lbl">Hosts Scanned</div>
  </div>
  <div class="card c-ok">
    <div class="val">{data.ok_tls_count}</div>
    <div class="lbl">TLS OK</div>
  </div>
  <div class="card c-warn">
    <div class="val">{data.warning_tls_count}</div>
    <div class="lbl">Warnings</div>
  </div>
  <div class="card c-high">
    <div class="val">{data.high_tls_count}</div>
    <div class="lbl">High Issues</div>
  </div>
  <div class="card c-crit">
    <div class="val">{data.critical_tls_count}</div>
    <div class="lbl">Critical</div>
  </div>
  <div class="card c-acc">
    <div class="val">{iface_total}</div>
    <div class="lbl">Interfaces</div>
  </div>
</div>"""


def _render_tls_section(findings: list[TLSFinding]) -> str:
    cnt = len(findings)
    if cnt == 0:
        return ""

    rows = ""
    for f in findings:
        issues_html = ""
        if f.issues:
            items = "".join(
                f"<li>{escape(issue)}</li>" for issue in f.issues
            )
            issues_html = f'<ul class="issues">{items}</ul>'
        else:
            issues_html = '<span style="color:var(--ok)">None</span>'

        rows += f"""
<tr>
  <td class="mono">{escape(f.host)}<span style="color:var(--muted)">:{f.port}</span></td>
  <td>{_badge(f.severity)}</td>
  <td class="mono" style="color:var(--muted)">{escape(f.tls_version)}</td>
  <td class="mono" style="color:var(--muted);font-size:11px">{escape(f.cipher_suite)}</td>
  <td>{_expiry_cell(f.days_until_expiry, f.severity == "error")}</td>
  <td style="min-width:220px">{issues_html}</td>
</tr>"""

    return f"""
<div class="section">
  <div class="section-hdr">
    <h2>TLS / Certificate Findings</h2>
    <span class="cnt">{cnt} host{"s" if cnt != 1 else ""}</span>
  </div>
  <div class="tbl-wrap">
    <table>
      <thead>
        <tr>
          <th>Host</th>
          <th>Status</th>
          <th>TLS Version</th>
          <th>Cipher Suite</th>
          <th>Expiry</th>
          <th>Issues</th>
        </tr>
      </thead>
      <tbody>{rows}
      </tbody>
    </table>
  </div>
</div>"""


def _render_interface_section(ifaces: list[InterfaceInfo]) -> str:
    cnt = len(ifaces)
    if cnt == 0:
        return ""

    rows = ""
    for iface in ifaces:
        star = ' <span class="star" title="Default capture interface">★</span>' if iface.is_default else ""
        rows += f"""
<tr>
  <td class="mono">{escape(iface.name)}{star}</td>
  <td class="mono" style="color:var(--ok)">{escape(iface.ip or "—")}</td>
  <td class="mono" style="color:var(--muted)">{escape(iface.mac or "—")}</td>
</tr>"""

    return f"""
<div class="section">
  <div class="section-hdr">
    <h2>Network Interfaces</h2>
    <span class="cnt">{cnt} interface{"s" if cnt != 1 else ""}</span>
  </div>
  <div class="tbl-wrap">
    <table>
      <thead>
        <tr>
          <th>Interface</th>
          <th>IP Address</th>
          <th>MAC Address</th>
        </tr>
      </thead>
      <tbody>{rows}
      </tbody>
    </table>
  </div>
</div>"""


# ── Public API ────────────────────────────────────────────────────────────────

def render(data: ReportData) -> str:
    """Return a complete, self-contained HTML5 document for *data*."""
    ts = data.generated_at.strftime("%Y-%m-%d %H:%M:%S")

    cards    = _render_cards(data)
    tls_sec  = _render_tls_section(data.tls_findings)
    ifc_sec  = _render_interface_section(data.interfaces)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NST Security Report — {escape(ts)}</title>
  <style>{_CSS}</style>
</head>
<body>
<header>
  <div class="hdr-inner">
    <div class="logo">Network Security Toolkit <em>/ Security Report</em></div>
    <div class="meta">
      Generated&nbsp;: <strong>{escape(ts)}</strong><br>
      Host&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: <strong>{escape(data.hostname)}</strong><br>
      Version&nbsp;&nbsp;&nbsp;: <strong>v{escape(data.toolkit_version)}</strong>
    </div>
  </div>
</header>
<div class="wrap">
  {cards}
  {tls_sec}
  {ifc_sec}
</div>
<footer>
  Generated by Network Security Toolkit v{escape(data.toolkit_version)} &mdash; {escape(ts)}
</footer>
</body>
</html>"""
