from __future__ import annotations
import html
import json
from pathlib import Path

REPORT_TYPES = {
    "web": {
        "title": "Web Application Security Assessment",
        "summary": "This report details the findings of a comprehensive Web Application Penetration Test. The assessment is intended to identify security vulnerabilities mapping to the OWASP Top 10 framework, including injection flaws, broken authentication, and cross-site scripting (XSS).",
        "target_prefix": "Target",
        "type_line": "Application URL / Name",
        "finding_column": "OWASP Category",
        "method": "The assessment covered all authenticated and unauthenticated workflows on the primary web domain. Automated scanning was complemented by intensive manual exploitation using proxy tools.",
        "accent": "#2563eb",
    },
    "network": {
        "title": "Network Infrastructure Assessment",
        "summary": "This report outlines the findings of the Network Penetration Test performed against the assessed infrastructure. The objective was to identify misconfigurations, unpatched CVEs, exposed administrative interfaces, and opportunities for lateral movement across the network perimeter.",
        "target_prefix": "Target",
        "type_line": "Internal / External",
        "finding_column": "Affected Host/IP",
        "method": "The assessment targeted the IP ranges provided in the Rules of Engagement (RoE). The methodology included host discovery, port scanning, service enumeration, and targeted exploitation of identified services.",
        "accent": "#16a34a",
    },
    "api": {
        "title": "API Security Testing Report",
        "summary": "This report presents the results of the API security assessment conducted on the assessed endpoints. Testing evaluated the endpoints against the OWASP API Security Top 10, specifically scrutinizing authentication mechanisms, authorization (BOLA/BFLA), rate limiting, and data exposure.",
        "target_prefix": "Target",
        "type_line": "REST / GraphQL",
        "finding_column": "OWASP API Category",
        "method": "Testing was performed on the provided API endpoints and documentation. Request/response structures were analyzed, tokens were manipulated, and cross-tenant data access controls were tested.",
        "accent": "#9333ea",
    },
}
SEVERITY_ORDER = ("critical", "high", "medium", "low")

def _escape(value):
    return html.escape(str(value if value is not None else ""))

def _category(finding, config):
    return finding.get(config["finding_column"].lower().replace(" ", "_")) or finding.get("owasp_category") or finding.get("category") or finding.get("owasp") or "—"

def _finding_rows(report, config):
    rows=[]
    for finding in report.get("findings", []):
        sev=str(finding.get("severity", "info")).lower()
        rows.append(
            "<tr>"
            f"<td><span class='pill sev-{_escape(sev)}'>{_escape(sev.title())}</span></td>"
            f"<td>{_escape(finding.get('name'))}</td>"
            f"<td>{_escape(_category(finding, config))}</td>"
            f"<td>{_escape(finding.get('validation_status') or 'Open')}</td>"
            "</tr>"
        )
    return "".join(rows) or "<tr><td colspan='4' class='empty'>No validated/corroborated findings.</td></tr>"

def _counts(findings):
    return {sev: sum(1 for f in findings if str(f.get("severity", "")).lower() == sev) for sev in SEVERITY_ORDER}

def write_reports(report, output_dir, html_enabled=True):
    output_dir=Path(output_dir); output_dir.mkdir(parents=True, exist_ok=True)
    json_path=output_dir/'report.json'; json_path.write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    paths={'json':json_path}
    if not html_enabled: return paths
    report_type=report.get('meta',{}).get('report_type','web'); config=REPORT_TYPES.get(report_type,REPORT_TYPES['web'])
    findings=report.get('findings',[]); counts=_counts(findings); meta=report.get('meta',{}); surface=report.get('attack_surface',{})
    client=meta.get('client') or '—'; assessment=meta.get('assessment') or '—'; target=meta.get('target') or '—'; version=meta.get('version') or '—'
    date=str(meta.get('started_at',''))[:10] or '—'
    if report_type=='network':
        target_type='Internal / External'; surface_line=f"Open ports identified: {len(surface.get('ports',[]))} | Technologies/services: {len(surface.get('technologies',[]))}"
    else:
        target_type='REST / GraphQL' if report_type=='api' else 'Web Application'; surface_line=f"Endpoints identified: {len(surface.get('endpoints',[]))} | Technologies identified: {len(surface.get('technologies',[]))}"
    testssl_results=[r for r in report.get('results',[]) if r.get('tool')=='testssl.sh']
    testssl_block=''
    if testssl_results:
        tr=testssl_results[-1]
        testssl_block=("<section class='scope'><b>Tooling:</b> TLS/SSL assessment was performed with testssl.sh "
                       f"({ _escape(tr.get('status','unknown')) }). Official repository: "
                       "<a href='https://github.com/testssl/testssl.sh' rel='noopener'>github.com/testssl/testssl.sh</a>.</section>")
    suppressed=' ; '.join(f"{x.get('candidate','')} [{x.get('severity','')}] — {x.get('reason','')}" for x in report.get('not_reported',[])) or 'No suppressed candidates.'
    page=f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{_escape(config['title'])}</title>
<style>
:root{{--accent:{config['accent']};--ink:#202938;--muted:#64748b;--line:#dce3eb}}*{{box-sizing:border-box}}body{{margin:0;background:#fff;color:var(--ink);font-family:Arial,Helvetica,sans-serif}}.page{{width:min(1120px,calc(100% - 44px));margin:42px auto;padding-bottom:60px}}.header{{background:#f7f9fb;border:1px solid #dde5ed;border-left:7px solid var(--accent);padding:19px 22px}}h1{{font-size:23px;margin:0 0 9px}}.meta{{font-size:13px;color:#475569;display:flex;gap:18px;flex-wrap:wrap}}h2{{font-size:17px;margin:28px 0 10px;padding-bottom:8px;border-bottom:2px solid var(--line)}}p{{font-size:14px;line-height:1.55}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:14px 0 30px}}.metric{{border:1px solid var(--line);min-height:94px;text-align:center;padding:12px 10px;position:relative}}.metric:before{{content:"";position:absolute;left:0;right:0;top:0;height:4px;background:var(--bar)}}.label{{font-size:12px;color:#667085;text-transform:uppercase;font-weight:700;letter-spacing:.5px;margin-top:8px}}.value{{font-size:25px;font-weight:700;margin-top:8px;color:#111827}}table{{width:100%;border-collapse:collapse;border:1px solid var(--line);font-size:13px}}th,td{{padding:10px 12px;border-bottom:1px solid #e6ebf1;text-align:left;vertical-align:top}}th{{background:#eef2f7}}tr:nth-child(even) td{{background:#fbfcfe}}.pill{{display:inline-block;border-radius:999px;padding:4px 10px;font-size:11px;font-weight:700;min-width:72px;text-align:center}}.sev-critical{{background:#fee2e2;color:#991b1b}}.sev-high{{background:#ffedd5;color:#9a3412}}.sev-medium{{background:#fef3c7;color:#92400e}}.sev-low{{background:#dbeafe;color:#1d4ed8}}.sev-info{{background:#e2e8f0;color:#334155}}.scope{{background:#f8fafc;border:1px solid var(--line);padding:14px 16px;margin-top:18px;font-size:13px;line-height:1.55}}.small{{font-size:12px;color:var(--muted)}}.empty{{text-align:center;color:var(--muted);padding:22px}}.footer{{margin-top:34px;padding-top:12px;border-top:1px solid var(--line);font-size:11px;color:#7a8594;display:flex;justify-content:space-between}}a{{color:#2563eb}}@media(max-width:760px){{.grid{{grid-template-columns:repeat(2,1fr)}}}}@media print{{.page{{width:100%;margin:0;padding:18mm}}}}
</style></head><body><main class="page">
<section class="header"><h1>{_escape(config['title'])}</h1><div class="meta"><span>{_escape(config['target_prefix'])}: {_escape(target)}</span><span>Date: {_escape(date)}</span><span>Type: {_escape(target_type)}</span><span>Version: {_escape(version)}</span></div></section>
<h2>EXECUTIVE SUMMARY</h2><p>{_escape(config['summary'])}</p><p class="small"><b>Client:</b> {_escape(client)} &nbsp; | &nbsp; <b>Assessment:</b> {_escape(assessment)} &nbsp; | &nbsp; <b>Scan ID:</b> {_escape(meta.get('scan_id') or '—')}</p>
<h2>VULNERABILITY OVERVIEW</h2><section class="grid"><div class="metric" style="--bar:#dc2626"><div class="label">Critical</div><div class="value">{counts['critical']}</div></div><div class="metric" style="--bar:#f97316"><div class="label">High</div><div class="value">{counts['high']}</div></div><div class="metric" style="--bar:#eab308"><div class="label">Medium</div><div class="value">{counts['medium']}</div></div><div class="metric" style="--bar:#3b82f6"><div class="label">Low</div><div class="value">{counts['low']}</div></div></section>
<h2>FINDINGS LOG</h2><table><thead><tr><th>Severity</th><th>Vulnerability Name</th><th>{_escape(config['finding_column'])}</th><th>Status</th></tr></thead><tbody>{_finding_rows(report,config)}</tbody></table>
<section class="scope"><b>Scope &amp; Methodology:</b> {_escape(config['method'])}</section><section class="scope"><b>Assessment Type:</b> {_escape(report_type.title())} &nbsp; | &nbsp; {_escape(surface_line)}</section>{testssl_block}
<section class="scope"><b>Why ReconForge Did NOT Report This:</b><br>{_escape(suppressed)}</section>
<div class="footer"><span>ReconForge Advanced Recon Report v{_escape(version)}</span><span>Generated: {_escape(meta.get('ended_at') or '—')}</span></div></main></body></html>'''
    html_path=output_dir/'report.html'; html_path.write_text(page,encoding='utf-8'); paths['html']=html_path; return paths
