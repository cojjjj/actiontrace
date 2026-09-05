"""Dependency-free terminal, SARIF 2.1.0, and self-contained HTML reports."""
import html
from urllib.parse import quote
from .analyzer import RULES


def terminal(report):
    lines = [f"ActionTrace | {report.files_scanned} files | {len(report.findings)} findings"]
    for finding in report.findings:
        lines.append(f"\n[{finding.severity.upper()}] {finding.rule} {finding.title}")
        lines.append(f"  {finding.path}:{finding.line} (job: {finding.job})")
        for node in finding.trace:
            lines.append(f"  -> {node.path}:{node.line} {node.message}")
        lines.append(f"  Fix: {finding.remediation}")
    for diagnostic in report.diagnostics:
        lines.append(f"\n{diagnostic['level'].upper()}: {diagnostic['path']}: {diagnostic['message']}")
    return "\n".join(lines) + "\n"


def location(path, line):
    return {"physicalLocation": {"artifactLocation": {"uri": quote(path, safe="/"), "uriBaseId": "%SRCROOT%"}, "region": {"startLine": line}}}


def sarif(report):
    results = []
    for finding in report.findings:
        results.append({
            "ruleId": finding.rule,
            "level": {"high": "error", "medium": "warning", "low": "note"}[finding.severity],
            "message": {"text": finding.message + "\nRemediation: " + finding.remediation},
            "locations": [location(finding.path, finding.line)],
            "partialFingerprints": {"actiontrace/v1": finding.fingerprint},
            "properties": {"confidence": finding.confidence, "severity": finding.severity},
            "codeFlows": [{"threadFlows": [{"locations": [
                {"location": {**location(node.path, node.line), "message": {"text": node.message}}}
                for node in finding.trace
            ]}]}],
        })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "ActionTrace", "version": "0.1.0", "rules": [
            {"id": key, "shortDescription": {"text": title}, "help": {"text": fix}}
            for key, (title, fix) in RULES.items()
        ]}},
        "invocations": [{"executionSuccessful": not any(d["level"] == "error" for d in report.diagnostics),
                         "toolExecutionNotifications": [{"level": "error" if d["level"] == "error" else "warning", "message": {"text": f"{d['path']}: {d['message']}"}} for d in report.diagnostics]}],
        "results": results,
    }]}


def html_report(report):
    escape = html.escape
    cards = []
    for finding in report.findings:
        trace = "".join(f"<li><code>{escape(n.path)}:{n.line}</code><span>{escape(n.message)}</span></li>" for n in finding.trace)
        cards.append(f"""<article data-severity="{finding.severity}">
<div class="meta"><b class="badge {finding.severity}">{finding.severity.upper()}</b> {finding.rule} · {finding.confidence} confidence</div>
<h2>{escape(finding.title)}</h2><p class="where">{escape(finding.path)}:{finding.line} · job {escape(finding.job)}</p>
<p>{escape(finding.message)}</p><ol>{trace}</ol><div class="fix"><strong>Remediation</strong><p>{escape(finding.remediation)}</p></div>
</article>""")
    diagnostics = "".join(f"<li>{escape(d['level'].upper())} · {escape(d['path'])}: {escape(d['message'])}</li>" for d in report.diagnostics)
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ActionTrace · Trust boundary report</title><style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#0b1020;color:#e4eafa}body{max-width:1060px;margin:auto;padding:44px 24px}header{border-bottom:1px solid #303952;padding-bottom:32px}h1{font-size:clamp(40px,7vw,72px);letter-spacing:-3px;margin:8px 0}h2{font-size:21px}.eyebrow{color:#5ee0c2;letter-spacing:3px;font-size:12px;font-weight:700}.sub{color:#b0bed8;max-width:680px;line-height:1.7}.stats{display:flex;gap:36px;margin:24px 0}.stats b{display:block;font-size:30px}.stats span{color:#a2b0ca;font-size:13px}nav{display:flex;gap:10px;flex-wrap:wrap;margin:24px 0}button{background:#172139;color:#e4eafa;border:1px solid #44506a;border-radius:20px;padding:9px 18px;cursor:pointer}button[aria-pressed=true]{background:#5ee0c2;color:#071e19}article{background:#121b30;border:1px solid #2a3751;border-radius:14px;padding:25px;margin:18px 0}p{line-height:1.6}.meta,.where{font-size:13px;color:#a9b8d2}.badge{padding:4px 9px;border-radius:5px;margin-right:9px}.high{color:#ffb6bb;background:#582637}.medium{color:#ffdc91;background:#4a3c26}.low{color:#a7c6ff;background:#263d60}ol{border-left:2px solid #418876;margin-left:8px;padding-left:26px}li{padding:8px 0;line-height:1.5;overflow-wrap:anywhere}li span{display:block;color:#bac7df}code{font-size:12px;color:#72e5ce}.fix{background:#0c1526;border-radius:8px;padding:15px}.fix strong{color:#5ee0c2;font-size:12px;text-transform:uppercase;letter-spacing:1px}.fix p{margin-bottom:0}footer{color:#a5b4ce;font-size:13px;margin:32px 0}[hidden]{display:none}
</style></head><body><header><div class="eyebrow">OFFLINE SECURITY ANALYSIS / V0.1</div><h1>ActionTrace<span style="color:#5ee0c2">.</span></h1>
<p class="sub">Follow the data. Review the trust boundary.<br>Evidence paths from workflow inputs to executable code, with explicit uncertainty and actionable fixes.</p>
""" + f"<div class='stats'><div><b>{len(report.findings)}</b><span>findings</span></div><div><b>{report.files_scanned}</b><span>files analyzed</span></div><div><b>{len(report.diagnostics)}</b><span>coverage diagnostics</span></div></div>" + """</header>
<nav aria-label="Filter severity"><button aria-pressed="true" data-filter="all">All findings</button><button aria-pressed="false" data-filter="high">High</button><button aria-pressed="false" data-filter="medium">Medium</button><button aria-pressed="false" data-filter="low">Low</button></nav><main>""" + ("".join(cards) or "<p>No modeled findings. Review coverage diagnostics and limitations before drawing conclusions.</p>") + f"</main><section><h2>Coverage diagnostics</h2><ul>{diagnostics or '<li>No additional diagnostics.</li>'}</ul></section>" + """<footer>Static review candidates, not proof of exploitation. Remote action code, dynamic outputs, access policies, and arbitrary shell semantics are outside this analysis. No workflows were executed.</footer>
<script>document.querySelectorAll('button[data-filter]').forEach(button=>button.addEventListener('click',()=>{document.querySelectorAll('button[data-filter]').forEach(b=>b.setAttribute('aria-pressed',String(b===button)));document.querySelectorAll('article').forEach(card=>card.hidden=button.dataset.filter!=='all'&&card.dataset.severity!==button.dataset.filter);}));</script></body></html>"""
