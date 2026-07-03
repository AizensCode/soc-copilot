"""Render an Investigation as a self-contained HTML report.

The copilot's output is a rich structured object; an analyst shouldn't have to
read JSON to triage. This turns an (Alert, Investigation) pair into a single,
dependency-free HTML file — no external CSS, fonts, or scripts — that reads like
a SOC console: verdict and escalation at a glance up top, evidence and pivots
below, attacker-controlled text safely escaped throughout.

    from src.report import render_report
    Path("report.html").write_text(render_report(alert, investigation))
"""
from html import escape

from .models import Alert, Investigation

# Machine data (IOCs, T-codes, timestamps, hashes, the escalation draft) is set
# in mono; prose in sans — the way security tooling actually renders these.
_STYLE = """
:root{
  --bg:#0e141b; --panel:#161f2b; --raised:#1c2836; --line:#263547;
  --ink:#e6edf3; --muted:#8695a8; --faint:#5b6b7e;
  --accent:#4cc2ff;
  --crit:#ff5b6e; --warn:#f0a63f; --good:#43c06d;
}
*{box-sizing:border-box}
.rp{
  font-family:ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  background:var(--bg); color:var(--ink); line-height:1.55;
  max-width:940px; margin:0 auto; padding:34px 26px 72px;
  font-size:15px; -webkit-font-smoothing:antialiased;
}
.rp .mono{font-family:ui-monospace,"SF Mono","Cascadia Code","JetBrains Mono",Consolas,monospace}
.rp h1,.rp h2,.rp h3{margin:0;text-wrap:balance;font-weight:640}
.rp .eyebrow{
  font-size:11px;letter-spacing:.16em;text-transform:uppercase;
  color:var(--faint);font-weight:600;
}
.rp a{color:var(--accent);text-decoration:none}

/* Verdict header */
.rp .head{
  display:grid;grid-template-columns:4px 1fr auto;gap:0 20px;
  background:var(--panel);border:1px solid var(--line);border-radius:12px;
  padding:22px 24px;margin-bottom:14px;align-items:start;
}
.rp .rail{grid-row:1/3;width:4px;border-radius:4px;background:var(--muted)}
.rp .rail.crit{background:var(--crit)} .rp .rail.warn{background:var(--warn)} .rp .rail.good{background:var(--good)}
.rp .head-main h1{font-size:21px;margin-top:7px;line-height:1.3}
.rp .meta{display:flex;flex-wrap:wrap;gap:6px 16px;margin-top:12px;
  font-size:12.5px;color:var(--muted)}
.rp .meta b{color:var(--ink);font-weight:600}
.rp .verdict{grid-column:3;text-align:right;display:flex;flex-direction:column;gap:8px;align-items:flex-end}
.rp .pill{
  display:inline-flex;align-items:center;gap:7px;font-weight:650;
  padding:7px 14px;border-radius:999px;font-size:13px;white-space:nowrap;
  border:1px solid transparent;
}
.rp .pill.crit{background:rgba(255,91,110,.13);color:#ffb3bc;border-color:rgba(255,91,110,.35)}
.rp .pill.warn{background:rgba(240,166,63,.13);color:#f7cd8f;border-color:rgba(240,166,63,.35)}
.rp .pill.good{background:rgba(67,192,109,.13);color:#9be0b3;border-color:rgba(67,192,109,.35)}
.rp .dot{width:7px;height:7px;border-radius:50%;background:currentColor}
.rp .chips{display:flex;flex-wrap:wrap;gap:6px;justify-content:flex-end}
.rp .chip{
  font-size:11.5px;padding:4px 9px;border-radius:6px;border:1px solid var(--line);
  color:var(--muted);background:var(--raised);white-space:nowrap;
}
.rp .chip b{color:var(--ink);font-weight:600}
.rp .chip.on{color:#ffb3bc;border-color:rgba(255,91,110,.4);background:rgba(255,91,110,.1)}

/* Attention banners */
.rp .banner{
  display:flex;gap:12px;padding:14px 16px;border-radius:10px;margin-bottom:12px;
  border:1px solid;font-size:14px;align-items:flex-start;
}
.rp .banner .bicon{font-weight:800;font-size:15px;line-height:1.4}
.rp .banner.red{background:rgba(255,91,110,.08);border-color:rgba(255,91,110,.4)}
.rp .banner.red .bt{color:#ffb3bc}
.rp .banner.amber{background:rgba(240,166,63,.08);border-color:rgba(240,166,63,.4)}
.rp .banner.amber .bt{color:#f7cd8f}
.rp .banner .bt{font-weight:650}

/* Sections */
.rp section{
  background:var(--panel);border:1px solid var(--line);border-radius:12px;
  padding:18px 22px;margin-top:14px;
}
.rp section > .eyebrow{margin-bottom:12px;display:block}
.rp p{margin:0}
.rp .hyp{font-size:15.5px;line-height:1.6}

/* Tag rows (techniques, groups) */
.rp .tags{display:flex;flex-wrap:wrap;gap:8px}
.rp .tag{
  font-size:12.5px;padding:6px 11px;border-radius:7px;border:1px solid var(--line);
  background:var(--raised);
}
.rp .tag .tid{color:var(--accent);font-weight:600}
.rp .tag .cnt{color:var(--faint);margin-left:6px}

/* Lists (evidence, pivots, sightings) */
.rp .stack{display:flex;flex-direction:column;gap:10px}
.rp .card{
  border:1px solid var(--line);border-radius:9px;padding:13px 15px;background:var(--raised);
}
.rp .card .top{display:flex;justify-content:space-between;gap:12px;align-items:baseline;margin-bottom:5px}
.rp .card .src{font-size:12px;color:var(--muted);font-weight:600}
.rp .card .claim{font-size:14px}
.rp .lvl{font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;font-weight:700;padding:2px 7px;border-radius:5px}
.rp .lvl.high{color:#ffb3bc;background:rgba(255,91,110,.13)}
.rp .lvl.medium{color:#f7cd8f;background:rgba(240,166,63,.13)}
.rp .lvl.low{color:var(--muted);background:var(--raised);border:1px solid var(--line)}
.rp .pivot{display:grid;grid-template-columns:auto 1fr;gap:2px 12px}
.rp .pivot .prio{grid-row:1/3}
.rp .pivot .act{font-weight:600;font-size:14px}
.rp .pivot .rat{color:var(--muted);font-size:13.5px}
.rp .sig{color:var(--faint);font-size:12px;margin-top:3px}

/* Escalation draft */
.rp .draft{
  white-space:pre-wrap;font-size:13px;line-height:1.6;
  background:#0b1017;border:1px solid var(--line);border-radius:9px;
  padding:16px;color:#cdd8e4;overflow-x:auto;
}
.rp .reason{color:var(--muted);font-size:13.5px;white-space:pre-wrap;line-height:1.6}
.rp .empty{color:var(--faint);font-size:13.5px;font-style:italic}
.rp footer{margin-top:26px;text-align:center;color:var(--faint);font-size:11.5px;letter-spacing:.04em}
"""

_VERDICT = {
    "true_positive": ("crit", "True Positive"),
    "false_positive": ("good", "False Positive"),
    "inconclusive": ("warn", "Inconclusive"),
}


def _section(eyebrow: str, inner: str) -> str:
    return f'<section><span class="eyebrow">{escape(eyebrow)}</span>{inner}</section>'


def _lvl(level: str) -> str:
    lv = escape(level or "low")
    return f'<span class="lvl {lv}">{lv}</span>'


def _render_head(alert: Alert, inv: Investigation) -> str:
    cls, label = _VERDICT.get(inv.verdict, ("", inv.verdict))
    esc_on = inv.escalation_recommended
    esc_chip = (
        '<span class="chip on"><b>Escalate</b></span>'
        if esc_on
        else '<span class="chip">No escalation</span>'
    )
    return f"""
    <div class="head">
      <div class="rail {cls}"></div>
      <div class="head-main">
        <span class="eyebrow">SOC Copilot · Investigation Report</span>
        <h1>{escape(alert.title)}</h1>
        <div class="meta">
          <span class="mono">{escape(alert.alert_id)}</span>
          <span>Source <b>{escape(alert.source)}</b></span>
          <span>Severity <b>{escape(alert.severity)}</b></span>
          <span class="mono">{escape(alert.timestamp.strftime("%Y-%m-%d %H:%M UTC"))}</span>
        </div>
      </div>
      <div class="verdict">
        <span class="pill {cls}"><span class="dot"></span>{escape(label)}</span>
        <div class="chips">
          <span class="chip">Confidence <b>{escape(inv.confidence)}</b></span>
          {esc_chip}
        </div>
      </div>
    </div>"""


def _render_banners(inv: Investigation) -> str:
    out = []
    if inv.injection_flags:
        n = len(inv.injection_flags)
        out.append(
            f'<div class="banner red"><span class="bicon">⚠</span><div>'
            f'<span class="bt">Prompt injection detected and resisted.</span> '
            f'{n} manipulation attempt{"s" if n != 1 else ""} embedded in the '
            f'alert content were flagged and ignored — see Security below.</div></div>'
        )
    corr = inv.correlation
    if corr and corr.is_campaign:
        out.append(
            f'<div class="banner amber"><span class="bicon">◆</span><div>'
            f'<span class="bt">Part of a coordinated campaign.</span> '
            f'{escape(corr.summary)}</div></div>'
        )
    return "".join(out)


def _render_sections(alert: Alert, inv: Investigation) -> str:
    s = []

    s.append(_section("Hypothesis", f'<p class="hyp">{escape(inv.hypothesis)}</p>'))

    if inv.attack_techniques:
        tags = "".join(
            f'<span class="tag mono">{escape(t)}</span>' for t in inv.attack_techniques
        )
        s.append(_section("MITRE ATT&CK Techniques", f'<div class="tags">{tags}</div>'))

    if inv.associated_groups:
        tags = "".join(
            f'<span class="tag"><span class="mono">{escape(g.group)}</span>'
            f'<span class="cnt">×{g.overlap_count}</span></span>'
            for g in inv.associated_groups
        )
        s.append(_section(
            "Threat Groups with Overlapping TTPs",
            f'<div class="tags">{tags}</div>'
            '<p class="sig">Technique overlap is suggestive context, not attribution.</p>',
        ))

    if inv.prior_sightings:
        cards = "".join(
            f'<div class="card"><div class="top">'
            f'<span class="src mono">{escape(p.alert_id)}</span>'
            f'<span class="mono sig">{escape(p.timestamp.strftime("%Y-%m-%d"))}</span></div>'
            f'<div class="claim">{escape(p.title)} — verdict '
            f'<b>{escape(p.verdict)}</b></div>'
            f'<div class="sig mono">shared: {escape(", ".join(p.matched_iocs))}</div></div>'
            for p in inv.prior_sightings
        )
        s.append(_section("Prior Sightings (shared indicators)", f'<div class="stack">{cards}</div>'))

    corr = inv.correlation
    if corr and corr.related_alerts:
        cards = "".join(
            f'<div class="card"><div class="top">'
            f'<span class="src mono">{escape(r.alert_id)}</span>'
            f'<span class="mono sig">{escape(r.timestamp.strftime("%Y-%m-%d"))}</span></div>'
            f'<div class="sig mono">{escape(", ".join(r.signals))}</div></div>'
            for r in corr.related_alerts
        )
        s.append(_section("Correlated Alerts", f'<div class="stack">{cards}</div>'))

    if inv.evidence:
        cards = "".join(
            f'<div class="card"><div class="top">'
            f'<span class="src mono">{escape(e.source_tool)}</span>{_lvl(e.confidence)}</div>'
            f'<div class="claim">{escape(e.claim)}</div></div>'
            for e in inv.evidence
        )
        s.append(_section("Evidence", f'<div class="stack">{cards}</div>'))

    if inv.suggested_pivots:
        cards = "".join(
            f'<div class="card pivot">{_lvl(p.priority)}'
            f'<span class="prio"></span>'
            f'<div class="act">{escape(p.action)}</div>'
            f'<div class="rat">{escape(p.rationale)}</div></div>'
            for p in inv.suggested_pivots
        )
        s.append(_section("Suggested Pivots", f'<div class="stack">{cards}</div>'))

    if inv.injection_flags:
        rows = "".join(
            f'<div class="card"><div class="top">'
            f'<span class="src mono">{escape(f.location)}</span>'
            f'<span class="lvl high">{escape(f.pattern)}</span></div>'
            f'<div class="claim mono sig">{escape(f.excerpt)}</div></div>'
            for f in inv.injection_flags
        )
        s.append(_section(
            "Security — Injection Attempts (resisted)",
            '<p class="sig">These were embedded in the untrusted alert content '
            'and ignored, not obeyed.</p>'
            f'<div class="stack">{rows}</div>',
        ))

    if inv.escalation_draft:
        s.append(_section("Escalation Draft",
                          f'<div class="draft mono">{escape(inv.escalation_draft)}</div>'))

    if inv.reasoning_transcript:
        s.append(_section("Reasoning Transcript",
                          f'<p class="reason">{escape(inv.reasoning_transcript)}</p>'))

    return "".join(s)


def render_report_body(alert: Alert, inv: Investigation) -> str:
    """Return the report as body content (a <style> block + markup), suitable
    for embedding. Use render_report() for a standalone file."""
    return (
        f"<style>{_STYLE}</style>"
        f'<div class="rp">'
        f"{_render_head(alert, inv)}"
        f"{_render_banners(inv)}"
        f"{_render_sections(alert, inv)}"
        f'<footer>Generated by SOC Copilot · verdict and enrichment are '
        f'decision support for a human analyst</footer>'
        f"</div>"
    )


def render_report(alert: Alert, inv: Investigation) -> str:
    """Return a complete, self-contained HTML document for the investigation."""
    title = f"Investigation {escape(alert.alert_id)}"
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{title}</title></head>"
        f"<body style='margin:0;background:#0e141b'>{render_report_body(alert, inv)}</body></html>\n"
    )
