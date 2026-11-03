from __future__ import annotations

import datetime
import html
import json
import os
from collections import defaultdict


def _rate(rs):
    valid = [r for r in rs if r["status"] != "error"]
    succ = sum(1 for r in valid if r["status"] == "success")
    return succ, len(valid)


def summarize(results: list[dict]) -> dict:
    s, n = _rate(results)
    by_cat, by_mut, matrix = defaultdict(list), defaultdict(list), defaultdict(lambda: defaultdict(list))
    for r in results:
        by_cat[r["category"]].append(r)
        by_mut[r["mutator"]].append(r)
        matrix[r["category"]][r["mutator"]].append(r)
    pct = lambda a, b: round(100 * a / b, 1) if b else 0.0
    return {
        "total_runs": len(results),
        "errors": sum(1 for r in results if r["status"] == "error"),
        "blocked": sum(1 for r in results if r["status"] == "blocked"),
        "successful_attacks": s,
        "asr_percent": pct(s, n),
        "by_category": {k: pct(*_rate(v)) for k, v in by_cat.items()},
        "by_mutator": {k: pct(*_rate(v)) for k, v in by_mut.items()},
        "matrix": {c: {m: pct(*_rate(v)) for m, v in row.items()} for c, row in matrix.items()},
    }


def write_reports(results, target_name: str, out_dir: str) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    rows = [r.to_dict() for r in results]
    summary = summarize(rows)
    meta = {"target": target_name, "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "summary": summary}
    with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "results": rows}, f, indent=2)
    with open(os.path.join(out_dir, "report.html"), "w", encoding="utf-8") as f:
        f.write(_html(meta, rows))
    return summary


def _cell(v):
    a = min(max(v / 100, 0), 1)
    return f'<td style="background:rgba(220,38,38,{a:.2f});text-align:center">{v:g}%</td>'


def _html(meta, rows):
    s = meta["summary"]
    e = html.escape
    muts = list(s["by_mutator"].keys())
    matrix = "".join(
        f"<tr><td>{e(c)}</td>" + "".join(_cell(s['matrix'][c].get(m, 0)) for m in muts) + _cell(s['by_category'][c]) + "</tr>"
        for c in sorted(s["matrix"]))
    hdr = "".join(f"<th>{e(m)}</th>" for m in muts)

    grouped = defaultdict(list)
    for r in rows:
        grouped[r["attack_id"]].append(r)
    findings = ""
    for aid, rs in sorted(grouped.items()):
        wins = [r for r in rs if r["status"] == "success"]
        if not wins:
            continue
        first = wins[0]
        findings += (
            f"<div class='f'><h3>{e(aid)} - {e(first['title'])} "
            f"<span class='sev {e(first['severity'])}'>{e(first['severity'])}</span></h3>"
            f"<p>{e(first['category'])} | OWASP {e(first['owasp'])} | ATLAS {e(first['atlas'])}</p>"
            f"<p>Worked with: <b>{e(', '.join(r['mutator'] for r in wins))}</b> "
            f"({len(wins)}/{len(rs)} variants)</p>"
            f"<p>Evidence: {e(first['evidence'])}</p>"
            f"<pre>{e(first['prompt_sent'][:400])}</pre><pre>{e(first['response_text'][:300])}</pre></div>")
    if not findings:
        findings = "<p>No successful attacks. Check 'blocked' and 'errors' counts before trusting this.</p>"

    return f"""<!doctype html><html><head><meta charset="utf-8"><title>LLM Red-Team Report</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#111}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:6px 10px}}
.f{{border:1px solid #ddd;border-radius:8px;padding:0 1rem;margin:1rem 0}}pre{{background:#f4f4f5;padding:8px;overflow-x:auto;white-space:pre-wrap}}
.sev{{font-size:.7em;padding:2px 8px;border-radius:99px;background:#eee}}.sev.high,.sev.critical{{background:#fecaca}}
.kpi{{display:flex;gap:1rem}}.kpi div{{flex:1;border:1px solid #ddd;border-radius:8px;padding:1rem;text-align:center}}
.kpi b{{display:block;font-size:1.8rem}}</style></head><body>
<h1>LLM Red-Team Report</h1><p>Target: <b>{e(meta['target'])}</b> | {e(meta['generated'])}</p>
<div class="kpi"><div><b>{s['asr_percent']}%</b>attack success rate</div><div><b>{s['successful_attacks']}</b>successful</div>
<div><b>{s['blocked']}</b>blocked</div><div><b>{s['errors']}</b>errors</div><div><b>{s['total_runs']}</b>total runs</div></div>
<h2>Attack success rate by category and mutator</h2>
<table><tr><th>Category</th>{hdr}<th>All</th></tr>{matrix}</table>
<h2>Findings</h2>{findings}
<p><small>Heuristic detectors; verify findings manually. Mappings: OWASP Top 10 for LLM Applications, MITRE ATLAS.</small></p>
</body></html>"""


def compare(base: dict, guarded: dict) -> str:
    b, g = base["meta"]["summary"], guarded["meta"]["summary"]
    lines = [f"# Guard effectiveness: {base['meta']['target']} vs {guarded['meta']['target']}", "",
             "| Category | Baseline ASR | Guarded ASR | Reduction |", "|---|---|---|---|"]
    for c in sorted(b["by_category"]):
        x, y = b["by_category"][c], g["by_category"].get(c, 0)
        lines.append(f"| {c} | {x}% | {y}% | {round(x - y, 1)} pts |")
    lines.append(f"| **Overall** | **{b['asr_percent']}%** | **{g['asr_percent']}%** | "
                 f"**{round(b['asr_percent'] - g['asr_percent'], 1)} pts** |")
    lines += ["", "Residual attacks that still worked against the guarded target:", ""]
    survivors = sorted({(r["attack_id"], r["mutator"]) for r in guarded["results"] if r["status"] == "success"})
    lines += [f"- {a} via `{m}`" for a, m in survivors] or ["- none"]
    return "\n".join(lines)
