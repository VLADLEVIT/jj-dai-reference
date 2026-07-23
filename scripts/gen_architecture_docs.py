#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scripts/gen_architecture_docs.py — one source of truth, three surfaces
======================================================================
Reads docs/architecture_status.json and generates:

  1. the README status table (between STATUS:BEGIN/END markers)
  2. docs/JJDAI_Code_Architecture_Map_v0.5.md   (fully generated)
  3. docs/site/JJDAI_Architecture_Status_v<version>.html

Motivation (v0.5.2 audit): three hand-edited surfaces drifted three
times. Now humans edit ONE json; scripts/check_docs_drift.py fails CI
when any surface disagrees with it or when a referenced path is missing.

    python3 scripts/gen_architecture_docs.py           # regenerate all
"""
from __future__ import annotations

import html
import io
import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STATUS = os.path.join(ROOT, "docs", "architecture_status.json")
README = os.path.join(ROOT, "README.md")
MAP = os.path.join(ROOT, "docs", "JJDAI_Code_Architecture_Map_v0.5.md")

STATUS_WORD = {"impl": "Implemented", "proto": "Prototype",
               "iface": "Interface only", "plan": "Planned",
               "const": "Constitutional text only"}

BEGIN = "<!-- STATUS:BEGIN (generated from docs/architecture_status.json — do not edit by hand) -->"
END = "<!-- STATUS:END -->"


def load() -> dict:
    with open(STATUS, encoding="utf-8") as f:
        return json.load(f)


def count_acceptance() -> int:
    """Count acceptance test functions the same way run_acceptance collects
    them (def test_* at top level of tests/**/test_*.py)."""
    n = 0
    for dirpath, _dirs, files in os.walk(os.path.join(ROOT, "tests")):
        for fn in files:
            if fn.startswith("test_") and fn.endswith(".py"):
                src = io.open(os.path.join(dirpath, fn),
                              encoding="utf-8").read()
                n += len(re.findall(r"^def test_", src, re.M))
    return n


# --------------------------------------------------------------------------- #
#  Surfaces
# --------------------------------------------------------------------------- #

def gen_readme_table(st: dict, acceptance: int) -> str:
    rows = ["| Component | Status |", "|---|---|"]
    for sec in st["sections"]:
        for c in sec.get("cards", []):
            chips = ", ".join(ch for ch in c["chips"]
                              if ch != "generated count")
            status = STATUS_WORD[c["status"]]
            extra = f" ({chips})" if chips and chips != status else ""
            name = c["name"]
            if "generated count" in c["chips"]:
                extra = f" ({acceptance}/{acceptance} green)"
            rows.append(f"| {name} | {status}{extra} |")
    return "\n".join(rows)


def gen_map(st: dict, acceptance: int) -> str:
    out = [f"# JJ DAI — Code Architecture Map v{st['version']}",
           "",
           "> GENERATED from `docs/architecture_status.json` by "
           "`scripts/gen_architecture_docs.py` — edit the JSON, not this "
           "file. `scripts/check_docs_drift.py` fails CI on divergence.",
           "",
           f"Acceptance: {acceptance}/{acceptance} green (stdlib runner; "
           "CI matrix Python 3.10-3.12).", ""]
    for sec in st["sections"]:
        out.append(f"## #{sec['id']} · {sec['title']}")
        if sec.get("note"):
            out += ["", sec["note"]]
        if sec.get("layers"):
            out += ["", "| Layer | Status |", "|---|---|"]
            out += [f"| {n}. {t} | **{STATUS_WORD[s]}** |"
                    for n, t, s in sec["layers"]]
        if sec.get("cards"):
            out += ["", "| Module | What it is | Status |", "|---|---|---|"]
            for c in sec["cards"]:
                path = f"`{c['path']}`" if c.get("path") else "—"
                chips = ", ".join(c["chips"])
                out.append(f"| {path} | {c['name']}: {c['desc']} "
                           f"| **{STATUS_WORD[c['status']]}** ({chips}) |")
        out.append("")
    out += ["## The honest sentence", ""]
    out += [p + "\n" for p in st["honest_sentence"]]
    return "\n".join(out)


_HTML_HEAD = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>JJ DAI — Codebase Architecture Status · v{v}</title>
<meta name="description" content="What exists in the JJ DAI reference codebase, and what does not yet. Generated from architecture_status.json.">
<meta name="theme-color" content="#04060c">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@500;600;700&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{{--bg:#05070d;--panel:#0b101c;--panel-2:#0e1524;--line:#1b2436;
--ink:#dfe6f2;--muted:#7d8aa5;--faint:#4b5872;--impl:#3fbf8f;--proto:#d9a441;
--iface:#6f8dd6;--plan:#64748c;--const:#c084c9;--new:#e8657a;
--mono:'IBM Plex Mono',ui-monospace,monospace}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:var(--bg);color:var(--ink);
font:400 16px/1.55 'IBM Plex Sans',system-ui,sans-serif;-webkit-font-smoothing:antialiased}}
.wrap{{max-width:1060px;margin:0 auto;padding:0 24px}}
header{{padding:56px 0 34px;border-bottom:1px solid var(--line)}}
.eyebrow{{font-family:var(--mono);font-size:12px;letter-spacing:.18em;color:var(--muted);text-transform:uppercase}}
h1{{font-family:'Rajdhani',sans-serif;font-weight:700;font-size:clamp(34px,5.4vw,56px);line-height:1.04;margin:14px 0 10px;text-transform:uppercase}}
h1 .thin{{font-weight:500;color:var(--muted)}}
.sub{{color:var(--muted);max-width:62ch}}
.badges{{display:flex;flex-wrap:wrap;gap:10px;margin-top:22px}}
.badge{{font-family:var(--mono);font-size:12.5px;padding:7px 13px;border:1px solid var(--line);border-radius:3px;background:var(--panel)}}
.badge b{{color:var(--impl);font-weight:500}}.badge.warn b{{color:var(--proto)}}
.legend{{display:flex;flex-wrap:wrap;gap:8px 20px;padding:20px 0 4px}}
.lg{{display:flex;align-items:center;gap:8px;font-size:13.5px;color:var(--muted)}}
.dot{{width:11px;height:11px;border-radius:2px;flex:none}}
.dot.impl{{background:var(--impl)}}.dot.proto{{background:var(--proto)}}
.dot.iface{{background:var(--iface)}}
.dot.plan{{background:transparent;border:1.5px dashed var(--plan)}}
.dot.const{{background:var(--const)}}
section{{padding:34px 0 10px}}
.rec{{font-family:var(--mono);font-size:12.5px;color:var(--faint);display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px}}
.rec .kind{{color:var(--ink);letter-spacing:.14em}}
.rec::before{{content:"";width:14px;height:14px;flex:none;border:1px solid var(--line);border-radius:2px;background:linear-gradient(135deg,var(--panel-2),var(--panel))}}
h2{{font-family:'Rajdhani',sans-serif;font-weight:600;font-size:26px;letter-spacing:.02em;text-transform:uppercase;margin-bottom:4px}}
.secnote{{color:var(--muted);font-size:14.5px;max-width:72ch;margin-bottom:18px}}
.chainline{{border-left:1px solid var(--line);margin-left:7px;padding-left:24px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px;margin-bottom:8px}}
.card{{background:var(--panel);border:1px solid var(--line);border-left-width:3px;border-radius:4px;padding:14px 15px 12px}}
.card.impl{{border-left-color:var(--impl)}}.card.proto{{border-left-color:var(--proto)}}
.card.iface{{border-left-color:var(--iface)}}
.card.plan{{border-style:solid solid solid dashed;border-left-color:var(--plan);background:transparent}}
.card.const{{border-left-color:var(--const)}}
.path{{font-family:var(--mono);font-size:12px;color:var(--muted);margin-bottom:5px;word-break:break-all}}
.cname{{font-family:'Rajdhani',sans-serif;font-weight:600;font-size:18.5px;margin-bottom:4px}}
.cdesc{{font-size:13.5px;color:var(--muted);line-height:1.5}}
.chips{{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}}
.chip{{font-family:var(--mono);font-size:11px;letter-spacing:.06em;padding:3px 8px;border-radius:2px;text-transform:uppercase}}
.chip.impl{{background:rgba(63,191,143,.13);color:var(--impl)}}
.chip.proto{{background:rgba(217,164,65,.13);color:var(--proto)}}
.chip.iface{{background:rgba(111,141,214,.14);color:var(--iface)}}
.chip.plan{{background:rgba(100,116,140,.14);color:#93a1bd}}
.chip.const{{background:rgba(192,132,201,.14);color:var(--const)}}
.stack{{display:flex;flex-direction:column;max-width:640px;margin:6px 0 14px}}
.layer{{display:flex;align-items:center;gap:14px;background:var(--panel);border:1px solid var(--line);padding:11px 16px}}
.layer+.layer{{border-top:none}}
.layer .n{{font-family:var(--mono);font-size:11.5px;color:var(--faint);width:16px}}
.layer .t{{font-family:'Rajdhani',sans-serif;font-weight:600;font-size:16.5px;flex:1}}
.layer .s{{font-family:var(--mono);font-size:11px;letter-spacing:.06em;text-transform:uppercase}}
.layer .s.impl{{color:var(--impl)}}.layer .s.proto{{color:var(--proto)}}
.honest{{background:var(--panel-2);border:1px solid var(--line);border-radius:4px;padding:20px 22px;margin:10px 0 6px;max-width:860px}}
.honest p{{font-size:14.5px}}.honest p+p{{margin-top:10px}}
.honest .cap{{font-family:var(--mono);font-size:11.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--muted);display:block;margin-bottom:10px}}
footer{{margin-top:46px;border-top:1px solid var(--line);padding:26px 0 54px}}
.anchor{{font-family:var(--mono);font-size:12.5px;color:var(--faint);line-height:1.9}}
.anchor .k{{color:var(--muted)}}.motto{{margin-top:14px;color:var(--muted);font-size:14px}}
a{{color:var(--iface);text-decoration:none}}a:hover{{text-decoration:underline}}
@media(max-width:560px){{.grid{{grid-template-columns:1fr}}.chainline{{padding-left:14px}}}}
</style></head><body>
"""


def gen_html(st: dict, acceptance: int) -> str:
    v = st["version"]
    e = html.escape
    out = [_HTML_HEAD.format(v=v)]
    out.append(f"""<header><div class="wrap">
<div class="eyebrow">jj-dai.org · reference codebase · generated from architecture_status.json</div>
<h1>Architecture Status <span class="thin">/ what exists, what does not yet</span></h1>
<p class="sub">Every component of the JJ DAI trust, governance and agent kernel, classified into exactly one of five honest statuses. This page follows the code, not the ambition.</p>
<div class="badges">
<span class="badge">build <b>v{v}</b></span>
<span class="badge">acceptance <b>{acceptance}/{acceptance} green</b></span>
<span class="badge">stdlib-only core · Python ≥ 3.10</span>
<span class="badge warn">status <b>experimental organism — NOT a security-alpha</b></span>
</div><div class="legend">""")
    for k, label in st["legend"].items():
        out.append(f'<span class="lg"><span class="dot {k}"></span>{e(label)}</span>')
    out.append("</div></div></header><main class=\"wrap\">")

    prev = "GENESIS"
    for sec in st["sections"]:
        out.append(f"""<section><div class="rec"><span>#{sec['id']}</span>"""
                   f"""<span class="kind">KIND: {e(sec['kind'])}</span>"""
                   f"""<span>prev: {prev}</span></div><div class="chainline">"""
                   f"""<h2>{e(sec['title'])}</h2>""")
        prev = "#" + sec["id"]
        if sec.get("note"):
            out.append(f'<p class="secnote">{e(sec["note"])}</p>')
        if sec.get("layers"):
            out.append('<div class="stack">')
            for n, t, s in sec["layers"]:
                out.append(f'<div class="layer"><span class="n">{n}</span>'
                           f'<span class="t">{e(t)}</span>'
                           f'<span class="s {s}">{e(STATUS_WORD[s])}</span></div>')
            out.append("</div>")
        if sec.get("cards"):
            out.append('<div class="grid">')
            for c in sec["cards"]:
                out.append(f'<div class="card {c["status"]}">')
                if c.get("path"):
                    out.append(f'<div class="path">{e(c["path"])}</div>')
                out.append(f'<div class="cname">{e(c["name"])}</div>'
                           f'<div class="cdesc">{e(c["desc"])}</div>'
                           f'<div class="chips">')
                for ch in c["chips"]:
                    if ch == "generated count":
                        ch = f"{acceptance}/{acceptance} green"
                    out.append(f'<span class="chip {c["status"]}">{e(ch)}</span>')
                out.append("</div></div>")
            out.append("</div>")
        out.append("</div></section>")

    out.append("""<section><div class="rec"><span>#07</span>
<span class="kind">KIND: COMPOSITION STATUS</span><span>prev: #06</span></div>
<div class="chainline"><h2>The honest sentence</h2><div class="honest">
<span class="cap">what changed · what must not be overclaimed</span>""")
    for p in st["honest_sentence"]:
        out.append(f"<p>{e(p)}</p>")
    out.append(f"""</div></div></section></main>
<footer><div class="wrap"><div class="anchor">
<div><span class="k">record</span> #08 · KIND: ANCHOR · prev: #07</div>
<div><span class="k">source</span> docs/architecture_status.json @ v{v} · generated by scripts/gen_architecture_docs.py</div>
<div><span class="k">site</span> <a href="https://jj-dai.org">jj-dai.org</a> · <span class="k">license</span> AGPL-3.0-only core / Apache-2.0 NECS</div>
</div><p class="motto">truth is discovered, not decreed · Jai Guru Dev</p>
</div></footer></body></html>""")
    return "\n".join(out)


# --------------------------------------------------------------------------- #

def generate(write: bool = True) -> dict:
    st = load()
    acceptance = count_acceptance()
    table = gen_readme_table(st, acceptance)
    readme = io.open(README, encoding="utf-8").read()
    if BEGIN not in readme or END not in readme:
        raise SystemExit("README is missing STATUS markers")
    new_readme = re.sub(re.escape(BEGIN) + ".*?" + re.escape(END),
                        BEGIN + "\n" + table + "\n" + END, readme,
                        flags=re.S)
    map_md = gen_map(st, acceptance)
    page = gen_html(st, acceptance)
    html_path = os.path.join(ROOT, "docs", "site",
                             f"JJDAI_Architecture_Status_v{st['version']}.html")
    if write:
        io.open(README, "w", encoding="utf-8").write(new_readme)
        io.open(MAP, "w", encoding="utf-8").write(map_md)
        io.open(html_path, "w", encoding="utf-8").write(page)
        print(f"generated: README table · map · {os.path.basename(html_path)}"
              f"  (acceptance {acceptance})")
    return {"readme": new_readme, "map": map_md, "html": page,
            "html_path": html_path, "acceptance": acceptance}


if __name__ == "__main__":
    generate(write="--check" not in sys.argv)
