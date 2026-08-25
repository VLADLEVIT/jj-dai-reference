#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scripts/typeset_roadmap.py — build the roadmap PDF and STAMP ITS SOURCE
=======================================================================

    python3 scripts/typeset_roadmap.py            # rebuild the PDF
    python3 scripts/typeset_roadmap.py --check    # is the PDF current?

`--check` is stdlib-only and runs everywhere. Building needs pandoc,
wkhtmltopdf, reportlab, pypdf and qpdf, which is why the build half is a
maintainer tool and the check half is acceptance.

WHY THIS EXISTS
---------------
`docs/roadmap/README.md` says the PDF is the same document typeset. In
v0.6.8-recut2 that sentence was false: the markdown said 213/213 in three
places and the PDF, built from an earlier draft, said 211/211 in the same
three places. `check_docs_drift.py` reported clean throughout, because it
verifies the surfaces GENERATED FROM `architecture_status.json` and the
roadmap PDF is not one of them. Nothing in the tree could see it.

The fix is not a sidecar file recording which markdown the PDF came from —
a sidecar is a third thing to keep in sync, and a claim about the artefact
kept next to the artefact is exactly what went stale. Instead the sha256 of
the source markdown is written INTO the PDF, as a marker string in its
document metadata, and travels with it. A PDF separated from this tree still
answers the question "which text is this?".

WHAT THE CHECK PROVES AND WHAT IT DOES NOT
------------------------------------------
It proves the PDF was stamped against the markdown that is in the tree right
now. It does not prove the RENDERING is faithful — a stamp is not a
comparison of glyphs, and this check would not catch a typesetter that
silently dropped a table. Naming that here rather than letting a reader
assume more: the failure it exists for is the one that actually happened,
a PDF built before the last edit to its source.
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RM_DIR = os.path.join(ROOT, "docs", "roadmap")

#: The marker is a literal ASCII string so a stdlib check can find it in the
#: raw bytes without a PDF parser, and so `strings` finds it too. The PDF is
#: therefore written WITHOUT object-stream packing: packing would compress
#: the metadata dictionary and make the stamp unreadable to anything that is
#: not a full PDF implementation.
MARKER = "JJDAI-ROADMAP-SOURCE-SHA256:"


def source_markdown() -> str:
    mds = sorted(f for f in os.listdir(RM_DIR)
                 if f.startswith("JJ_DAI_Roadmap_") and f.endswith(".md"))
    if len(mds) != 1:
        raise ValueError("typeset_roadmap: expected exactly one roadmap "
                         "markdown in docs/roadmap/, found %s" % mds)
    return mds[0]


def source_sha256(md_name: str = None) -> str:
    md_name = md_name or source_markdown()
    with open(os.path.join(RM_DIR, md_name), "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def stamped_sha256(pdf_path: str):
    """The sha256 the PDF was stamped with, or None if it carries no stamp."""
    with open(pdf_path, "rb") as fh:
        blob = fh.read()
    m = re.search((MARKER + r"([0-9a-f]{64})").encode("ascii"), blob)
    return m.group(1).decode("ascii") if m else None


def check() -> int:
    md = source_markdown()
    pdf = os.path.join(RM_DIR, md[:-3] + ".pdf")
    if not os.path.exists(pdf):
        print("ROADMAP PDF MISSING: %s" % os.path.relpath(pdf, ROOT))
        return 1
    want = source_sha256(md)
    have = stamped_sha256(pdf)
    if have is None:
        print("ROADMAP PDF UNSTAMPED: %s carries no %s marker. It cannot be "
              "shown to correspond to any particular text."
              % (os.path.relpath(pdf, ROOT), MARKER))
        return 1
    if have != want:
        print("ROADMAP PDF STALE: %s was typeset from a different text.\n"
              "  markdown now: %s\n  pdf stamped : %s\n"
              "Rebuild with scripts/typeset_roadmap.py."
              % (os.path.relpath(pdf, ROOT), want, have))
        return 1
    print("roadmap PDF ok — stamped %s, matches %s" % (have[:12], md))
    return 0


# --------------------------------------------------------------- building
def build() -> int:
    md = source_markdown()
    base = md[:-3]
    src = os.path.join(RM_DIR, md)
    out = os.path.join(RM_DIR, base + ".pdf")
    sha = source_sha256(md)
    rev = base.replace("JJ_DAI_Roadmap_r", "r").replace("_", ".")
    tmp = os.path.join(ROOT, ".typeset")
    os.makedirs(tmp, exist_ok=True)

    css = os.path.join(os.path.dirname(__file__), "roadmap_print.css")
    body = os.path.join(tmp, "body.html")
    page = os.path.join(tmp, "page.html")
    core = os.path.join(tmp, "core.pdf")

    subprocess.run(["pandoc", src, "-f", "gfm", "-t", "html5", "-o", body],
                   check=True)
    html = ('<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8">'
            '<title>JJ DAI Roadmap %s</title><style>%s</style></head>'
            '<body>%s</body></html>'
            % (rev, io.open(css, encoding="utf-8").read(),
               io.open(body, encoding="utf-8").read()))
    io.open(page, "w", encoding="utf-8").write(html)

    subprocess.run(["wkhtmltopdf", "--enable-local-file-access",
                    "--encoding", "utf-8", "--page-size", "A4",
                    "--margin-top", "16mm", "--margin-bottom", "18mm",
                    "--margin-left", "14mm", "--margin-right", "14mm",
                    page, core], check=True)

    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from pypdf import PdfReader, PdfWriter

    pdfmetrics.registerFont(
        TTFont("DJ", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"))
    reader = PdfReader(core)
    n = len(reader.pages)
    W, H = A4
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    foot = ("JJ DAI \u00b7 \u0420\u043e\u0430\u0434\u043c\u044d\u043f "
            "\u0434\u043e \u0437\u0430\u043f\u0443\u0441\u043a\u0430 "
            "\u0441\u0435\u0442\u0438 \u00b7 %s" % rev)
    for i in range(1, n + 1):
        if i > 1:
            c.setStrokeColorRGB(.82, .84, .87)
            c.setLineWidth(0.4)
            c.line(40, 34, W - 40, 34)
            c.setFont("DJ", 6.8)
            c.setFillColorRGB(.42, .45, .50)
            c.drawString(40, 25, foot)
            c.drawRightString(W - 40, 25, "%d / %d" % (i, n))
        c.showPage()
    c.save()
    buf.seek(0)

    overlay = PdfReader(buf)
    writer = PdfWriter()
    for i, pg in enumerate(reader.pages):
        pg.merge_page(overlay.pages[i])
        writer.add_page(pg)
    writer.add_metadata({
        "/Title": "JJ DAI \u00b7 \u0420\u043e\u0430\u0434\u043c\u044d\u043f %s" % rev,
        "/Author": "JJ GROUP",
        "/Subject": MARKER + sha,
        "/Keywords": MARKER + sha,
    })
    packed = os.path.join(tmp, "packed.pdf")
    with open(packed, "wb") as fh:
        writer.write(fh)

    # --object-streams=disable, NOT generate. Packing objects into compressed
    # streams shrinks the file and hides the stamp from anything without a
    # full PDF parser — including the stdlib check above, which is the one
    # that has to run everywhere.
    subprocess.run(["qpdf", "--object-streams=disable",
                    "--compress-streams=y", packed, out], check=True)

    got = stamped_sha256(out)
    if got != sha:
        print("typeset_roadmap: the stamp did not survive packing "
              "(wanted %s, found %r)" % (sha, got))
        return 2
    print("wrote %s — %d pages, stamped %s"
          % (os.path.relpath(out, ROOT), n, sha[:12]))
    return 0


if __name__ == "__main__":
    raise SystemExit(check() if "--check" in sys.argv[1:] else build())
