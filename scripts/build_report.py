"""Render the Markdown reports to print-ready HTML (then "Save as PDF").

There is no pandoc / Word pipeline on this machine, and the lab wants a PDF.
A browser is the most reliable Markdown->PDF converter that is already
installed: this script produces a self-contained, A4-styled HTML file, and you
print it to PDF from Edge/Chrome.

Usage
-----
    python scripts/build_report.py                 # both reports
    python scripts/build_report.py docs/report_zh.md
    python scripts/build_report.py docs/report_zh.md docs/report_en.md

Then: open the .html file, Ctrl+P, destination "Save as PDF",
paper A4, margins "Default", and tick "Background graphics".

Missing screenshots are rendered as a dashed placeholder box that names the
file you still have to take, so the PDF never shows a broken image icon.
"""
from __future__ import annotations

import html
import re
import sys
from pathlib import Path

try:
    import markdown
except ImportError:  # pragma: no cover
    sys.exit("python-markdown is required:  pip install markdown")

CSS = """
:root { color-scheme: light; }
@page { size: A4; margin: 16mm 14mm 18mm 14mm; }
* { box-sizing: border-box; }
body {
  font-family: "Segoe UI", "Microsoft YaHei", "PingFang SC", "Noto Sans CJK SC", system-ui, sans-serif;
  font-size: 10.5pt; line-height: 1.62; color: #1b1b1b; margin: 0 auto; max-width: 190mm;
  -webkit-print-color-adjust: exact; print-color-adjust: exact;
}
h1 { font-size: 1.65em; line-height: 1.3; margin: 0 0 .6em; padding-bottom: .3em; border-bottom: 2px solid #2c4a7c; }
h1 + h1, h1:not(:first-of-type) { page-break-before: always; }
h2 { font-size: 1.22em; margin: 1.5em 0 .5em; padding-bottom: .18em; border-bottom: 1px solid #dde3ea; page-break-after: avoid; }
h3 { font-size: 1.05em; margin: 1.2em 0 .4em; page-break-after: avoid; }
h4 { font-size: 1em; margin: 1em 0 .3em; page-break-after: avoid; }
p { margin: .55em 0; }
ul, ol { margin: .5em 0 .5em 1.4em; padding: 0; }
li { margin: .22em 0; }
li > ul, li > ol { margin: .2em 0 .2em 1.1em; }
a { color: #1a4d8f; text-decoration: none; word-break: break-word; }
code {
  font-family: Consolas, "Cascadia Mono", "SFMono-Regular", monospace; font-size: .9em;
  background: #f2f4f7; padding: .08em .32em; border-radius: 3px; color: #1f2933;
}
pre {
  background: #f8f9fb; border: 1px solid #e2e6ec; border-left: 4px solid #4a6fa5;
  padding: 8px 11px; overflow-x: auto; page-break-inside: avoid; margin: .7em 0;
  font-size: .86em; line-height: 1.5; white-space: pre-wrap; word-break: break-word;
}
pre code { background: none; padding: 0; font-size: 1em; }
table { border-collapse: collapse; width: 100%; margin: .8em 0; font-size: .93em; page-break-inside: avoid; }
th, td { border: 1px solid #d3dae2; padding: 4px 7px; vertical-align: top; text-align: left; }
th { background: #eef2f7; font-weight: 600; }
tbody tr:nth-child(even) { background: #fbfcfd; }
blockquote {
  margin: .8em 0; padding: .55em .9em; background: #f6f9fc;
  border-left: 4px solid #9db4d0; color: #2b323b;
}
blockquote p { margin: .18em 0; }
img { max-width: 100%; height: auto; }
hr { border: none; border-top: 1px solid #dde3ea; margin: 1.4em 0; }
.missing {
  border: 1px dashed #c0392b; color: #a53224; background: #fdf6f5;
  padding: 10px 12px; margin: 8px 0; font-size: .9em; border-radius: 4px;
}
.missing code { background: #fff; }
.task { font-family: Consolas, monospace; }
@media print { body { max-width: none; } }
"""

IMG_RE = re.compile(r'<img\b([^>]*?)\bsrc="([^"]+)"([^>]*?)>', re.IGNORECASE)
CJK_RE = re.compile(r"[\u4e00-\u9fff]")


def placeholder(target: str, chinese: bool) -> str:
    label = "待补截图" if chinese else "screenshot pending"
    return (
        f'<div class="missing">📷 {label}: <code>{html.escape(target)}</code></div>'
    )


def render(md_path: Path) -> Path:
    source = md_path.read_text(encoding="utf-8")
    chinese = bool(CJK_RE.search(source))

    body = markdown.markdown(
        source,
        extensions=[
            # Full module paths are required here: this build resolves short
            # names literally, which also breaks the bundled "extra" bundle.
            "markdown.extensions.tables",
            "markdown.extensions.fenced_code",
            "markdown.extensions.sane_lists",
            "markdown.extensions.attr_list",
        ],
        output_format="html5",
    )

    # Replace references to screenshots that do not exist yet.
    def _img(match: re.Match) -> str:
        src = match.group(2)
        if src.startswith(("http://", "https://", "data:")):
            return match.group(0)
        if (md_path.parent / src).exists():
            return match.group(0)
        return placeholder(src, chinese)

    body = IMG_RE.sub(_img, body)

    title_match = re.search(r"<h1[^>]*>(.*?)</h1>", body, re.S)
    title = re.sub(r"<[^>]+>", "", title_match.group(1)).strip() if title_match else md_path.stem

    doc = f"""<!DOCTYPE html>
<html lang="{'zh-CN' if chinese else 'en'}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>{CSS}</style>
</head>
<body>
{body}
</body>
</html>
"""
    out = md_path.with_suffix(".html")
    out.write_text(doc, encoding="utf-8")
    return out


def main(argv: list[str]) -> int:
    root = Path(__file__).resolve().parent.parent
    targets = [Path(a) for a in argv[1:]] or [
        root / "docs" / "report_zh.md",
        root / "docs" / "report_en.md",
    ]
    for target in targets:
        path = target if target.is_absolute() else (Path.cwd() / target)
        if not path.exists():
            print(f"! missing: {path}")
            continue
        out = render(path)
        print(f"-> {out.relative_to(Path.cwd()) if out.is_relative_to(Path.cwd()) else out}")

    print()
    print("Open the .html file in Edge/Chrome, then Ctrl+P:")
    print("  destination = Save as PDF, paper = A4, margins = Default, background graphics = on")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
