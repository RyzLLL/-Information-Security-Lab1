"""Render a command's real output as a terminal-looking PNG.

Useful when the desktop is busy (screen capture grabs whatever window is on
top), or on CI where there is no desktop at all.

    python scripts/render_output.py -o docs/screenshots/bandit.png -- python -m bandit -r app -ll -ii

The image shows the exact command line and its stdout/stderr; only the
presentation is generated, the content is the tool's own output.
"""
from __future__ import annotations

import argparse
import html
import subprocess
import sys
import tempfile
from pathlib import Path

BROWSERS = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"/usr/bin/google-chrome",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
)

PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
@page {{ margin: 0; }}
body {{ margin: 0; background: #0c0c0c; padding: 18px 22px;
        font-family: Consolas, "Cascadia Mono", monospace; font-size: 15px;
        line-height: 1.45; color: #cccccc; }}
.cmd {{ color: #f2d675; margin-bottom: 10px; }}
.out {{ white-space: pre-wrap; word-break: break-word; }}
</style></head>
<body>
<div class="cmd">PS&gt; {command}</div>
<div class="out">{output}</div>
</body></html>
"""


def main() -> int:
    argv = sys.argv[1:]
    if "--" in argv:
        split = argv.index("--")
        own, command = argv[:split], argv[split + 1:]
    else:
        own, command = argv, []
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--width", type=int, default=1180)
    args = ap.parse_args(own)
    if not command:
        print("nothing to run: pass the command after --")
        return 2

    proc = subprocess.run(command, capture_output=True, text=True, errors="replace")
    text = (proc.stdout or "") + (proc.stderr or "")
    lines = text.rstrip("\n").splitlines() or ["(no output)"]

    height = 90 + int(len(lines) * 22) + 30
    page = PAGE.format(command=html.escape(" ".join(command)),
                       output=html.escape("\n".join(lines)))

    with tempfile.TemporaryDirectory() as tmp:
        html_path = Path(tmp) / "page.html"
        html_path.write_text(page, encoding="utf-8")
        browser = next((b for b in BROWSERS if Path(b).exists()), None)
        if browser is None:
            print("no browser found")
            return 1
        out = Path(args.out).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        if out.exists():
            out.unlink()   # so a stale file cannot be mistaken for success
        cmd = [
            browser, "--headless=new", "--disable-gpu", "--no-first-run",
            "--hide-scrollbars", f"--user-data-dir={Path(tmp) / 'prof'}",
            "--virtual-time-budget=4000",
            f"--window-size={args.width},{height}",
            f"--screenshot={out}", html_path.resolve().as_uri(),
        ]
        subprocess.run(cmd, capture_output=True, timeout=120)

    if not out.exists():
        print("the browser produced no image")
        return 1
    print(f"saved {out} ({out.stat().st_size} bytes, {len(lines)} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
