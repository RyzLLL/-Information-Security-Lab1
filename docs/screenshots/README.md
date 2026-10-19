# Screenshots

All five images referenced by the README and both reports are present.

| File | What it shows | How it was produced |
|---|---|---|
| `api-demo.png` | the 9-step API walkthrough, every step `PASS` | `scripts\capture.ps1` running `scripts\demo.ps1 -Compact` in a fresh console |
| `cve-exploit.png` | 403 baseline → 200 bypass (user table + bcrypt hashes) → `create user ok!` on Nacos 1.4.0 | `scripts\capture.ps1` running `cve\exploit.ps1` |
| `cve-fixed.png` | every check `PASS` + `RESULT: fix verified` on Nacos 1.4.1 | `scripts\capture.ps1` running `cve\verify-fix.ps1` |
| `ci-green.png` | the real GitHub run: 5/5 jobs green, `Success`, 28 s, 3 artifacts | headless Edge screenshot of the run page, cropped above the annotations block |
| `bandit.png` | `No issues identified` (670 LOC, Low 3 / Medium 0 / High 0) | `scripts\render_output.py` rendering the output of the same command CI runs |
| `pip-audit.png` | `No known vulnerabilities found` | same, for `pip-audit -r requirements.txt --strict` |
| `api-postman.png` *(optional)* | Postman collection runner: 10/10 green | your own Postman run, see below |

## Why two of them are rendered, not photographed

`capture.ps1` copies a region of the desktop, so it photographs whatever window
is on top — during the CI captures another application had focus and the first
attempts caught the wrong window. `render_output.py` runs the command, takes its
real stdout/stderr and lays it out in a terminal-styled page, which Edge then
screenshots headlessly. The content is the tool's own output; only the
presentation is generated.

`ci-green.png` is a genuine screenshot of the GitHub page, taken with headless
Edge (no desktop involved).

## Postman

Import [`docs/postman_collection.json`](../postman_collection.json)
(*Import* → *File*), start the API (`python run.py` or the PyCharm run
configuration), then *Run* the collection: the *Login* request stores the JWT in
the `{{token}}` collection variable and the other nine requests carry
assertions, so the runner summary shows 10 green tests.

A screenshot of that summary is a good companion to `api-demo.png`.

## Reproducing any of them

```powershell
# console-based ones (needs the app / containers running)
powershell -ExecutionPolicy Bypass -File .\scripts\capture.ps1 `
    -Command "powershell -ExecutionPolicy Bypass -File .\scripts\demo.ps1 -Compact" `
    -Out .\docs\screenshots\api-demo.png -Settle 16

# scanner reports (no desktop, deterministic)
$env:PYTHONPATH='C:\Users\ryz20\OneDrive\文档\deepseek-harness\default-workspace\.tools'
python scripts\render_output.py -o docs\screenshots\bandit.png -- python -m bandit -r app -ll -ii
```

## Tips

* Include the **command line** in the shot — evidence without the command is weak.
* Keep the browser's URL bar visible in CI screenshots so the repository and
  workflow are identifiable.
