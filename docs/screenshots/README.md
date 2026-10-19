# Screenshots checklist

Put the PNGs here with exactly these names — the README and both reports
reference them.

## A. CI / CD (after pushing to GitHub)

| File | How to capture |
|---|---|
| `ci-green.png` | *Actions* → *CI* → the latest run → screenshot the job graph (3 green jobs: Tests, SAST - Bandit, SCA - pip-audit) |
| `bandit.png` | *Actions* → *CI* → *SAST - Bandit* → the **Summary** page (shows the Bandit report text) |
| `pip-audit.png` | *Actions* → *CI* → *SCA - pip-audit* → the **Summary** page (shows `No known vulnerabilities found`) |
| `code-scanning.png` *(optional)* | *Security* → *Code scanning* → the Bandit SARIF results |

## B. API behaviour (local)

| File | How to capture |
|---|---|
| `api-demo.png` | `python run.py` in one terminal, `.\scripts\demo.ps1` in another, screenshot the transcript |
| `api-postman.png` *(optional)* | Postman: login → copy token → `GET /api/data` with the Bearer header |

## C. The CVE (needs Docker)

| File | How to capture |
|---|---|
| `cve-exploit.png` | vulnerable build: `curl --path-as-is .../etc/passwd` output (`root:x:0:0:...`) and the `id` command execution |
| `cve-fixed.png` | fixed build: the same curl returning 404/403, plus the `verify-fix` `RESULT: fix verified` line |
| `cve-docker-ps.png` *(optional)* | `docker compose ps` showing the container up |

## Tips

* On Windows, **Windows Terminal** + `powershell` gives clean, readable text;
  increase the font size before screenshotting.
* Include the **command line** in the shot — evidence without the command is
  weak.
* Keep the browser's window title / URL bar visible in CI screenshots so the
  repository and workflow are identifiable.
