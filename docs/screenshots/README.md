# Screenshots

The PNGs here are referenced by the README and both reports. Two of them are
already captured (see the table); the CI ones are filled in after the first push.

## Already captured

| File | What it shows | How it was produced |
|---|---|---|
| `api-demo.png` | the 9-step API walkthrough, every step `PASS` | `scripts\capture.ps1` running `scripts\demo.ps1 -Compact` in a fresh console |
| `cve-exploit.png` | 403 baseline → 200 bypass (user table + bcrypt hashes) → `create user ok!` on Nacos 1.4.0 | `scripts\capture.ps1` running `cve\exploit.ps1` |
| `cve-fixed.png` | every check `PASS` + `RESULT: fix verified` on Nacos 1.4.1 | `scripts\capture.ps1` running `cve\verify-fix.ps1` |

Reproduce any of them:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\capture.ps1 `
    -Command "powershell -ExecutionPolicy Bypass -File .\scripts\demo.ps1 -Compact" `
    -Out .\docs\screenshots\api-demo.png -Settle 16
```

`capture.ps1` opens a titled console, runs the command, resizes the window,
grabs the window region from the desktop and closes the console. `demo.ps1
-Compact` prints one line per step so the whole run fits on one screen.

## Still to capture (after the first push)

| File | Where |
|---|---|
| `ci-green.png` | *Actions* → *CI* → latest run → the job list (four green jobs: Tests, Lint, SAST - Bandit, SCA - pip-audit) |
| `bandit.png` | *Actions* → *CI* → *SAST - Bandit* → **Summary** (the Bandit report text) |
| `pip-audit.png` | *Actions* → *CI* → *SCA - pip-audit* → **Summary** (`No known vulnerabilities found`) |
| `api-postman.png` *(optional)* | Postman, see below |

## Postman

Import [`docs/postman_collection.json`](../postman_collection.json)
(*Import* → *File*), start the API (`python run.py` or the PyCharm run
configuration), then *Run* the collection: the *Login* request stores the JWT in
the `{{token}}` collection variable and the other nine requests carry
assertions, so the runner summary shows 10 green tests.

A screenshot of that summary is a good companion to `api-demo.png`.

## Tips

* Include the **command line** in the shot — evidence without the command is weak.
* Keep the browser's URL bar visible in CI screenshots so the repository and
  workflow are identifiable.
