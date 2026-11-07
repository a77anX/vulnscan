# Benchmarking vulnscan against DVWA and OWASP Juice Shop

This is a methodology, not a results claim. I haven't run DVWA or Juice Shop myself — this
environment can't reach the Docker images or a browser needed to set them up — so the numbers
in the result tables below are blank on purpose. Fill them in by actually running the steps,
and the table becomes evidence you can cite (in a capstone report, a thesis, or just to know
what the tool is actually good for) instead of a guess.

Why these two targets: both are standard, citable benchmarks that security tooling is commonly
measured against, so "vulnscan caught N of DVWA's categories at Low security" is a claim a
reader can verify by running the same steps themselves.

---

## 1. Set up the targets

### DVWA
```
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```
Visit `http://localhost/setup.php`, click "Create / Reset Database", log in with
`admin` / `password`, then set **DVWA Security** (left sidebar) to the level you're testing.

### OWASP Juice Shop
```
docker run --rm -it -p 3000:3000 bkimminich/juice-shop
```
Visit `http://localhost:3000`. Juice Shop has no security-level toggle — it's a single fixed
difficulty, modern JavaScript SPA (Angular), which makes it a useful second data point precisely
*because* it's architecturally different from DVWA's traditional server-rendered PHP.

---

## 2. Run vulnscan against each

Copy your session cookie from the browser's dev tools (Application → Cookies) first for any
page that needs login.

```
# DVWA, at whatever security level is currently set
vulnscan web http://localhost/vulnerabilities/ --active --authorized --blind-sqli \
  --delay 0.3 -H "Cookie: PHPSESSID=<value>; security=<level>" --format md -o dvwa-<level>.md

# DVWA's SQLi page specifically (the crawler won't reach a GET-param page without a link to it)
vulnscan web "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit" --active --authorized \
  --blind-sqli -H "Cookie: PHPSESSID=<value>; security=<level>" --format md -o dvwa-sqli-<level>.md

# Juice Shop -- an Angular SPA, so plain crawling will likely find very little without JS rendering
vulnscan web http://localhost:3000 --active --authorized --delay 0.3 --format md -o juiceshop.md

# Same, with the headless-browser crawler (needs: pip install playwright && playwright install chromium)
vulnscan web http://localhost:3000 --active --authorized --render-js --delay 0.3 \
  --format md -o juiceshop-rendered.md
```

Repeat the DVWA commands at **Low**, **Medium**, and **High** security (reset the level in the
DVWA UI between runs) to see how detection drops as the app adds real defenses.

---

## 3. Coverage checklist — DVWA

DVWA groups its vulnerabilities into named categories. This maps each to the vulnscan rule that
*could* catch it, and leaves the actual result for you to fill in after running step 2.

| DVWA category | Closest vulnscan rule(s) | Expected to fire? | Low | Medium | High |
|---|---|---|---|---|---|
| SQL Injection | `WEB-SQLI-001` (error-based) | Yes, at Low | ☐ | ☐ | ☐ |
| SQL Injection (Blind) | `WEB-SQLI-002` (time-based) | Yes, at Low | ☐ | ☐ | ☐ |
| Command Injection | *(none yet — see §5 below)* | No | — | — | — |
| CSRF | `WEB-CSRF-001` | Yes, at Low | ☐ | ☐ | ☐ |
| File Inclusion | *(none)* | No | — | — | — |
| File Upload | *(none)* | No | — | — | — |
| Insecure CAPTCHA | *(none — needs CAPTCHA-solving logic)* | No | — | — | — |
| Reflected XSS | `WEB-XSS-001` | Yes, at Low | ☐ | ☐ | ☐ |
| Stored XSS | *(none — only reflected XSS is implemented)* | No | — | — | — |
| Weak session IDs | *(none — would need session-token entropy analysis)* | No | — | — | — |
| CSP bypass | `WEB-HDR-001` flags the missing header, but doesn't evaluate bypasses | Partial | ☐ | ☐ | ☐ |

**Fill in a ☐ with ✅ (fired, and it's a true positive) or ❌ (missed, or a false positive) —**
**whichever actually happened — and note the exact finding ID under each.**

Expect the "No" rows to genuinely score 0. That's not a bug to chase before reporting results;
it's the honest boundary of what's built so far, and worth stating as plainly in a writeup as
the rows that do score.

---

## 4. Coverage checklist — Juice Shop

Juice Shop's challenges are scored and tracked in its own scoreboard (`/#/score-board`), which
is a cleaner ground truth than DVWA's category list. Pick 10-15 challenges tagged with a
category vulnscan targets (Injection, XSS, Broken Access Control) and record, per challenge:

| # | Challenge name | Category | vulnscan rule it should map to | Fired? |
|---|---|---|---|---|
| 1 | | | | ☐ |
| 2 | | | | ☐ |
| ... | | | | |

Two things to expect and note rather than be surprised by:
- **The plain crawler will likely find almost nothing** without `--render-js`, since Juice
  Shop's initial HTML is an empty Angular shell. Compare `juiceshop.md` against
  `juiceshop-rendered.md` from step 2 — the gap between them *is* the measurement of how much
  JS rendering buys you, which is itself a useful, citable result.
- Many Juice Shop challenges (broken access control, business-logic flaws, JWT issues) are
  outside what any pattern/behavior-based scanner like vulnscan looks for at all. Recording
  that as "0/N, out of scope by design" is more honest than searching for a way to count it.

---

## 5. What this exercise is actually for

The point isn't to make vulnscan look good — it's to produce a defensible, repeatable statement
of what it catches and what it doesn't, the same kind of coverage statement any real scanner's
documentation ought to have. A capstone or thesis section built from this would read something
like:

> "Against DVWA at Low security, vulnscan correctly flagged N/M applicable categories
> (list them), with zero false positives on a 20-request control page. At Medium security,
> detection dropped to N'/M as [specific defense] began sanitizing input. vulnscan has no
> coverage for stored XSS, file upload, or command injection, which would need new rules."

That last sentence is a legitimate and useful finding in itself — it's a prioritized list of
what to build next, backed by a real benchmark instead of a guess. Command injection in
particular is a natural next addition: a `WEB-CMDI-001` active check timing a response against
an OS-level sleep payload (`; sleep 2`, `| ping -c 5 127.0.0.1`), using the same timing-based
approach `WEB-SQLI-002` already implements in `vulnscan/web/active.py`.
