\# vulnscan — Command Reference



All commands below assume your virtual environment is activated and the package is installed

(`pip install -e .` from the project root). Run every command from the project folder unless a

full path is given.



Only scan systems you own or have written, signed authorization to test. `--active` is blocked

by the tool itself unless `--authorized` is also passed — that flag is you confirming permission

exists, not the tool granting it.



\---



\## 1. Install



```

pip install -e .

pip install pytest

```



Installs the `vulnscan` command and its one dependency (`requests`). `pytest` is only needed to

run the test suite.



\---



\## 2. Top-level usage



```

vulnscan <command> \[options]

```



Two commands are available: `code` (static analysis) and `web` (web application scanning).



Run `vulnscan --help`, `vulnscan code --help`, or `vulnscan web --help` at any time to see the

live list of flags for your installed version.



\---



\## 3. `vulnscan code` — static analysis (SAST)



Reads source files; never makes a network request.



```

vulnscan code <path> \[options]

```



| Argument / flag | Meaning |

|---|---|

| `<path>` | A single file or a directory to scan recursively. |

| `--format {text,json,md,sarif}` | Report format. Default `text`. |

| `-o, --output <file>` | Write the report to a file instead of printing it. |

| `--fail-on {info,low,medium,high,critical}` | Exit code 1 if any finding is at or above this severity — for CI gates. |

| `--triage` | Send each finding to a local Ollama model for a true/false-positive opinion. Advisory only; never affects `--fail-on`. |

| `--triage-model <name>` | Ollama model to use. Default `qwen2.5-coder:7b`. |

| `--ollama-host <url>` | Ollama server address. Default `http://localhost:11434`. |

| `--hide-false-positives` | Drop findings the model marked `false\_positive`. Only applies with `--triage`. |



\*\*Examples\*\*



```

\# Scan one file, print to screen

vulnscan code samples\\vuln\_app.py



\# Scan a whole project folder, save a Markdown report

vulnscan code C:\\path\\to\\project --format md -o code-report.md



\# Scan and fail the build if anything HIGH or above is found (for CI)

vulnscan code . --fail-on high



\# Scan with local AI triage (needs Ollama running)

vulnscan code samples\\vuln\_app.py --triage --triage-model gemma3:4b



\# Triage and hide what the model is confident is a false positive

vulnscan code . --triage --triage-model gemma3:4b --hide-false-positives



\# SARIF for GitHub code scanning / IDE integration

vulnscan code . --format sarif -o results.sarif

```



\*\*What not to point it at:\*\* a folder containing your virtual environment (`Lib`, `Scripts`,

`site-packages`) or `node\_modules`/`vendor` — third-party code will flood the report. Scan your

own source folders specifically.



\---



\## 4. `vulnscan web` — web application scanning (DAST)



Crawls a live site and, optionally, sends test requests to it.



```

vulnscan web <url> \[options]

```



| Argument / flag | Meaning |

|---|---|

| `<url>` | Starting URL to crawl. |

| `--active` | Send test payloads (XSS, SQLi, open redirect, CSRF probes). Requires `--authorized`. |

| `--authorized` | Confirms you have written permission to test this target. Required for `--active`. |

| `--max-pages <n>` | Stop crawling after this many pages. Default `30`. |

| `--delay <seconds>` | Pause between requests. Default `0.2`. Raise this (e.g. `1`) on a live/production server. |

| `--insecure` | Skip TLS certificate verification — for self-signed certs on your own test servers only. |

| `-H, --header "Name: value"` | Add a custom header (e.g. a session cookie). Repeatable. |

| `--format {text,json,md,sarif}` | Report format. Default `text`. |

| `-o, --output <file>` | Write the report to a file instead of printing it. |

| `--fail-on {info,low,medium,high,critical}` | Exit code 1 if any finding is at or above this severity. |



\*\*Examples\*\*



```

\# Passive scan only — browses and inspects responses, sends no test payloads

vulnscan web https://yourapp.example.com --max-pages 50



\# Active scan — requires written authorization on the target

vulnscan web https://yourapp.example.com --active --authorized --delay 1



\# Local lab target (included in samples/)

vulnscan web http://127.0.0.1:8000/ --active --authorized --delay 0



\# Save a shareable Markdown report

vulnscan web https://yourapp.example.com --active --authorized --format md -o app-report.md



\# Self-signed cert on your own test server

vulnscan web https://localhost/app/ --active --authorized --insecure



\# Authenticated scan, using a session cookie copied from your browser

vulnscan web https://yourapp.example.com --active --authorized -H "Cookie: PHPSESSID=abc123; security=low"

```



\*\*What `--active` actually does:\*\* submits real form data and real parameters, and can create

test records, trigger emails, or (for `WEB-CSRF-001`) actually submit state-changing forms twice.

Only run it against a staging copy or a system where this is expected, and back up the database

first if you run it against anything live.



\---



\## 5. Running the included lab target



A deliberately vulnerable local server ships with the project, for safe testing of the scanner

itself.



```

\# Terminal 1 — start the lab server (keeps running)

python samples\\vuln\_server.py



\# Terminal 2 — scan it

vulnscan web http://127.0.0.1:8000/ --active --authorized --delay 0

```



Stop the server with `Ctrl+C`. It only listens on `127.0.0.1` and is never reachable from outside

your machine.



\---



\## 6. Running the test suite



```

pytest tests

```



(Use `pytest tests`, not bare `pytest`, if your virtual environment lives inside the project

folder — otherwise pytest will also collect tests from installed packages in `Lib\\site-packages`.)



\---



\## 7. Report formats, in short



| Format | Best for |

|---|---|

| `text` | Quick look in the terminal (default). |

| `md` | A readable report to share with a client or teammate. |

| `json` | Raw data — scripting, dashboards, further processing. |

| `sarif` | GitHub code scanning, IDE problem panels, CI integration. |



\---



\## 8. Quick reference — all flags in one place



```

vulnscan code <path>

&#x20;   --format {text,json,md,sarif}

&#x20;   -o, --output <file>

&#x20;   --fail-on {info,low,medium,high,critical}

&#x20;   --triage

&#x20;   --triage-model <name>

&#x20;   --ollama-host <url>

&#x20;   --hide-false-positives



vulnscan web <url>

&#x20;   --active

&#x20;   --authorized

&#x20;   --max-pages <n>

&#x20;   --delay <seconds>

&#x20;   --insecure

&#x20;   -H, --header "Name: value"

&#x20;   --format {text,json,md,sarif}

&#x20;   -o, --output <file>

&#x20;   --fail-on {info,low,medium,high,critical}

```



