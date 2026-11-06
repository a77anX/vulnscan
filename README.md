# vulnscan

Modular scanner framework: web (DAST) + code (SAST). Python 3.9+, only dependency: `requests`.

    pip install -e .
    vulnscan code ./myproject --format sarif -o results.sarif --fail-on high
    vulnscan web https://target.example            # passive crawl + checks
    vulnscan web https://target.example --active --authorized   # adds XSS/SQLi/redirect probes

Triage (optional, local): `vulnscan code . --triage --triage-model qwen2.5-coder:7b` (needs Ollama; add `--hide-false-positives`). Advisory only, never affects --fail-on.

Lab: `python samples/vuln_server.py` then `vulnscan web http://127.0.0.1:8000/ --active --authorized`.

## Add a check (no wiring needed)
- `vulnscan/web/passive.py`  -> `@web_passive def check(page, ctx)`
- `vulnscan/web/active.py`   -> `@web_active  def check(pages, ctx)`
- `vulnscan/sast/*.py`       -> `@code_check  def check(path, text)`; or add a tuple to `RULES` in `patterns.py`

Only scan systems you own or have written permission to test.
