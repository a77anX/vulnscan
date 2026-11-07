# Vulnerability Scan Report

**Summary:** 4 MEDIUM, 4 LOW, 1 INFO

| Severity | Rule | Title | Location | CWE | OWASP |
|---|---|---|---|---|---|
| MEDIUM | WEB-CKE-002 | Cookie without HttpOnly flag | `https://limegreen-stork-690085.hostingersite.com` | CWE-1004 | A05:2021 |
| MEDIUM | WEB-CSRF-001 | CSRF: request accepted from a different origin | `https://limegreen-stork-690085.hostingersite.com/buildsync/web/` | CWE-352 | A01:2021 |
| MEDIUM | WEB-CSRF-001 | CSRF: request accepted from a different origin | `https://limegreen-stork-690085.hostingersite.com/buildsync/web/index.php` | CWE-352 | A01:2021 |
| MEDIUM | WEB-HDR-004 | Missing HSTS | `https://limegreen-stork-690085.hostingersite.com` | CWE-319 | A02:2021 |
| LOW | WEB-CKE-003 | Cookie without SameSite | `https://limegreen-stork-690085.hostingersite.com` | CWE-1275 | A01:2021 |
| LOW | WEB-HDR-002 | Clickjacking protection missing | `https://limegreen-stork-690085.hostingersite.com` | CWE-1021 | A05:2021 |
| LOW | WEB-HDR-003 | Missing X-Content-Type-Options: nosniff | `https://limegreen-stork-690085.hostingersite.com` | CWE-693 | A05:2021 |
| LOW | WEB-INF-001 | Software version disclosed | `https://limegreen-stork-690085.hostingersite.com` | CWE-200 | A05:2021 |
| INFO | WEB-HDR-005 | Missing Referrer-Policy | `https://limegreen-stork-690085.hostingersite.com` | CWE-200 | A05:2021 |

## Details
### WEB-CKE-002 — Cookie without HttpOnly flag
- **Severity:** MEDIUM
- **Location:** `https://limegreen-stork-690085.hostingersite.com`
- **Evidence:** `PHPSESSID`
- **Description:** Cookie readable by JavaScript (XSS impact).
- **Remediation:** Set HttpOnly.

### WEB-CSRF-001 — CSRF: request accepted from a different origin
- **Severity:** MEDIUM
- **Location:** `https://limegreen-stork-690085.hostingersite.com/buildsync/web/`
- **Evidence:** `POST https://limegreen-stork-690085.hostingersite.com/buildsync/web/ (cross-origin headers)`
- **Description:** The server accepted the submission with a cross-origin Origin/Referer, with no token-based protection to compensate.
- **Remediation:** Check Origin/Referer server-side, or add a validated anti-CSRF token.

### WEB-CSRF-001 — CSRF: request accepted from a different origin
- **Severity:** MEDIUM
- **Location:** `https://limegreen-stork-690085.hostingersite.com/buildsync/web/index.php`
- **Evidence:** `POST https://limegreen-stork-690085.hostingersite.com/buildsync/web/index.php (cross-origin headers)`
- **Description:** The server accepted the submission with a cross-origin Origin/Referer, with no token-based protection to compensate.
- **Remediation:** Check Origin/Referer server-side, or add a validated anti-CSRF token.

### WEB-HDR-004 — Missing HSTS
- **Severity:** MEDIUM
- **Location:** `https://limegreen-stork-690085.hostingersite.com`
- **Description:** Clients are not forced onto HTTPS.
- **Remediation:** Add Strict-Transport-Security.

### WEB-CKE-003 — Cookie without SameSite
- **Severity:** LOW
- **Location:** `https://limegreen-stork-690085.hostingersite.com`
- **Evidence:** `PHPSESSID`
- **Description:** Weaker CSRF protection.
- **Remediation:** Set SameSite=Lax or Strict.

### WEB-HDR-002 — Clickjacking protection missing
- **Severity:** LOW
- **Location:** `https://limegreen-stork-690085.hostingersite.com`
- **Description:** Page can be framed by other origins.
- **Remediation:** Set X-Frame-Options: DENY or CSP frame-ancestors.

### WEB-HDR-003 — Missing X-Content-Type-Options: nosniff
- **Severity:** LOW
- **Location:** `https://limegreen-stork-690085.hostingersite.com`
- **Description:** Browsers may MIME-sniff responses.
- **Remediation:** Add X-Content-Type-Options: nosniff.

### WEB-INF-001 — Software version disclosed
- **Severity:** LOW
- **Location:** `https://limegreen-stork-690085.hostingersite.com`
- **Evidence:** `x-powered-by: PHP/8.3.36`
- **Description:** Version banners help attackers pick known exploits.
- **Remediation:** Suppress or genericise version headers.

### WEB-HDR-005 — Missing Referrer-Policy
- **Severity:** INFO
- **Location:** `https://limegreen-stork-690085.hostingersite.com`
- **Description:** URLs may leak via the Referer header.
- **Remediation:** Add Referrer-Policy.
