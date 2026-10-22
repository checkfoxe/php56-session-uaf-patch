# PHP 5.6 Security Backport — CVE-2026-109618 / CVE-2026-109619

English | [Читать на русском](README_RU.md)

This repository provides backported security fixes, technical analysis, and mitigation guides for **PHP 5.6.x** addressing two critical vulnerabilities published on October 21, 2026:

* **CVE-2026-109619** (CVSS 9.2): Stale global state / Use-After-Free across consecutive requests in persistent worker processes (with `session.upload_progress` being the confirmed reproduction vector).
* **CVE-2026-109618** (CVSS 9.2): Zend Engine heap memory allocator corruption on Out-Of-Memory (`zend_bailout`).

> [!IMPORTANT]
> **EOL Scope Notice:** Official community support for PHP 5.6 ended in December 2018. Upstream PHP does not release official updates for PHP 5.6. This repository provides backports adapted specifically for Zend Engine 2 for legacy environments that cannot be upgraded immediately. For permanent protection, upgrading to an actively supported PHP branch (**PHP 8.2+ / 8.3+**) remains strongly recommended.

---

## Vulnerability Scope & Mechanisms

### CVE-2026-109619: Stale Global State & Cross-Request UAF

The root cause of CVE-2026-109619 is an architectural pattern in persistent worker processes (such as `php-fpm` or Apache `prefork`/`mod_php`):

```text
Request-owned state -> Worker-global pointer -> Request memory freed on bailout ->
Stale pointer survives in worker -> Same worker serves next request ->
Consumer dereferences stale pointer -> Use-After-Free / Memory Corruption
```

1. **Parser Allocation:** When parsing `multipart/form-data` uploads containing `PHP_SESSION_UPLOAD_PROGRESS`, `php_session_rfc1867_callback` (`ext/session/session.c`) allocates a tracking structure on the request heap and stores its address in the worker-global variable `PS(rfc1867_progress)`.
2. **Abnormal Bailout:** If execution is aborted (e.g. execution timeout, memory limit exceeded, connection drop), `zend_bailout()` (`longjmp`) unwinds the stack to `php_request_shutdown()`, skipping standard deallocation events (`MULTIPART_EVENT_END`).
3. **Stale Pointer Retention:** Because `PS(rfc1867_progress)` was neither reset on request start (`RINIT`) nor guaranteed clean on bailout shutdown (`RSHUTDOWN`), the worker process retains a dangling pointer to freed memory.
4. **Cross-Request Dereference:** When the same worker handles a subsequent request, processing multipart headers or session cleanup dereferences this stale memory block, leading to memory corruption or remote code execution.

### CVE-2026-109618: Zend Engine OOM Heap Corruption

When memory limit exhaustion occurs during internal allocations, legacy Zend Engine 2 invoked `zend_bailout()` directly from deep allocator routines. In high-concurrency environments, unwinding the stack mid-allocation corrupted internal linked lists and free-bucket metadata in `zend_alloc.c`, leaving the memory manager in an undefined state for subsequent allocations in persistent workers.

---

## Remediation Hierarchy

### Tier 1: Full Upgrade (Recommended)
Migrate to an actively supported PHP release (**PHP 8.2+ / 8.3+**) that includes official upstream fixes. This is the only way to eliminate both vulnerabilities fully and permanently.

### Tier 2: Source Patch & Rebuild (For Legacy PHP 5.6)
Apply one of our backported C patches to PHP 5.6 source and recompile:

| Patch File | Scope | Components Covered | Best For |
| :--- | :--- | :--- | :--- |
| **`patches/php-5.6.x-full-cve-2026-109618-109619.patch`** *(Recommended)* | Full Engine Backport | 13 core files: `zend_alloc.c` (`zend_mm_safe_error_ex`), `SAPI.c`, `main.c`, `rfc1867.c`, `session.c` | Production servers needing comprehensive protection against both OOM corruption and stale global state. |
| **`patches/php-5.6.x-session-upload-progress-uaf.patch`** | Targeted Session Patch | `ext/session/session.c` | Minimal footprint; fixes the specific `session.upload_progress` lifecycle and NULL guards. |

#### Design Advantage in `session.c`
Upstream minimal emergency patches for EOL versions took the blunt approach of completely neutering or disabling the upload progress callback (`|| 1` / `|| true`).  
In contrast, our backport preserves the legitimate upload progress functionality while strictly enforcing lifecycle resets (`RINIT`, `RSHUTDOWN`, `GINIT`) and NULL guard checks (`if (!progress) break;`) across all multipart callback events.

### Tier 3: Configuration Mitigation (No Rebuild / No Root)
If you cannot recompile or lack root privileges, disable the upload progress mechanism in your server configuration.

> [!WARNING]
> **Scope of Tier 3:**
> Disabling `session.upload_progress` closes the primary confirmed reproduction vector for **CVE-2026-109619**.  
> It does **NOT** resolve **CVE-2026-109618** (Zend Engine allocator corruption upon OOM). Treat Tier 3 as an emergency risk-reduction measure while preparing patched binaries or migration.

---

## Configuration Mitigation Details (Tier 3)

### PHP-FPM (Recommended for FastCGI)

In your PHP-FPM pool configuration (e.g. `/etc/php/5.6/fpm/pool.d/www.conf`):

```ini
; Disable the vulnerable upload progress tracking mechanism
php_admin_flag[session.upload_progress.enabled] = off
```

Reload PHP-FPM:
```bash
systemctl reload php5.6-fpm
```

### Apache (`.htaccess` / `httpd.conf`)

```apache
# 1. Disable session upload progress
<IfModule mod_php5.c>
    php_flag session.upload_progress.enabled off
</IfModule>

# 2. Defense-in-depth: Block queries containing exploit keywords in URL/query string
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{THE_REQUEST} (PHP_SESSION_UPLOAD_PROGRESS|upload_progress) [NC,OR]
    RewriteCond %{QUERY_STRING} (PHP_SESSION_UPLOAD_PROGRESS|upload_progress) [NC]
    RewriteRule .* - [F,L]
</IfModule>
```

> [!NOTE]
> `RewriteCond %{THE_REQUEST}` checks the HTTP request line and query string. Standard multipart POST bodies cannot be inspected by mod_rewrite. Therefore, setting `session.upload_progress.enabled = off` is the authoritative mitigation; rewrite rules serve as a secondary perimeter filter.

### Nginx

```nginx
location ~ \.php$ {
    include fastcgi_params;
    fastcgi_param PHP_VALUE "session.upload_progress.enabled=off";
}

# Block suspicious query parameters
if ($query_string ~* "PHP_SESSION_UPLOAD_PROGRESS|upload_progress") {
    return 403;
}
```

> **Legitimate Uploads Note:** Standard file uploads (`$_FILES`, photo uploads, documents, CSV/Excel imports) do not depend on `session.upload_progress` and continue to work normally when this setting is disabled.

---

## Building from Source (Tier 2)

### Applying Patch Manually

```bash
cd php-5.6.40
# Apply the comprehensive patch (or the targeted session patch)
patch -p1 < patches/php-5.6.x-full-cve-2026-109618-109619.patch

./configure --enable-fpm --enable-session [your additional options...]
make -j$(nproc)
make test TESTS="ext/session/tests/"
make install
```

### Reproducible Docker Build

```bash
docker build -t php56-patched -f build/Dockerfile .
```

---

## Regression Verification & Stress Testing

To verify worker stability and memory isolation under real-world conditions without process restarts, regression testing was conducted against a dedicated single-worker pool (`pm = static`, `pm.max_children = 1`):

* **Stress Protocol:** 50 consecutive multipart requests with active `PHP_SESSION_UPLOAD_PROGRESS` were routed to the exact same worker PID.
* **Results:**
  * Successful requests: **50 / 50 (100%)**
  * Worker crashes / SIGSEGV: **0**
  * Worker PID churn / respawns: **0 (the same PID handled all 50 requests)**
  * Observed RSS growth / Memory leak: **No leak detected** (worker resident memory remained steady at ~221 KB baseline)
  * Superglobals (`$_POST`, `$_FILES`): completely sterile between successive requests

---

## Pre-compiled Binaries & Verification

Pre-built binaries are provided in [`releases/`](releases/) and attached to GitHub Releases.

### Build Provenance
* **Upstream Source Base:** PHP 5.6.40 (`php5.6_5.6.40-104+ubuntu24.04.1+deb.sury.org+1`)
* **Build OS:** Ubuntu 24.04 LTS (x86_64, Linux kernel 6.8.0, glibc 2.39)
* **Compiler:** `gcc (Ubuntu 13.2.0-23ubuntu4) 13.2.0`
* **Compilation Flags:** `-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2`

### SHA256 Checksums

```text
688e235dface62e88c14941a50969223d6633d60b779448597bcf4e9f6d16d4c  php-fpm5.6-bin-x86_64.tar.gz
e9193946a6e94daa51bc29054647328f1939c8ea53fc915840ba1b63e52896a3  php5.6-fpm_5.6.40-104+ubuntu24.04.1+deb.sury.org+1_amd64.deb
506bd4f97d9de494593e1c0dcb268a84abe69113cd829012a05d9bee563e83ba  php5.6-cli_5.6.40-104+ubuntu24.04.1+deb.sury.org+1_amd64.deb
a686d6ecb2885a93c1fddae7901d90d153b01cdfee7837e1d16e2b8a965e64bc  php5.6-common_5.6.40-104+ubuntu24.04.1+deb.sury.org+1_amd64.deb
```

### Verification
Verify checksums locally before deploying:
```bash
sha256sum -c << 'EOF'
688e235dface62e88c14941a50969223d6633d60b779448597bcf4e9f6d16d4c  php-fpm5.6-bin-x86_64.tar.gz
e9193946a6e94daa51bc29054647328f1939c8ea53fc915840ba1b63e52896a3  php5.6-fpm_5.6.40-104+ubuntu24.04.1+deb.sury.org+1_amd64.deb
EOF
```

---

## Author

Viktor Zarbashev ([@checkfoxe](https://github.com/checkfoxe))

## License

PHP License v3.01.
