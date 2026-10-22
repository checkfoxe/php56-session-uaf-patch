# PHP 5.6 Backport: Session Upload Progress Fix for CVE-2026-109619

English | [Читать на русском](README_RU.md)

This project provides a PHP 5.6 backport addressing the stale `rfc1867_progress` state in the Session Upload Progress mechanism associated with **CVE-2026-109619** (CVSS 9.2).

Unlike the emergency mitigation used in upstream EOL packages (which simply disabled the Session Upload Progress callback with `|| true`), this patch preserves the feature and explicitly manages the lifetime of `rfc1867_progress` across request initialization and shutdown.

> **Important Scope Notice:** This patch specifically targets the confirmed Session Upload Progress vector of CVE-2026-109619. It should not be interpreted as a full backport of all upstream changes associated with CVE-2026-109618/CVE-2026-109619 across the entirety of Zend Engine. For production systems, upgrading to an actively supported PHP release (8.2+) remains strongly recommended.

---

## Remediation Hierarchy (Choose Your Strategy)

### Tier 1: Full Upgrade (Recommended)
Migrate to an actively supported PHP release (**PHP 8.2+ / 8.3+**) that includes official upstream fixes. This is the only way to eliminate both vulnerabilities fully and permanently.

### Tier 2: Source Patch & Rebuild (For Legacy PHP 5.6)
Apply the backported C patch (`patches/php-5.6.x-session-upload-progress-uaf.patch`) and recompile PHP 5.6. This addresses the dangling pointer lifecycle across worker processes by isolating request state in Zend Engine 2.

### Tier 3: Emergency Temporary Mitigation (No Rebuild / No Root)
Disable `session.upload_progress` in your configuration (`.htaccess`, `php.ini`, or `nginx.conf`).

> [!WARNING]
> **What Tier 3 Fixes and What It Does NOT Fix:**
> Disabling `session.upload_progress` disables the confirmed exploitation vector for **CVE-2026-109619**.  
> It does **NOT** fix **CVE-2026-109618** (general OOM memory exhaustion handling in Zend Engine). It must be treated as an emergency risk-reduction measure while preparing a patched binary or upgrade.

---

## Technical Details

### CVE-2026-109619: session.upload_progress UAF

1. **Parser Initialization:** When parsing `multipart/form-data` uploads containing `PHP_SESSION_UPLOAD_PROGRESS`, `php_session_rfc1867_callback` (`ext/session/session.c`) allocates a tracking struct and assigns its pointer to `PS(rfc1867_progress)`.
2. **Abnormal Bailout:** If execution is aborted or memory limit is exceeded, `zend_bailout()` (`longjmp`) unwinds the stack to request shutdown, bypassing `MULTIPART_EVENT_END`.
3. **Dangling Pointer across Workers:** Because `PS(rfc1867_progress)` was not reset in `php_rinit_session_globals()` or `php_rshutdown_session_globals()`, persistent worker processes (Apache `mod_php` or `php-fpm`) retain a stale pointer to freed request heap.
4. **Use-After-Free:** Subsequent requests handled by the same worker process dereference this stale memory during form data processing or session cleanup.

### What This Patch Changes

* **Explicit Request Initialization (`RINIT`):** Sets `PS(rfc1867_progress) = NULL;` in `php_rinit_session_globals()`. Recycled workers cannot inherit stale pointers from earlier aborted requests.
* **Emergency Cleanup (`RSHUTDOWN`):** Ensures `php_rshutdown_session_globals()` deallocates unclosed structures and resets the pointer if request ended via `zend_bailout()`.
* **Module Global Reset (`GINIT`):** Sets `ps_globals->rfc1867_progress = NULL;` on startup.

---

## Temporary Mitigation (Tier 3)

If you cannot recompile or lack root privileges, apply this immediate mitigation.

### Apache (.htaccess / httpd.conf)

```apache
# 1. Disable the vulnerable upload progress tracking feature
<IfModule mod_php5.c>
    php_flag session.upload_progress.enabled off
</IfModule>

# 2. Block incoming requests containing exploit signatures
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{THE_REQUEST} (PHP_SESSION_UPLOAD_PROGRESS|upload_progress) [NC,OR]
    RewriteCond %{QUERY_STRING} (PHP_SESSION_UPLOAD_PROGRESS|upload_progress) [NC]
    RewriteRule .* - [F,L]
</IfModule>
```

> **Note on Legitimate Uploads:** Regular file uploads (`$_FILES`, photo uploads, CSV/Excel imports) do **not** use `session.upload_progress` and continue to operate normally.

### Nginx

```nginx
location ~ \.php$ {
    include fastcgi_params;
    fastcgi_param PHP_VALUE "session.upload_progress.enabled=off";
}

if ($query_string ~* "PHP_SESSION_UPLOAD_PROGRESS|upload_progress") {
    return 403;
}
```

---

## Building from Source (Tier 2)

### Applying Patch Manually

```bash
cd php-5.6.40
patch -p1 < patches/php-5.6.x-session-upload-progress-uaf.patch

./configure --enable-fpm --enable-session [your options...]
make -j$(nproc)
make test TESTS="ext/session/tests/"
make install
```

### Reproducible Docker Build

```bash
docker build -t php56-patched -f build/Dockerfile .
```

---

## Pre-compiled Binaries & Verification

Pre-built binaries are provided in [`releases/`](releases/) and attached to [GitHub Releases](../../releases).

### Build Provenance
* **Upstream Source Base:** PHP 5.6.40 (`php5.6_5.6.40-104+ubuntu24.04.1+deb.sury.org+1`)
* **Build OS:** Ubuntu 24.04 LTS (x86_64, Linux kernel 6.8.0, glibc 2.39)
* **Compiler:** `gcc (Ubuntu 13.2.0-23ubuntu4) 13.2.0`
* **Compilation Flags:** `-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2`

### SHA256 Checksums

```text
6c4a6cad16f4f4c235ee1ec4c2da3886e659a3c8695153c4cca95224db0062d6  php-fpm5.6-bin-x86_64.tar.gz
f1106037dc10352fe1737cbf46a665381b770f9c182880f5c5a8a5f5728f8af1  php5.6-fpm_5.6.40-104+ubuntu24.04.1+deb.sury.org+1_amd64.deb
ef763df996d2d65993d977a4ec4ce1e99d9108aa5ce616256b69073e9852aca5  php5.6-cli_5.6.40-104+ubuntu24.04.1+deb.sury.org+1_amd64.deb
a686d6ecb2885a93c1fddae7901d90d153b01cdfee7837e1d16e2b8a965e64bc  php5.6-common_5.6.40-104+ubuntu24.04.1+deb.sury.org+1_amd64.deb
```

### Verification
Verify checksums locally before deploying:
```bash
sha256sum -c << 'EOF'
6c4a6cad16f4f4c235ee1ec4c2da3886e659a3c8695153c4cca95224db0062d6  php-fpm5.6-bin-x86_64.tar.gz
f1106037dc10352fe1737cbf46a665381b770f9c182880f5c5a8a5f5728f8af1  php5.6-fpm_5.6.40-104+ubuntu24.04.1+deb.sury.org+1_amd64.deb
EOF
```

---

## Author

Viktor Zarbashev ([@checkfoxe](https://github.com/checkfoxe))

## License

PHP License v3.01.
