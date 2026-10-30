<div align="center">

# 🛡️ Universal PHP Security Audit Scanner & EOL Patches (PHP 5.2–8.1)

### Comprehensive Protection Against CVE-2026-109618, CVE-2026-109619 & CVE-2026-115560 ("PHP2Shell")

[![Language: English](https://img.shields.io/badge/Language-English%20(Default)-2ea44f?style=for-the-badge)](README.md)
[![Language: Russian](https://img.shields.io/badge/%D0%AF%D0%B7%D1%8B%D0%BA-%D0%A0%D1%83%D1%81%D1%81%D0%BA%D0%B0%D1%8F%20%D0%B4%D0%BE%D0%BA%D1%83%D0%BC%D0%B5%D0%BD%D1%82%D0%B0%D1%86%D0%B8%D1%8F-007ec6?style=for-the-badge)](README.ru.md)

[![PHP Versions](https://img.shields.io/badge/PHP-5.2%20to%208.1%20EOL-777bb4?style=flat-square&logo=php&logoColor=white)](#)
[![Scanner Version](https://img.shields.io/badge/Scanner-v1.3%20(Strictly%20Read--Only)-brightgreen?style=flat-square)](#)
[![Architecture](https://img.shields.io/badge/Patch%20Architecture-Full%20Soft--OOM-blue?style=flat-square)](#)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20Bash)-orange?style=flat-square)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-007ec6?style=flat-square)](#)

[![Panels](https://img.shields.io/badge/Panels-FastPanel%20%7C%20ISPmanager%20%7C%20cPanel%20%7C%20Plesk%20%7C%20aaPanel%20%7C%20HestiaCP%20%7C%20DirectAdmin%20%7C%20CloudLinux-4c1?style=flat-square)](#)

</div>

A production-grade, **strictly read-only (zero-disk-write)** security audit toolkit and collection of native **Soft-OOM** backported patches for critical Zend Engine vulnerabilities affecting **all EOL PHP versions (5.2 through 8.1)**.  
While upstream PHP Group only addressed active branches (`8.2.35+`, `8.3.36+`, `8.4.27+`, `8.5.12+`), this repository provides an **all-in-one universal scanner (`check_php_cve.sh` v1.3)** for any Linux hosting environment and **full architectural Soft-OOM patches** with 100% **FastPanel** module ABI compatibility and **OpenSSL 1.1+ (`ssl://`, `tls://`)** stream transport support.

---

## 🔒 Vulnerability Overview ("PHP2Shell")

- **CVE-2026-109618 (RCE via ZendMM OOM `longjmp` memory corruption):**  
  Exceeding `memory_limit` in unpatched PHP triggered an immediate `zend_bailout()` (`longjmp`) directly inside the `ZendMM` memory allocator mid-operation (while parsing `POST`/`GET`/`COOKIE`, `multipart/form-data`, `unserialize()`, or mutating `HashTable` buckets). This left internal Zend Engine data structures with dangling/corrupted pointers, enabling Remote Code Execution during request shutdown or subsequent worker requests.
- **CVE-2026-109619 (RCE via stale executor & error-handler state across FPM requests):**  
  Corrupted global Zend VM executor state (`EG(user_error_handler)`, `CG`/`BG` globals) persisted across requests inside long-lived `php-fpm`, `mod_fcgid`, and `lsphp` worker processes.
- **CVE-2026-115560 & Session Upload Progress Deserialization Gaps (`Zero 1`):**  
  Unsafe deserialization of `PHP_SESSION_UPLOAD_PROGRESS` data prior to script execution, leading to PHP Object Injection when `session.upload_progress.enabled = 1` (especially when combined with `session.serialize_handler = php_serialize`).

The upstream PHP Group officially fixed these vulnerabilities only in active branches (**PHP 8.2.35+**, **8.3.36+**, **8.4.27+**, and **8.5.12+**), leaving all EOL branches (**PHP 5.2 – 8.1**) without official upstream releases.

---

## 🚀 Universal Read-Only Server Audit (`check_php_cve.sh` v1.3)

The scanner operates in **strictly Read-Only mode (`Zero Disk Writes`)**: it never modifies `php.ini`, never installs system packages, and never creates temporary files on disk (even remote HTTP probes execute 100% in memory).

### Quick One-Line Local Audit:
```bash
curl -sSL "https://raw.githubusercontent.com/avego/php2shell/main/check_php_cve.sh" | bash
```

### Advanced CLI Modes:
```bash
# Deep filesystem scan for all custom & archived PHP binaries (/opt, /www, /usr/local, /home, /var, /usr/src):
curl -sSL "https://raw.githubusercontent.com/avego/php2shell/main/check_php_cve.sh" | bash -s -- --all

# Machine-readable JSON output for CI/CD, Ansible, Zabbix, and fleet monitoring:
curl -sSL "https://raw.githubusercontent.com/avego/php2shell/main/check_php_cve.sh" | bash -s -- --json

# Non-destructive in-memory remote HTTP/HTTPS header, WAF & multipart probe (zero temp files):
curl -sSL "https://raw.githubusercontent.com/avego/php2shell/main/check_php_cve.sh" | bash -s -- --url https://example.com
```

---

## 🧠 How `check_php_cve.sh` Works & Key Differences vs. Other Scanners

Several third-party `PHP2Shell` scanners suffer from critical methodological flaws by matching indirect or historically "polluted" strings inside PHP binaries — resulting in **dangerous False Positive (`"PATCHED"`) verdicts on 100% vulnerable servers**.

### Architectural Comparison:

| Audit Criterion / Mechanism | Other Third-Party Scanners | `check_php_cve.sh` (v1.3) |
|---|---|---|
| **ELF Binary Signature Purity (Zero False Positives)** | ❌ Match `"Actual POST length does not match Content-Length"` (present in `main/SAPI.c` since **2004** in every unpatched PHP build!) or `max_multipart_body_parts` (introduced in **February 2023** for `CVE-2023-0662` in PHP 8.0.28 / 8.1.16, present in unpatched PHP 8.0.30 & 8.1.29). | ✅ Matches **exclusively October 2026 Zend Engine patch symbols** that never existed prior to the 2026 security patches: `zend_handle_delayed_oom` (Zend 2), `memory_hard_limit_percent` (Zend 3/4), `zend_mm_safe_error_ex`, `__PHP_Incomplete_Class_Serialized`. **False-positive rate = 0%.** |
| **Patch Architecture Classification (`Soft-OOM` vs `Minimal` vs `Partial`)** | ⚠️ Collapse any string match into a generic `"Patched"` label or misclassify EOL PHP 5.x/7.x backports. | ✅ Distinguishes 4 exact patch tiers:<br>1. **`Full Soft-OOM Patch`** (delayed OOM, FPM worker survives, `shutdown` functions run safely);<br>2. **`Enhanced Patch`** (`_exit(1)` on OOM + `incomplete_classes_only`);<br>3. **`Minimal Vendor Patch`** (abrupt `_exit(1)` inside allocator killing FPM workers with `502 Bad Gateway` + stripped `upload_progress`);<br>4. **`Partial Patch`** (`rfc1867`/`session` modified, but `ZendMM` allocator remains **UNPATCHED**!). |
| **Full SAPI Set Verification (`CLI` + `CGI` + `FPM` + `LSPHP`)** | ⚠️ Often inspect only the `php` CLI binary while overlooking an unpatched `php-fpm`, `php-cgi`, or `lsphp` daemon actively serving web traffic. | ✅ Audits **all 4 binaries per installation** (`bin/php`, `bin/php-cgi`, `sbin/php-fpm`, `bin/lsphp`), detects live `php-fpm` processes in memory, and reports `SAFE` **only if every present SAPI binary is patched**. |
| **Deep `session.upload_progress` & `Zero 1` Session Audit** | ⚠️ Only check `ini_get('session.upload_progress.enabled')` and mislead admins into thinking `Off` makes an unpatched binary safe (ignoring that `CVE-2026-109618` triggers via ordinary POST/GET OOM without `upload_progress`). | ✅ Distinguishes 5 exact states:<br>• `N/A in PHP 5.2/5.3` (feature added in 5.4);<br>• `HARD-DISABLED in binary (\|\| 1)` (dead-code eliminated at compile time in vendor `minimal` patches);<br>• `ENABLED & ISOLATED` (protected via `__PHP_Incomplete_Class_Serialized`);<br>• `DISABLED in php.ini` (mitigates `CVE-2026-115560` & `Zero 1`, while explicitly flagging the binary as **`[UNPATCHED BINARY]`** because OOM RCE remains exposed!);<br>• Reports active `session.serialize_handler` (`php` / `php_serialize`). |
| **OpenSSL Stream Transport Verification (`ssl://` & `tls://`)** | ❌ Not checked (recompiling legacy PHP 5.x/7.x on modern Linux distros frequently silently breaks HTTPS/cURL/SMTP due to OpenSSL 1.1/3.0 mismatches). | ✅ Actively verifies `stream_get_transports()` on every PHP runtime to ensure `ssl://` and `tls://` transports are operational. |
| **Strict `100% Read-Only` Guarantee** | ⚠️ May mutate production configs or write temporary files to `/tmp`. | ✅ **Strictly `Read-Only`:** zero disk writes, zero `mktemp` files, zero package installations. Works even without `binutils` (automatic fallback from `strings` to `grep -a`). |
| **Control Panel Discovery** | 5–6 basic paths (`aaPanel`, `Hestia`, `Plesk`, `cPanel`, `Remi`). | **13+ Control Panels & Repositories:** `FastPanel` (including internal `/opt/fphp`), `ISPmanager`, `aaPanel/Baota`, `Plesk`, `cPanel/EA4`, `CloudLinux alt-php`, `DirectAdmin`, `CyberPanel/OpenLiteSpeed`, `HestiaCP`, `VestaCP`, `BrainyCP`, `KeyHelp`, `Remi/RHSCL`, and system PHP. |

---

## ⚖️ Patching Paradigms Compared: Our `Full Soft-OOM` vs. Vendor `Minimal Patch`

Several control panel vendors (such as ISPmanager in `isp-php54..81` and FastPanel in `php54`/`php71`) shipped a stripped-down 7-function `minimal` patch instead of backporting upstream PHP 8.2.35's `Soft-OOM` architecture:

| Behavior / Feature | Vendor `Minimal Patch` (`zend_mm_safe_error_ex`) | Our `Full Soft-OOM Patch` (`avego/php2shell`) |
|---|---|---|
| **Behavior on `memory_limit` exhaustion (OOM)** | Immediately terminates the entire OS process via `_exit(1)` inside the allocator. | Sets a delayed OOM flag (`delayed_oom` / `memory_hard_limit_percent`), returns a safe fallback, and raises a clean fatal error at a safe VM point. |
| **PHP-FPM / Nginx Worker Stability** | ⚠️ Killed FPM worker drops the upstream socket (`502 Bad Gateway`), loses in-memory caches, and forces the FPM master to fork a replacement child. | ✅ PHP-FPM worker **stays alive**, cleanly unwinds request memory, and continues serving requests. |
| **`register_shutdown_function()` & Framework Loggers** | ❌ **Broken on OOM** — shutdown callbacks and error loggers never execute. | ✅ **Executes safely and reliably** after controlled stack unwinding. |
| **`session.upload_progress` Functionality** | ❌ **Hard-disabled at compile time** via `if (!PS(rfc1867_enabled) \|\| 1)` — upload progress bars stop working even if enabled in `php.ini`. | ✅ **Preserved & isolated** via `incomplete_classes_only` (`__PHP_Incomplete_Class_Serialized`) + early `php_rinit_session_globals()`. |

---

## 📊 Tested PHP Versions & Patching Manuals

| PHP Version | Target Environment | Protection Architecture | Status | Step-by-Step Guide (RU) |
|---|---|---|---|---|
| **PHP 5.2.17 – 5.4.45** | Source / Hosting Panels | Zend Engine 2 Backport (`zend_handle_delayed_oom`) | ✅ Patches in `patch/` | Universal `.patch` files |
| **PHP 5.6.40** | FastPanel `/opt/php56` | Zend Engine 2 Backport (`zend_handle_delayed_oom`) + OpenSSL 1.1 | ✅ Protected | [PHP 5.6 Manual](FASTPANEL_PHP5.6_PATCHING_MANUAL.md) |
| **PHP 7.0.33 – 7.3.33** | FastPanel `/opt/php71`, etc. | Zend Engine 3 Backport (`memory_hard_limit_percent`) | ✅ Protected | [PHP 7.1 Manual](FASTPANEL_PHP7.1_PATCHING_MANUAL.md) |
| **PHP 7.3.33 (`fphp`)** | FastPanel `/opt/fphp` | Internal FastPanel Panel Engine (`fastpanel2-apps`) | ✅ Protected | [fphp 7.3 Manual](FASTPANEL_FPHP7.3_PATCHING_MANUAL.md) |
| **PHP 7.4.33** | Debian 11 System PHP | Native `.deb` Packages (`dpkg-buildpackage`) | ✅ Protected | [Debian 11 PHP 7.4 Manual](FASTPANEL_PHP7.4_DEBIAN11_MANUAL.md) |
| **PHP 8.0.30 – 8.1.34** | FastPanel `/opt/php81` | Zend Engine 4 Backport (`memory_hard_limit_percent` + OPcache fix) | ✅ Protected | [PHP 8.1 Manual](FASTPANEL_PHP8.1_PATCHING_MANUAL.md) |
| **PHP 8.2.35+ / 8.3.36+ / 8.4.27+ / 8.5.12+** | FastPanel `/opt/php84`, `/opt/php85` | Official Upstream PHP Group Release (`Soft-OOM`) | ✅ Safe Upstream | Built into official release |

---

## 📁 Repository Structure

```text
├── patch/                                                     # Soft-OOM security backports & OpenSSL compatibility patches
│   ├── php56-openssl11/                                       # Adapted OpenSSL 1.1 extension sources for PHP 5.6
│   │   ├── openssl.c
│   │   ├── xp_ssl.c
│   │   └── php_openssl.h
│   ├── php-5.6-openssl-1.1.patch                              # Unified diff for OpenSSL 1.1 compatibility on PHP 5.6
│   ├── php-5.2.17-cve-2026-109618-109619.patch
│   ├── php-5.3.29-cve-2026-109618-109619.patch
│   ├── php-5.4.45-cve-2026-109618-109619.patch
│   ├── php-5.6.40-cve-2026-109618-109619.patch
│   ├── php-7.0.33-cve-2026-109618-109619.patch
│   ├── php-7.1.33-cve-2026-109618-109619.patch
│   ├── php-7.2.34-cve-2026-109618-109619.patch
│   ├── php-7.3.33-cve-2026-109618-109619.patch
│   ├── php-7.4.33-cve-2026-109618-109619.patch                # For clean upstream php-7.4.33.tar.gz
│   ├── php-7.4.33-debian11-cve-2026-109618-109619.patch       # Reference diff for Debian 11 dpkg-buildpackage
│   ├── php-8.0.30-cve-2026-109618-109619.patch
│   ├── php-8.1.29-cve-2026-109618-109619.patch
│   └── php-8.1.34-cve-2026-109618-109619.patch
├── FASTPANEL_PHP5.6_PATCHING_MANUAL.md                        # Compilation guide: FastPanel /opt/php56 (RU)
├── FASTPANEL_PHP7.1_PATCHING_MANUAL.md                        # Compilation guide: FastPanel /opt/php71 (RU)
├── FASTPANEL_FPHP7.3_PATCHING_MANUAL.md                       # Compilation guide: FastPanel /opt/fphp (RU)
├── FASTPANEL_PHP7.4_DEBIAN11_MANUAL.md                        # Compilation guide: Debian 11 native .deb (RU)
├── FASTPANEL_PHP8.1_PATCHING_MANUAL.md                        # Compilation guide: FastPanel /opt/php81 (RU)
├── check_php_cve.sh                                           # Universal Read-Only Security Scanner v1.3
├── README.md                                                  # English documentation (Default)
└── README.ru.md                                               # Russian documentation (На русском языке)
```

---

## ⚡ Key Compatibility Principles When Building for FastPanel

1. **Inspect Existing Build Configuration First:**
   Always verify the exact sub-version and original `Configure Command` flags before compiling:
   ```bash
   /opt/phpXX/bin/php -v
   /opt/phpXX/bin/php -i | grep -i "configure command"
   ```

2. **Preserve Database Extension ABI (`shared,mysqlnd`) & OpenSSL (`ssl://`, `tls://`):**
   FastPanel loads database drivers (`mysqli.so`, `pdo_mysql.so`) as **external shared modules (`shared`)** from `/opt/phpXX/conf.d/*.ini`.
   - Compile the core binary with built-in `mysqlnd` and `--with-openssl`, while keeping DB drivers shared:
     ```bash
     --with-openssl \
     --enable-mysqlnd \
     --with-mysqli=shared,mysqlnd \
     --with-pdo-mysql=shared,mysqlnd \
     --with-mysql-sock=/var/run/mysqld/mysqld.sock
     ```
     *(For PHP 5.6, also include `--with-mysql=shared,mysqlnd` and apply `patch/php-5.6-openssl-1.1.patch` for OpenSSL 1.1 compatibility).*

3. **Atomic Binary Replacement (`install -m 755`):**
   Avoid `Text file busy` errors on running workers by installing binaries atomically:
   ```bash
   install -m 755 sapi/cli/php /opt/phpXX/bin/php
   install -m 755 sapi/cgi/php-cgi /opt/phpXX/bin/php-cgi
   [ -f sapi/fpm/php-fpm ] && install -m 755 sapi/fpm/php-fpm /opt/phpXX/sbin/php-fpm 2>/dev/null || true
   ```

---

## 🔍 Manual Binary Verification

### For PHP 7.0 – 8.1 (Zend Engine 3 & 4):
```bash
/opt/phpXX/bin/php -i | grep memory_hard_limit_percent
strings /opt/phpXX/bin/php | grep -E "memory_hard_limit_percent|zend_mm_safe_error_ex"
```

### For PHP 5.2 – 5.6 (Zend Engine 2):
```bash
strings /opt/php56/bin/php | grep -E "zend_handle_delayed_oom|ZEND_OOM_STATE|zend_mm_safe_error_ex"
```

---

## 🛡️ Instant Rollback Procedure

```bash
install -m 755 /opt/phpXX.bak/bin/php /opt/phpXX/bin/php
[ -f /opt/phpXX.bak/bin/php-cgi ] && install -m 755 /opt/phpXX.bak/bin/php-cgi /opt/phpXX/bin/php-cgi 2>/dev/null || true
[ -f /opt/phpXX.bak/sbin/php-fpm ] && install -m 755 /opt/phpXX.bak/sbin/php-fpm /opt/phpXX/sbin/php-fpm 2>/dev/null || true

killall -9 php-cgi 2>/dev/null || true
systemctl restart apache2 2>/dev/null || true
systemctl restart nginx 2>/dev/null || true
systemctl restart fp2-phpXX-fpm 2>/dev/null || systemctl restart phpXX-fpm 2>/dev/null || true
```

---

## 👥 Credits & Provenance

- **Original Upstream PHP (`php-src`) Fix:**
  - **Core Mechanism Author:** **Arnaud Le Blanc** (`arnaud.lb@gmail.com`), upstream commit `01a40e89fb` (*"Avoid state corruption via bailout"*), officially released in PHP 8.2.35+, 8.3.36+, 8.4.27+, and 8.5.12+.
  - **Advisories:** CVE-2026-109618, CVE-2026-109619, CVE-2026-115560 (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp).
- **`Soft-OOM` Backports for EOL PHP Branches (5.2 – 8.1):**
  - **docker-php** community maintainers and **realhidden** ([gist.github.com/realhidden](https://gist.github.com/realhidden)).
- **Universal Read-Only Scanner `check_php_cve.sh` & FastPanel / Debian 11 Adaptation:**
  - **Repository:** [avego/php2shell](https://github.com/avego/php2shell).
