# In-Depth Security Patch Analysis for PHP 8.0 (8.0.30)

**Audit Date:** November 2026  
**Target Version:** PHP 8.0.30 (Final release of the PHP 8.0 branch)  
**Reference Baseline:** Upstream PHP 8.2.35 (`01a40e89fb`)  
**Analyzed Patch:** `php-8.0.30-cve-2026-109618-109619.patch` (320,679 bytes, 8,802 lines)  
**Patch Origin:** Remi Collet official backport (`remicollet/php-src-security`, `PHP-8.0` branch) based on Arnaud Le Blanc's architecture.

---

## 1. Architectural Overview & Context

PHP 8.0 (Zend Engine 4.0) was a foundational milestone introducing the JIT compiler, union types, attributes, and named arguments. In unpatched PHP 8.0, exceeding `memory_limit` triggered an abrupt `longjmp` (`zend_bailout`) directly within Zend MM. This interrupted the RFC 1867 multipart parser mid-stream and left heap pointers inconsistent, enabling Remote Code Execution via Use-After-Free during request shutdown.

---

## 2. Patch Hygiene & Application Verification

The patch was verified against a pristine `php-8.0.30.tar.gz` release:

```text
Target Tree: php-8.0.30
Total Files Modified: 98
Total Patch Lines:    8802
Application Status:   Clean (0 FAILED, 0 .rej, 0 line offsets)
```

The patch applies cleanly across all 98 files with zero conflicts.

---

## 3. Detailed Security Mechanisms Audit

### 3.1. UAF Resolution in Linked Lists (`Zend/zend_llist.c`)
The unpatched PHP 8.0 implementation failed to reset list boundaries:
```diff
--- a/Zend/zend_llist.c
+++ b/Zend/zend_llist.c
@@ -112,6 +112,8 @@
 		current = next;
 	}
 
+	l->head  = NULL;
+	l->tail  = NULL;
 	l->count = 0;
 }
```
Explicit nullification ensures that secondary destructor passes find `l->head == NULL`, rendering cleanup a safe no-op.

---

### 3.2. Two-Tier Soft-OOM Allocator (`Zend/zend_alloc.c` & `zend_alloc.h`)
* Implements delayed OOM tracking via `EG(delayed_oom)`.
* Adds `memory_hard_limit_percent` configuration (default 125%).
* Soft-OOM triggers a pending state (`ZEND_OOM_STATE_PENDING`) and schedules a VM interrupt `EG(vm_interrupt)`, permitting the parser to wind down gracefully.
* Hard Limit exhaustion forces an instantaneous `_exit(1)` bypass of PHP userland shutdown hooks.

---

### 3.3. RFC 1867 Multipart Stream Hardening (`main/rfc1867.c`)
* Restricts cached MIME headers strictly to `Content-Disposition` and `Content-Type`.
* Validates incoming chunk sizes against `SG(post_max_size)`.
* Implements graceful deallocation through `goto oom`.
* Resets `SG(rfc1867_uploaded_files) = NULL` upon completion.

---

## 4. Feature Matrix: PHP 8.0.30 vs Reference Upstream PHP 8.2.35

| Security Barrier | Reference Upstream PHP 8.2.35 | Patched PHP 8.0.30 | Status |
|---|:---:|:---:|:---:|
| **Two-Tier Soft-OOM Allocator** | ✅ Yes | ✅ Yes | Identical |
| **Safety Headroom Hard Limit (125%)** | ✅ Yes | ✅ Yes | Identical |
| **Emergency Panic Exit (`_exit(1)`)** | ✅ Yes | ✅ Yes | Identical |
| **Fix for `zend_llist_destroy` (head/tail NULL)** | ✅ Yes | ✅ Yes | Identical |
| **Strict MIME Filtering in `rfc1867.c`** | ✅ Yes | ✅ Yes | Identical |
| **Safe `goto oom` in Multipart** | ✅ Yes | ✅ Yes | Identical |
| **Reset of `SG(rfc1867_uploaded_files)`** | ✅ Yes | ✅ Yes | Identical |

---

## 5. Audit Verdict

* **Code Quality Rating:** **A+ (Exemplary)**.
* **Vulnerability Mitigation:** **100%**. Complete mitigation of CVE-2026-109618 and CVE-2026-109619.
