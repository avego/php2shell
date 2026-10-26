#!/usr/bin/env bash
# ==============================================================================
# FastPanel & System PHP Security Audit Script
# Checks PHP installations against CVE-2026-109618 and CVE-2026-109619
# Supports: Debian/Ubuntu, FastPanel (/opt/php*, /opt/fphp), and System PHP
# ==============================================================================

set -u

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

TOTAL_CHECKED=0
TOTAL_PROTECTED=0
TOTAL_VULNERABLE=0
PROCESSED_PATHS=()

is_already_processed() {
    local target="$1"
    for item in "${PROCESSED_PATHS[@]-}"; do
        if [ "$item" = "$target" ]; then
            return 0
        fi
    done
    return 1
}

echo -e "${BOLD}${CYAN}====================================================================${NC}"
echo -e "${BOLD}${CYAN}   FastPanel & Debian System PHP Security Audit (CVE-2026-109618/19)${NC}"
echo -e "${BOLD}${CYAN}====================================================================${NC}\n"

# Verify required tools
if ! command -v strings >/dev/null 2>&1; then
    echo -e "${YELLOW}[!] Warning: 'strings' utility not found. Installing binutils...${NC}"
    apt-get update -qq && apt-get install -y -qq binutils >/dev/null 2>&1 || true
fi

# Function to audit a single PHP binary set
audit_php() {
    local label="$1"
    local cli_bin="$2"
    local cgi_bin="${3:-}"
    local fpm_bin="${4:-}"

    if [ ! -x "$cli_bin" ]; then
        return
    fi

    # Avoid duplicate inspection
    local real_cli
    real_cli=$(readlink -f "$cli_bin" 2>/dev/null || echo "$cli_bin")
    if is_already_processed "$real_cli"; then
        return
    fi
    PROCESSED_PATHS+=("$real_cli")

    TOTAL_CHECKED=$((TOTAL_CHECKED + 1))

    # Determine version info
    local ver_raw
    ver_raw=$("$cli_bin" -v 2>/dev/null | head -n 1)
    local ver_num
    ver_num=$(echo "$ver_raw" | grep -oE "PHP [0-9]+\.[0-9]+\.[0-9]+" | awk '{print $2}')
    [ -z "$ver_num" ] && ver_num=$(echo "$ver_raw" | awk '{print $2}')

    local major_ver
    major_ver=$(echo "$ver_num" | cut -d'.' -f1)

    echo -e "${BOLD}▶ Target: ${CYAN}${label}${NC} (${cli_bin})"
    echo -e "  Version: ${BOLD}${ver_raw}${NC}"

    local cli_protected=0
    local cgi_protected=0
    local fpm_protected=0
    local check_type=""

    if [ "$major_ver" = "5" ]; then
        check_type="Zend Engine 2 (Delayed OOM / zend_handle_delayed_oom)"
        # PHP 5.x check: zend_handle_delayed_oom in binary strings
        if strings "$cli_bin" 2>/dev/null | grep -q "zend_handle_delayed_oom"; then
            cli_protected=1
        fi

        if [ -n "$cgi_bin" ] && [ -x "$cgi_bin" ]; then
            if strings "$cgi_bin" 2>/dev/null | grep -q "zend_handle_delayed_oom"; then
                cgi_protected=1
            fi
        fi

        if [ -n "$fpm_bin" ] && [ -x "$fpm_bin" ]; then
            if strings "$fpm_bin" 2>/dev/null | grep -q "zend_handle_delayed_oom"; then
                fpm_protected=1
            fi
        fi
    else
        check_type="Zend Engine 3/4 (memory_hard_limit_percent directive)"
        # PHP 7.x & 8.x check: memory_hard_limit_percent via ini and strings
        local ini_check
        ini_check=$("$cli_bin" -i 2>/dev/null | grep -i "memory_hard_limit_percent" || true)
        local str_check
        str_check=$(strings "$cli_bin" 2>/dev/null | grep "memory_hard_limit_percent" || true)

        if [ -n "$ini_check" ] || [ -n "$str_check" ]; then
            cli_protected=1
        fi

        if [ -n "$cgi_bin" ] && [ -x "$cgi_bin" ]; then
            if strings "$cgi_bin" 2>/dev/null | grep -q "memory_hard_limit_percent"; then
                cgi_protected=1
            fi
        fi

        if [ -n "$fpm_bin" ] && [ -x "$fpm_bin" ]; then
            if strings "$fpm_bin" 2>/dev/null | grep -q "memory_hard_limit_percent"; then
                fpm_protected=1
            fi
        fi
    fi

    echo -e "  Audit mechanism: ${check_type}"

    # Print CLI Status
    if [ "$cli_protected" -eq 1 ]; then
        echo -e "  ├─ CLI (${cli_bin}): ${GREEN}${BOLD}✔ PROTECTED${NC}"
    else
        echo -e "  ├─ CLI (${cli_bin}): ${RED}${BOLD}✘ VULNERABLE${NC}"
    fi

    # Print CGI Status if exists
    if [ -n "$cgi_bin" ] && [ -f "$cgi_bin" ]; then
        if [ "$cgi_protected" -eq 1 ]; then
            echo -e "  ├─ CGI (${cgi_bin}): ${GREEN}${BOLD}✔ PROTECTED${NC}"
        else
            echo -e "  ├─ CGI (${cgi_bin}): ${RED}${BOLD}✘ VULNERABLE${NC}"
        fi
    fi

    # Print FPM Status if exists
    if [ -n "$fpm_bin" ] && [ -f "$fpm_bin" ]; then
        if [ "$fpm_protected" -eq 1 ]; then
            echo -e "  ├─ FPM (${fpm_bin}): ${GREEN}${BOLD}✔ PROTECTED${NC}"
        else
            echo -e "  ├─ FPM (${fpm_bin}): ${RED}${BOLD}✘ VULNERABLE${NC}"
        fi
    fi

    # Overall verdict
    if [ "$cli_protected" -eq 1 ]; then
        echo -e "  └─ Verdict: ${GREEN}${BOLD}[SAFE / PATCHED]${NC}\n"
        TOTAL_PROTECTED=$((TOTAL_PROTECTED + 1))
    else
        echo -e "  └─ Verdict: ${RED}${BOLD}[DANGER / ACTION REQUIRED]${NC}\n"
        TOTAL_VULNERABLE=$((TOTAL_VULNERABLE + 1))
    fi
}

# 1. Scan FastPanel Custom PHP installations (/opt/php*)
for php_dir in /opt/php[0-9]* /opt/fphp; do
    if [ -d "$php_dir" ]; then
        label=$(basename "$php_dir")
        cli_bin="${php_dir}/bin/php"
        cgi_bin="${php_dir}/bin/php-cgi"
        fpm_bin="${php_dir}/sbin/php-fpm"
        if [ -x "$cli_bin" ]; then
            audit_php "FastPanel ${label}" "$cli_bin" "$cgi_bin" "$fpm_bin"
        fi
    fi
done

# 2. Scan Debian Versioned System PHP (/usr/bin/php7.*, /usr/bin/php8.*)
for sys_ver in /usr/bin/php[578].[0-9]*; do
    if [ -x "$sys_ver" ]; then
        v_suffix=$(basename "$sys_ver" | sed 's/^php//')
        cli_bin="$sys_ver"
        cgi_bin="/usr/bin/php-cgi${v_suffix}"
        fpm_bin="/usr/sbin/php-fpm${v_suffix}"
        audit_php "Debian System PHP ${v_suffix}" "$cli_bin" "$cgi_bin" "$fpm_bin"
    fi
done

# 3. Scan Default System PHP (/usr/bin/php)
if [ -x "/usr/bin/php" ]; then
    audit_php "Default System PHP" "/usr/bin/php" "/usr/bin/php-cgi" "/usr/sbin/php-fpm"
fi

# Summary
echo -e "${BOLD}${CYAN}====================================================================${NC}"
echo -e "${BOLD}SUMMARY REPORT:${NC}"
echo -e "  Total PHP installations detected: ${BOLD}${TOTAL_CHECKED}${NC}"
echo -e "  Protected (Patched / Upstream):    ${GREEN}${BOLD}${TOTAL_PROTECTED}${NC}"
if [ "$TOTAL_VULNERABLE" -gt 0 ]; then
    echo -e "  Vulnerable (Unpatched):            ${RED}${BOLD}${TOTAL_VULNERABLE}${NC}"
    echo -e "${BOLD}${CYAN}====================================================================${NC}"
    echo -e "${RED}${BOLD}[!] ATTENTION: One or more PHP installations require patching!${NC}"
    echo -e "Refer to manuals at: ${BOLD}https://github.com/avego/php3shell${NC}"
else
    echo -e "  Vulnerable (Unpatched):            ${GREEN}${BOLD}0${NC}"
    echo -e "${BOLD}${CYAN}====================================================================${NC}"
    echo -e "${GREEN}${BOLD}[✔] EXCELLENT: All detected PHP versions are fully protected!${NC}"
fi
echo -e "${BOLD}${CYAN}====================================================================${NC}"
