#!/usr/bin/env bash
# ==============================================================================
# Universal Hosting Control Panel & System PHP Security Audit Script
# Version: 1.2 (Updated: 2026-10-29)
# Checks PHP installations against CVE-2026-109618, CVE-2026-109619 & CVE-2026-115560
# Supports: FastPanel, ISPmanager, aaPanel/Baota, HestiaCP, VestaCP, Plesk,
#           cPanel/EasyApache, DirectAdmin, CyberPanel/OLS, BrainyCP, KeyHelp,
#           Remi Repository, and Debian/Ubuntu/RHEL System PHP
# ==============================================================================

set -u

SCRIPT_VERSION="1.2"
SCRIPT_DATE="2026-10-29"
REPO_URL="https://github.com/avego/php2shell"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
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

# Semver comparison: version_ge "$v1" "$v2" returns 0 if v1 >= v2
version_ge() {
    local v1="$1" v2="$2"
    awk -v v1="$v1" -v v2="$v2" '
    BEGIN {
        n1 = split(v1, a, "[.-]");
        n2 = split(v2, b, "[.-]");
        max = (n1 > n2) ? n1 : n2;
        for (i = 1; i <= max; i++) {
            c1 = (i <= n1) ? a[i] + 0 : 0;
            c2 = (i <= n2) ? b[i] + 0 : 0;
            if (c1 > c2) exit 0;
            if (c1 < c2) exit 1;
        }
        exit 0;
    }'
}

# Detect OS / Distribution
detect_os() {
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        echo "${PRETTY_NAME:-${NAME:-Linux} ${VERSION_ID:-}}"
    elif [ -f /etc/redhat-release ]; then
        cat /etc/redhat-release
    elif [ -f /etc/debian_version ]; then
        echo "Debian $(cat /etc/debian_version)"
    else
        uname -sr
    fi
}

# Detect running web servers
detect_web_server() {
    local servers=()
    if pgrep -x nginx >/dev/null 2>&1 || pgrep -f "nginx:" >/dev/null 2>&1; then
        servers+=("nginx")
    fi
    if pgrep -x apache2 >/dev/null 2>&1 || pgrep -x httpd >/dev/null 2>&1 || pgrep -f "apache2|httpd" >/dev/null 2>&1; then
        servers+=("apache")
    fi
    if pgrep -x openlitespeed >/dev/null 2>&1 || pgrep -f "openlitespeed|lsws" >/dev/null 2>&1; then
        servers+=("openlitespeed")
    fi
    if pgrep -x caddy >/dev/null 2>&1; then
        servers+=("caddy")
    fi
    if pgrep -x lighttpd >/dev/null 2>&1; then
        servers+=("lighttpd")
    fi

    if [ ${#servers[@]} -eq 0 ]; then
        echo "None detected (or CLI-only)"
    else
        local IFS=", "
        echo "${servers[*]}"
    fi
}

# Detect installed hosting control panels
detect_control_panels() {
    local panels=()
    if [ -d "/usr/share/fastpanel2" ] || [ -d "/opt/fphp" ] || dpkg -l fastpanel2 >/dev/null 2>&1; then
        panels+=("FastPanel (/opt/php*, /opt/fphp)")
    fi
    if [ -d "/usr/local/mgr5" ]; then
        panels+=("ISPmanager (/usr/local/mgr5, /opt/php*)")
    fi
    if [ -d "/www/server/php" ] || [ -f "/www/server/panel/class/common.py" ]; then
        panels+=("aaPanel / Baota (/www/server/php)")
    fi
    if [ -d "/usr/local/hestia" ]; then
        panels+=("HestiaCP (/usr/local/hestia)")
    fi
    if [ -d "/usr/local/vesta" ]; then
        panels+=("VestaCP (/usr/local/vesta)")
    fi
    if [ -d "/opt/plesk/php" ] || [ -d "/usr/local/psa" ]; then
        panels+=("Plesk (/opt/plesk/php)")
    fi
    if [ -d "/opt/cpanel" ] || [ -d "/var/cpanel" ]; then
        panels+=("cPanel / EasyApache (/opt/cpanel/ea-php*)")
    fi
    if [ -d "/usr/local/directadmin" ]; then
        panels+=("DirectAdmin (/usr/local/php*)")
    fi
    if [ -d "/usr/local/CyberCP" ]; then
        panels+=("CyberPanel (/usr/local/lsws/lsphp*)")
    fi
    if [ -d "/usr/local/brainycp" ]; then
        panels+=("BrainyCP")
    fi
    if [ -d "/opt/keyhelp" ]; then
        panels+=("KeyHelp (/opt/keyhelp/php)")
    fi
    if [ -d "/opt/remi" ]; then
        panels+=("Remi Repository (/opt/remi/php*)")
    fi

    if [ ${#panels[@]} -eq 0 ]; then
        echo "None (Standard OS / Distribution)"
    else
        local IFS=" + "
        echo "${panels[*]}"
    fi
}

# Verify required tools
if ! command -v strings >/dev/null 2>&1; then
    echo -e "${YELLOW}[!] Warning: 'strings' utility not found. Installing binutils...${NC}"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq binutils >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q binutils >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q binutils >/dev/null 2>&1 || true
    fi
fi

OS_INFO=$(detect_os)
WEB_SERVERS=$(detect_web_server)
CONTROL_PANELS=$(detect_control_panels)

echo -e "${BOLD}${CYAN}============================================================================${NC}"
echo -e "${BOLD}${CYAN}   Universal PHP Security Audit (CVE-2026-109618 / 109619 / 115560)${NC}"
echo -e "${BOLD}${CYAN}   Scanner Version : v${SCRIPT_VERSION} (${SCRIPT_DATE}) | ${REPO_URL}${NC}"
echo -e "${BOLD}${CYAN}============================================================================${NC}"
echo -e "  ${BOLD}OS / Distro    :${NC} ${OS_INFO}"
echo -e "  ${BOLD}Control Panel  :${NC} ${MAGENTA}${BOLD}${CONTROL_PANELS}${NC}"
echo -e "  ${BOLD}Web Server(s)  :${NC} ${WEB_SERVERS}"
echo -e "${BOLD}${CYAN}============================================================================${NC}\n"

# Inspect a single binary and return its protection type:
# Returns via stdout: "0|unpatched" or "1|<patch_description>"
inspect_binary_patch() {
    local bin="$1"
    local major_ver="$2"
    local ver_num="$3"
    local is_cli="${4:-0}"

    local branch
    branch=$(echo "$ver_num" | cut -d'.' -f1,2)

    # 1. Check Official Upstream Releases (8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+, 8.6+)
    if [ "$branch" = "8.2" ] && version_ge "$ver_num" "8.2.35"; then
        echo "1|Official Upstream Release (>= 8.2.35, Soft-OOM)"
        return
    elif [ "$branch" = "8.3" ] && version_ge "$ver_num" "8.3.36"; then
        echo "1|Official Upstream Release (>= 8.3.36, Soft-OOM)"
        return
    elif [ "$branch" = "8.4" ] && version_ge "$ver_num" "8.4.27"; then
        echo "1|Official Upstream Release (>= 8.4.27, Soft-OOM)"
        return
    elif [ "$branch" = "8.5" ] && version_ge "$ver_num" "8.5.12"; then
        echo "1|Official Upstream Release (>= 8.5.12, Soft-OOM)"
        return
    elif version_ge "$branch" "8.6"; then
        echo "1|Official Upstream Release (>= 8.6, Soft-OOM)"
        return
    fi

    # 2. Check PHP 5.x (Zend Engine 2)
    if [ "$major_ver" = "5" ]; then
        if strings "$bin" 2>/dev/null | grep -q "zend_handle_delayed_oom"; then
            echo "1|Full Soft-OOM Patch (avego / Delayed OOM, worker stays alive)"
            return
        elif strings "$bin" 2>/dev/null | grep -q "zend_mm_safe_error_ex"; then
            if strings "$bin" 2>/dev/null | grep -q "incomplete_classes_only"; then
                echo "1|Enhanced Patch (_exit(1) on OOM + incomplete_classes_only)"
            else
                echo "1|Minimal Vendor Patch (_exit(1) on OOM, upload_progress disabled)"
            fi
            return
        fi
        echo "0|Unpatched"
        return
    fi

    # 3. Check PHP 7.x / 8.0 / 8.1 / <8.2.35 (Zend Engine 3/4)
    if { [ "$is_cli" -eq 1 ] && "$bin" -i 2>/dev/null | grep -qi "memory_hard_limit_percent"; } || \
       strings "$bin" 2>/dev/null | grep -q "memory_hard_limit_percent"; then
        echo "1|Full Soft-OOM Patch (avego / PHP 8.2.35 backport, worker stays alive)"
        return
    elif strings "$bin" 2>/dev/null | grep -q "zend_mm_safe_error_ex"; then
        if strings "$bin" 2>/dev/null | grep -q "incomplete_classes_only"; then
            echo "1|Enhanced Patch (_exit(1) on OOM + incomplete_classes_only)"
        else
            echo "1|Minimal Vendor Patch (_exit(1) on OOM, upload_progress disabled)"
        fi
        return
    fi

    echo "0|Unpatched"
}

# Function to audit a single PHP binary set (CLI + CGI + FPM + LSPHP)
audit_php() {
    local label="$1"
    local cli_bin="$2"
    local cgi_bin="${3:-}"
    local fpm_bin="${4:-}"
    local lsphp_bin="${5:-}"

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
    ver_raw=$("$cli_bin" -v 2>/dev/null | head -n 1 || true)
    local ver_num
    ver_num=$(echo "$ver_raw" | grep -oE "PHP [0-9]+\.[0-9]+\.[0-9]+" | awk '{print $2}')
    [ -z "$ver_num" ] && ver_num=$(echo "$ver_raw" | awk '{print $2}')
    [ -z "$ver_num" ] && ver_num="0.0.0"

    local major_ver
    major_ver=$(echo "$ver_num" | cut -d'.' -f1)

    echo -e "${BOLD}▶ Target: ${CYAN}${label}${NC} (${cli_bin})"
    echo -e "  Version        : ${BOLD}${ver_raw}${NC}"

    # Check CLI
    local cli_res cli_protected cli_patch_desc
    cli_res=$(inspect_binary_patch "$cli_bin" "$major_ver" "$ver_num" 1)
    cli_protected=$(echo "$cli_res" | cut -d'|' -f1)
    cli_patch_desc=$(echo "$cli_res" | cut -d'|' -f2)

    # Check CGI
    local cgi_exists=0 cgi_protected=0 cgi_patch_desc=""
    if [ -n "$cgi_bin" ] && [ -x "$cgi_bin" ]; then
        cgi_exists=1
        local cgi_res
        cgi_res=$(inspect_binary_patch "$cgi_bin" "$major_ver" "$ver_num" 0)
        cgi_protected=$(echo "$cgi_res" | cut -d'|' -f1)
        cgi_patch_desc=$(echo "$cgi_res" | cut -d'|' -f2)
    fi

    # Check FPM
    local fpm_exists=0 fpm_protected=0 fpm_patch_desc="" fpm_running=0
    if [ -n "$fpm_bin" ] && [ -x "$fpm_bin" ]; then
        fpm_exists=1
        local fpm_res
        fpm_res=$(inspect_binary_patch "$fpm_bin" "$major_ver" "$ver_num" 0)
        fpm_protected=$(echo "$fpm_res" | cut -d'|' -f1)
        fpm_patch_desc=$(echo "$fpm_res" | cut -d'|' -f2)

        local real_fpm
        real_fpm=$(readlink -f "$fpm_bin" 2>/dev/null || echo "$fpm_bin")
        if ps -eo args 2>/dev/null | grep -v grep | grep -qF "$fpm_bin" || \
           ps -eo args 2>/dev/null | grep -v grep | grep -qF "$real_fpm"; then
            fpm_running=1
        fi
    fi

    # Check LSPHP (if exists and not a symlink to CLI/CGI)
    local lsphp_exists=0 lsphp_protected=0
    if [ -n "$lsphp_bin" ] && [ -x "$lsphp_bin" ]; then
        lsphp_exists=1
        local lsphp_res
        lsphp_res=$(inspect_binary_patch "$lsphp_bin" "$major_ver" "$ver_num" 0)
        lsphp_protected=$(echo "$lsphp_res" | cut -d'|' -f1)
    fi

    # Audit mechanism description
    local check_type=""
    if [ "$major_ver" = "5" ]; then
        check_type="Zend Engine 2 (Delayed OOM / zend_handle_delayed_oom / zend_mm_safe_error_ex)"
    else
        check_type="Zend Engine 3/4 (memory_hard_limit_percent / zend_mm_safe_error_ex)"
    fi
    echo -e "  Audit mechanism: ${check_type}"

    # Check OpenSSL and SSL transports
    local ssl_status="${RED}MISSING (no ssl:// transport)${NC}"
    if "$cli_bin" -r '$t=stream_get_transports(); exit(in_array("ssl", $t) && in_array("tls", $t) ? 0 : 1);' 2>/dev/null; then
        ssl_status="${GREEN}ACTIVE (OpenSSL ssl:// & tls:// available)${NC}"
    fi
    echo -e "  SSL Transports : ${ssl_status}"

    # Check session.upload_progress.enabled in php.ini
    local up_val up_status
    up_val=$("$cli_bin" -r "echo ini_get('session.upload_progress.enabled');" 2>/dev/null || true)
    if [ "$up_val" = "0" ] || [ "$up_val" = "" ] || [ "$up_val" = "Off" ]; then
        up_status="${GREEN}DISABLED in php.ini (Off)${NC}"
    else
        if echo "$cli_patch_desc" | grep -q "Minimal Vendor Patch"; then
            up_status="${YELLOW}HARD-DISABLED in binary (|| 1)${NC}"
        elif echo "$cli_patch_desc" | grep -qE "Full Soft-OOM|Enhanced|Official Upstream"; then
            up_status="${GREEN}ENABLED & ISOLATED (__PHP_Incomplete_Class_Serialized)${NC}"
        else
            up_status="${RED}ENABLED & UNPROTECTED (On)${NC}"
        fi
    fi
    echo -e "  Upload Progress: ${up_status}"

    # Print CLI Status
    if [ "$cli_protected" -eq 1 ]; then
        echo -e "  ├─ CLI (${cli_bin}): ${GREEN}${BOLD}✔ PROTECTED${NC} [${cli_patch_desc}]"
    else
        echo -e "  ├─ CLI (${cli_bin}): ${RED}${BOLD}✘ VULNERABLE${NC}"
    fi

    # Print CGI Status if exists
    if [ "$cgi_exists" -eq 1 ]; then
        if [ "$cgi_protected" -eq 1 ]; then
            echo -e "  ├─ CGI (${cgi_bin}): ${GREEN}${BOLD}✔ PROTECTED${NC} [${cgi_patch_desc}]"
        else
            echo -e "  ├─ CGI (${cgi_bin}): ${RED}${BOLD}✘ VULNERABLE${NC}"
        fi
    fi

    # Print FPM Status if exists
    if [ "$fpm_exists" -eq 1 ]; then
        local fpm_run_tag=""
        [ "$fpm_running" -eq 1 ] && fpm_run_tag=" ${CYAN}(active in memory)${NC}"
        if [ "$fpm_protected" -eq 1 ]; then
            echo -e "  ├─ FPM (${fpm_bin}): ${GREEN}${BOLD}✔ PROTECTED${NC} [${fpm_patch_desc}]${fpm_run_tag}"
        else
            echo -e "  ├─ FPM (${fpm_bin}): ${RED}${BOLD}✘ VULNERABLE${NC}${fpm_run_tag}"
        fi
    fi

    # Print LSPHP Status if exists
    if [ "$lsphp_exists" -eq 1 ]; then
        if [ "$lsphp_protected" -eq 1 ]; then
            echo -e "  ├─ LSI (${lsphp_bin}): ${GREEN}${BOLD}✔ PROTECTED${NC}"
        else
            echo -e "  ├─ LSI (${lsphp_bin}): ${RED}${BOLD}✘ VULNERABLE${NC}"
        fi
    fi

    # Overall verdict: require ALL primary SAPI binaries (CLI, CGI, FPM) to be protected
    local all_protected=1
    [ "$cli_protected" -eq 0 ] && all_protected=0
    [ "$cgi_exists" -eq 1 ] && [ "$cgi_protected" -eq 0 ] && all_protected=0
    [ "$fpm_exists" -eq 1 ] && [ "$fpm_protected" -eq 0 ] && all_protected=0

    if [ "$all_protected" -eq 1 ]; then
        echo -e "  └─ Verdict: ${GREEN}${BOLD}[SAFE / PATCHED]${NC}\n"
        TOTAL_PROTECTED=$((TOTAL_PROTECTED + 1))
    else
        echo -e "  └─ Verdict: ${RED}${BOLD}[DANGER / ACTION REQUIRED]${NC}\n"
        TOTAL_VULNERABLE=$((TOTAL_VULNERABLE + 1))
    fi
}

# ==============================================================================
# Discovery & Audit Across All Panels and System Paths
# ==============================================================================

# 1. FastPanel / ISPmanager (/opt/php* and /opt/fphp*)
for php_dir in /opt/php[0-9]* /opt/fphp*; do
    if [ -d "$php_dir" ]; then
        label=$(basename "$php_dir")
        panel_prefix="FastPanel"
        [ -d "/usr/local/mgr5" ] && [ ! -d "/usr/share/fastpanel2" ] && panel_prefix="ISPmanager"
        audit_php "${panel_prefix} ${label}" \
            "${php_dir}/bin/php" \
            "${php_dir}/bin/php-cgi" \
            "${php_dir}/sbin/php-fpm" \
            "${php_dir}/bin/lsphp"
    fi
done

# 2. aaPanel / Baota Panel (/www/server/php/*)
if [ -d "/www/server/php" ]; then
    for php_dir in /www/server/php/*; do
        if [ -d "$php_dir" ] && [ -x "${php_dir}/bin/php" ]; then
            label=$(basename "$php_dir")
            audit_php "aaPanel/Baota PHP ${label}" \
                "${php_dir}/bin/php" \
                "${php_dir}/bin/php-cgi" \
                "${php_dir}/sbin/php-fpm" \
                "${php_dir}/bin/lsphp"
        fi
    done
fi

# 3. Plesk (/opt/plesk/php/*)
if [ -d "/opt/plesk/php" ]; then
    for php_dir in /opt/plesk/php/*; do
        if [ -d "$php_dir" ] && [ -x "${php_dir}/bin/php" ]; then
            label=$(basename "$php_dir")
            audit_php "Plesk PHP ${label}" \
                "${php_dir}/bin/php" \
                "${php_dir}/bin/php-cgi" \
                "${php_dir}/sbin/php-fpm" \
                ""
        fi
    done
fi

# 4. cPanel / EasyApache 4 (/opt/cpanel/ea-php*)
if [ -d "/opt/cpanel" ]; then
    for php_dir in /opt/cpanel/ea-php*; do
        if [ -d "$php_dir" ] && [ -x "${php_dir}/root/usr/bin/php" ]; then
            label=$(basename "$php_dir")
            audit_php "cPanel ${label}" \
                "${php_dir}/root/usr/bin/php" \
                "${php_dir}/root/usr/bin/php-cgi" \
                "${php_dir}/root/usr/sbin/php-fpm" \
                "${php_dir}/root/usr/bin/lsphp"
        fi
    done
fi

# 5. Remi Repository SCL (/opt/remi/php*)
if [ -d "/opt/remi" ]; then
    for php_dir in /opt/remi/php*; do
        if [ -d "$php_dir" ] && [ -x "${php_dir}/root/usr/bin/php" ]; then
            label=$(basename "$php_dir")
            audit_php "Remi SCL ${label}" \
                "${php_dir}/root/usr/bin/php" \
                "${php_dir}/root/usr/bin/php-cgi" \
                "${php_dir}/root/usr/sbin/php-fpm" \
                ""
        fi
    done
fi

# 6. DirectAdmin (/usr/local/php*)
for php_dir in /usr/local/php[0-9]*; do
    if [ -d "$php_dir" ] && [ -x "${php_dir}/bin/php" ]; then
        label=$(basename "$php_dir")
        audit_php "DirectAdmin ${label}" \
            "${php_dir}/bin/php" \
            "${php_dir}/bin/php-cgi" \
            "${php_dir}/sbin/php-fpm" \
            "${php_dir}/bin/lsphp"
    fi
done

# 7. CyberPanel / OpenLiteSpeed (/usr/local/lsws/lsphp*)
if [ -d "/usr/local/lsws" ]; then
    for php_dir in /usr/local/lsws/lsphp*; do
        if [ -d "$php_dir" ] && [ -x "${php_dir}/bin/php" ]; then
            label=$(basename "$php_dir")
            audit_php "OpenLiteSpeed/CyberPanel ${label}" \
                "${php_dir}/bin/php" \
                "" \
                "" \
                "${php_dir}/bin/lsphp"
        fi
    done
fi

# 8. KeyHelp (/opt/keyhelp/php/*)
if [ -d "/opt/keyhelp/php" ]; then
    for php_dir in /opt/keyhelp/php/*; do
        if [ -d "$php_dir" ] && [ -x "${php_dir}/bin/php" ]; then
            label=$(basename "$php_dir")
            audit_php "KeyHelp PHP ${label}" \
                "${php_dir}/bin/php" \
                "${php_dir}/bin/php-cgi" \
                "${php_dir}/sbin/php-fpm" \
                ""
        fi
    done
fi

# 9. Debian / Ubuntu / HestiaCP / VestaCP Versioned System PHP (/usr/bin/php5.*, /usr/bin/php7.*, /usr/bin/php8.*)
for sys_ver in /usr/bin/php[578].[0-9]*; do
    if [ -x "$sys_ver" ]; then
        v_suffix=$(basename "$sys_ver" | sed 's/^php//')
        cli_bin="$sys_ver"
        cgi_bin="/usr/bin/php-cgi${v_suffix}"
        fpm_bin="/usr/sbin/php-fpm${v_suffix}"
        audit_php "System / Sury PHP ${v_suffix}" "$cli_bin" "$cgi_bin" "$fpm_bin" ""
    fi
done

# 10. Default System PHP (/usr/bin/php, /usr/local/bin/php)
if [ -x "/usr/bin/php" ]; then
    audit_php "Default System PHP" "/usr/bin/php" "/usr/bin/php-cgi" "/usr/sbin/php-fpm" ""
fi
if [ -x "/usr/local/bin/php" ]; then
    audit_php "Local System PHP (/usr/local)" "/usr/local/bin/php" "/usr/local/bin/php-cgi" "/usr/local/sbin/php-fpm" ""
fi

# Summary
echo -e "${BOLD}${CYAN}============================================================================${NC}"
echo -e "${BOLD}SUMMARY REPORT:${NC}"
echo -e "  Control Panel(s)       : ${MAGENTA}${BOLD}${CONTROL_PANELS}${NC}"
echo -e "  Total PHP installations: ${BOLD}${TOTAL_CHECKED}${NC}"
echo -e "  Protected (Patched)    : ${GREEN}${BOLD}${TOTAL_PROTECTED}${NC}"
if [ "$TOTAL_VULNERABLE" -gt 0 ]; then
    echo -e "  Vulnerable (Unpatched) : ${RED}${BOLD}${TOTAL_VULNERABLE}${NC}"
    echo -e "${BOLD}${CYAN}============================================================================${NC}"
    echo -e "${RED}${BOLD}[!] ATTENTION: One or more PHP installations require patching!${NC}"
    echo -e "Refer to manuals & patches at: ${BOLD}${REPO_URL}${NC}"
    echo -e "${BOLD}${CYAN}============================================================================${NC}"
    exit 1
else
    echo -e "  Vulnerable (Unpatched) : ${GREEN}${BOLD}0${NC}"
    echo -e "${BOLD}${CYAN}============================================================================${NC}"
    echo -e "${GREEN}${BOLD}[✔] EXCELLENT: All detected PHP versions are fully protected!${NC}"
    echo -e "${BOLD}${CYAN}============================================================================${NC}"
    exit 0
fi
