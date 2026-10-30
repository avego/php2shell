#!/usr/bin/env bash
# ==============================================================================
# Universal Hosting Control Panel & System PHP Security Audit Script
# Version: 1.3 (Updated: 2026-10-30) — strictly READ-ONLY (zero disk writes)
# Checks PHP installations against CVE-2026-109618, CVE-2026-109619 & CVE-2026-115560
# + Audits surviving session gaps (Zero 1: upload_progress + serialize_handler)
# Supports:
#   - Local Audit: FastPanel, ISPmanager, aaPanel/Baota, HestiaCP, VestaCP, Plesk,
#                  cPanel/EasyApache, CloudLinux alt-php, DirectAdmin, CyberPanel/OLS,
#                  BrainyCP, KeyHelp, Remi/RHSCL, and Debian/Ubuntu/RHEL/Alpine/Arch PHP
#   - Remote Audit: --url <https://example.com> (in-memory HTTP header & multipart probe)
#   - CI/CD Output: --json (structured JSON output)
#   - Deep Scan   : --all (filesystem search for custom PHP builds)
# ==============================================================================

set -u

SCRIPT_VERSION="1.3"
SCRIPT_DATE="2026-10-30"
REPO_URL="https://github.com/avego/php2shell"

# CLI Options (strictly read-only)
OPT_JSON=0
OPT_ALL=0
OPT_QUIET=0
OPT_URL=""

show_help() {
    cat <<EOF
Universal PHP2Shell Security Auditor v${SCRIPT_VERSION} (${SCRIPT_DATE}) [READ-ONLY]
Repository: ${REPO_URL}

Usage:
  bash check_php_cve.sh [OPTIONS]
  curl -sSL "https://raw.githubusercontent.com/avego/php2shell/main/check_php_cve.sh" | bash -s -- [OPTIONS]

Options:
  -u, --url <URL>     Run non-destructive in-memory remote HTTP/HTTPS probe against a URL
  -j, --json          Output results in machine-readable JSON format (for CI/CD & monitoring)
  -a, --all           Deep filesystem scan for custom compiled PHP binaries (/usr, /opt, /www, /home)
  -q, --quiet         Suppress banner and informational headers
  -h, --help          Show this help message

Exit Codes:
  0 - All detected PHP installations are PATCHED (or remote target is safe)
  1 - One or more PHP installations are VULNERABLE (unpatched allocator)
  2 - Partially patched or only INI-mitigated installations detected
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -u|--url)
            shift
            OPT_URL="${1:-}"
            ;;
        --url=*)
            OPT_URL="${1#*=}"
            ;;
        -j|--json)
            OPT_JSON=1
            ;;
        -a|--all)
            OPT_ALL=1
            ;;
        -q|--quiet)
            OPT_QUIET=1
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1 (use --help for usage)" >&2
            exit 1
            ;;
    esac
    shift
done

# Colors for terminal output (disabled in JSON mode or non-TTY)
if [ "$OPT_JSON" -eq 1 ] || [ -n "${NO_COLOR:-}" ]; then
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' MAGENTA='' BOLD='' NC=''
else
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    MAGENTA='\033[0;35m'
    BOLD='\033[1m'
    NC='\033[0m'
fi

TOTAL_CHECKED=0
TOTAL_PROTECTED=0
TOTAL_PARTIAL=0
TOTAL_MITIGATED=0
TOTAL_VULNERABLE=0
PROCESSED_PATHS=()
JSON_ITEMS=()

json_escape() {
    local s="${1:-}"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

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

# Pure read-only binary string matcher (works with 'strings' or fallback 'grep -a')
bin_has_string() {
    local bin="$1"
    local pattern="$2"
    if command -v strings >/dev/null 2>&1; then
        strings "$bin" 2>/dev/null | grep -qE "$pattern"
    else
        grep -a -qE "$pattern" "$bin" 2>/dev/null
    fi
}

extract_bin_patch_sigs() {
    local bin="$1"
    local pattern="zend_handle_delayed_oom|memory_hard_limit_percent|zend_mm_safe_error_ex|incomplete_classes_only|__PHP_Incomplete_Class_Serialized|_array_init_singleton|zend_new_array_singleton|php_basic_early_rinit"
    if command -v strings >/dev/null 2>&1; then
        strings "$bin" 2>/dev/null | grep -E "$pattern" || true
    else
        grep -a -oE "$pattern" "$bin" 2>/dev/null || true
    fi
}

# ==============================================================================
# Remote Non-Destructive In-Memory Web Audit (--url) — ZERO temporary files
# ==============================================================================
run_remote_audit() {
    local target_url="$1"
    if ! command -v curl >/dev/null 2>&1; then
        if [ "$OPT_JSON" -eq 1 ]; then
            printf '{"error":"curl is required for --url remote audit"}\n'
        else
            echo -e "${RED}[!] Error: 'curl' is required for remote auditing.${NC}"
        fi
        exit 1
    fi

    local boundary="----Php2ShellAudit$$"

    # Capture response headers in memory (no temp files on disk)
    local get_resp http_code hdr_get
    get_resp=$(curl -k -sS -L --max-time 15 -D - -o /dev/null -w "\n__HTTP_CODE__:%{http_code}" "$target_url" 2>/dev/null || echo "__HTTP_CODE__:000")
    http_code=$(echo "$get_resp" | grep "^__HTTP_CODE__:" | tail -n 1 | cut -d':' -f2)
    hdr_get=$(echo "$get_resp" | grep -v "^__HTTP_CODE__:")

    if [ -z "$http_code" ] || [ "$http_code" = "000" ]; then
        if [ "$OPT_JSON" -eq 1 ]; then
            printf '{"target":"%s","status":"ERROR","details":"Connection failed"}\n' "$(json_escape "$target_url")"
        else
            echo -e "${RED}[!] Failed to connect to ${target_url}${NC}"
        fi
        exit 1
    fi

    local server_hdr powered_by waf_detected="None"
    server_hdr=$(echo "$hdr_get" | grep -i "^server:" | tail -n 1 | cut -d':' -f2- | sed 's/^[[:space:]]*//' | tr -d '\r\n')
    powered_by=$(echo "$hdr_get" | grep -i "^x-powered-by:" | tail -n 1 | cut -d':' -f2- | sed 's/^[[:space:]]*//' | tr -d '\r\n')

    if echo "$hdr_get" | grep -qi "cloudflare"; then
        waf_detected="Cloudflare"
    elif echo "$hdr_get" | grep -qi "x-sucuri-id"; then
        waf_detected="Sucuri WAF"
    elif echo "$hdr_get" | grep -qi "x-amz-cf-id"; then
        waf_detected="AWS CloudFront"
    elif echo "$hdr_get" | grep -qi "ddos-guard"; then
        waf_detected="DDoS-Guard"
    fi

    # Send safe 200-byte multipart probe in memory via stdin pipe
    local post_code
    post_code=$(printf -- '--%s\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nprobe\r\n--%s\r\nContent-Disposition: form-data; name="file"; filename="p.txt"\r\nContent-Type: text/plain\r\n\r\n1\r\n--%s--\r\n' "$boundary" "$boundary" "$boundary" | \
        curl -k -sS -L --max-time 15 -X POST \
             -H "Content-Type: multipart/form-data; boundary=${boundary}" \
             -H "Cookie: PHPSESSID=p2saudit$$" \
             --data-binary @- \
             -o /dev/null -w "%{http_code}" "$target_url" 2>/dev/null || echo "000")

    local exposed_ver=""
    if [ -n "$powered_by" ]; then
        exposed_ver=$(echo "$powered_by" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -n 1 || true)
    fi
    if [ -z "$exposed_ver" ] && [ -n "$server_hdr" ]; then
        exposed_ver=$(echo "$server_hdr" | grep -oE "PHP/[0-9]+\.[0-9]+\.[0-9]+" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -n 1 || true)
    fi

    local remote_verdict="INCONCLUSIVE (Headers hidden; run local binary scan on server)"
    local exit_code=0

    if [ "$post_code" = "403" ] || [ "$post_code" = "406" ]; then
        remote_verdict="WAF_FILTERED (Multipart upload_progress probe blocked with HTTP ${post_code})"
    elif [ -n "$exposed_ver" ]; then
        local r_branch
        r_branch=$(echo "$exposed_ver" | cut -d'.' -f1,2)
        if { [ "$r_branch" = "8.2" ] && version_ge "$exposed_ver" "8.2.35"; } || \
           { [ "$r_branch" = "8.3" ] && version_ge "$exposed_ver" "8.3.36"; } || \
           { [ "$r_branch" = "8.4" ] && version_ge "$exposed_ver" "8.4.27"; } || \
           { [ "$r_branch" = "8.5" ] && version_ge "$exposed_ver" "8.5.12"; } || \
           version_ge "$r_branch" "8.6"; then
            remote_verdict="SAFE_UPSTREAM (PHP ${exposed_ver} includes official Soft-OOM patch)"
            exit_code=0
        else
            remote_verdict="POTENTIALLY_VULNERABLE_VERSION (PHP ${exposed_ver} requires backport verification via local CLI)"
            exit_code=2
        fi
    fi

    if [ "$OPT_JSON" -eq 1 ]; then
        printf '{"mode":"remote","target":"%s","http_get":%s,"http_post":%s,"server":"%s","x_powered_by":"%s","exposed_php_version":"%s","waf":"%s","verdict":"%s"}\n' \
            "$(json_escape "$target_url")" \
            "$http_code" \
            "$post_code" \
            "$(json_escape "${server_hdr:-hidden}")" \
            "$(json_escape "${powered_by:-hidden}")" \
            "$(json_escape "${exposed_ver:-unknown}")" \
            "$(json_escape "$waf_detected")" \
            "$(json_escape "$remote_verdict")"
    else
        echo -e "${BOLD}${CYAN}============================================================================${NC}"
        echo -e "${BOLD}${CYAN}   Remote PHP2Shell HTTP/HTTPS Probe (v${SCRIPT_VERSION}) [READ-ONLY]${NC}"
        echo -e "${BOLD}${CYAN}============================================================================${NC}"
        echo -e "  ${BOLD}Target URL     :${NC} ${target_url}"
        echo -e "  ${BOLD}HTTP Status    :${NC} GET=${http_code}, Multipart POST=${post_code}"
        echo -e "  ${BOLD}Server Header  :${NC} ${server_hdr:-<not disclosed>}"
        echo -e "  ${BOLD}X-Powered-By   :${NC} ${powered_by:-<not disclosed>}"
        echo -e "  ${BOLD}WAF / CDN      :${NC} ${waf_detected}"
        echo -e "  ${BOLD}Verdict        :${NC} ${YELLOW}${BOLD}${remote_verdict}${NC}"
        echo -e "${BOLD}${CYAN}============================================================================${NC}"
        echo -e "  Note: Backported patches in PHP 5.2-8.1 cannot be verified over HTTP alone"
        echo -e "        because version headers stay identical (e.g. 5.6.40 / 7.4.33)."
        echo -e "        Run this script locally on the server to inspect ELF binaries."
        echo -e "${BOLD}${CYAN}============================================================================${NC}"
    fi
    exit "$exit_code"
}

if [ -n "$OPT_URL" ]; then
    run_remote_audit "$OPT_URL"
fi

# Detect OS / Distribution
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "${PRETTY_NAME:-${NAME:-Linux} ${VERSION_ID:-}}"
    elif [ -f /etc/redhat-release ]; then
        cat /etc/redhat-release
    elif [ -f /etc/debian_version ]; then
        echo "Debian $(cat /etc/debian_version)"
    else
        uname -srm
    fi
}

# Detect active web servers
detect_web_server() {
    local servers=()
    if command -v pgrep >/dev/null 2>&1; then
        if pgrep -x "nginx" >/dev/null 2>&1; then
            local ng_ver
            ng_ver=$(nginx -v 2>&1 | awk -F'/' '{print $2}' | awk '{print $1}' || true)
            servers+=("Nginx${ng_ver:+ ($ng_ver)}")
        fi
        if pgrep -x "apache2" >/dev/null 2>&1 || pgrep -x "httpd" >/dev/null 2>&1; then
            servers+=("Apache/httpd")
        fi
        if pgrep -x "litespeed" >/dev/null 2>&1 || pgrep -x "openlitespeed" >/dev/null 2>&1 || pgrep -f "lshttpd" >/dev/null 2>&1; then
            servers+=("LiteSpeed/OpenLiteSpeed")
        fi
        if pgrep -x "caddy" >/dev/null 2>&1; then
            servers+=("Caddy")
        fi
    else
        local ps_out
        ps_out=$(ps -eo comm 2>/dev/null || true)
        echo "$ps_out" | grep -qx "nginx" && servers+=("Nginx")
        echo "$ps_out" | grep -qE "^(apache2|httpd)$" && servers+=("Apache/httpd")
        echo "$ps_out" | grep -qE "^(litespeed|openlitespeed|lshttpd)$" && servers+=("LiteSpeed/OpenLiteSpeed")
        echo "$ps_out" | grep -qx "caddy" && servers+=("Caddy")
    fi
    if [ ${#servers[@]} -eq 0 ]; then
        echo "None detected in memory"
    else
        local out="" s
        for s in "${servers[@]}"; do
            [ -n "$out" ] && out="${out}, "
            out="${out}${s}"
        done
        echo "$out"
    fi
}

# Detect installed hosting control panels
detect_control_panels() {
    local panels=()
    if [ -d "/usr/share/fastpanel2" ] || [ -d "/opt/fphp" ] || \
       { command -v dpkg >/dev/null 2>&1 && dpkg -l fastpanel2 >/dev/null 2>&1; } || \
       { command -v rpm >/dev/null 2>&1 && rpm -q fastpanel2 >/dev/null 2>&1; }; then
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
    if [ -d "/opt/alt" ]; then
        panels+=("CloudLinux alt-php (/opt/alt/php*)")
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
    if [ -d "/opt/remi" ] || [ -d "/opt/rh" ]; then
        panels+=("Remi / RedHat SCL (/opt/remi/php*, /opt/rh/rh-php*)")
    fi

    if [ ${#panels[@]} -eq 0 ]; then
        echo "None (Standard OS / Distribution)"
    else
        local IFS=" + "
        echo "${panels[*]}"
    fi
}

OS_INFO=$(detect_os)
WEB_SERVERS=$(detect_web_server)
CONTROL_PANELS=$(detect_control_panels)

if [ "$OPT_JSON" -eq 0 ] && [ "$OPT_QUIET" -eq 0 ]; then
    echo -e "${BOLD}${CYAN}============================================================================${NC}"
    echo -e "${BOLD}${CYAN}   Universal PHP Security Audit (CVE-2026-109618 / 109619 / 115560)${NC}"
    echo -e "${BOLD}${CYAN}   Scanner Version : v${SCRIPT_VERSION} (${SCRIPT_DATE}) [READ-ONLY] | ${REPO_URL}${NC}"
    echo -e "${BOLD}${CYAN}============================================================================${NC}"
    echo -e "  ${BOLD}OS / Distro    :${NC} ${OS_INFO}"
    echo -e "  ${BOLD}Control Panel  :${NC} ${MAGENTA}${BOLD}${CONTROL_PANELS}${NC}"
    echo -e "  ${BOLD}Web Server(s)  :${NC} ${WEB_SERVERS}"
    echo -e "${BOLD}${CYAN}============================================================================${NC}\n"
fi

# Inspect a single binary and return its protection type:
# Returns via stdout:
#   "2|<patch_description>" -> Fully or minimally patched allocator (CVE-2026-109618/19 fixed)
#   "1|<patch_description>" -> Partial patch (only session isolation or only rfc1867 without allocator)
#   "0|Unpatched"           -> Unpatched binary
inspect_binary_patch() {
    local bin="$1"
    local major_ver="$2"
    local ver_num="$3"
    local is_cli="${4:-0}"

    local branch
    branch=$(echo "$ver_num" | cut -d'.' -f1,2)

    # 1. Check Official Upstream Releases (8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+, 8.6+)
    if [ "$branch" = "8.2" ] && version_ge "$ver_num" "8.2.35"; then
        echo "2|Official Upstream Release (>= 8.2.35, Soft-OOM)"
        return
    elif [ "$branch" = "8.3" ] && version_ge "$ver_num" "8.3.36"; then
        echo "2|Official Upstream Release (>= 8.3.36, Soft-OOM)"
        return
    elif [ "$branch" = "8.4" ] && version_ge "$ver_num" "8.4.27"; then
        echo "2|Official Upstream Release (>= 8.4.27, Soft-OOM)"
        return
    elif [ "$branch" = "8.5" ] && version_ge "$ver_num" "8.5.12"; then
        echo "2|Official Upstream Release (>= 8.5.12, Soft-OOM)"
        return
    elif version_ge "$branch" "8.6"; then
        echo "2|Official Upstream Release (>= 8.6, Soft-OOM)"
        return
    fi

    # Extract relevant 2026 patch symbols in a single read-only pass
    local sigs
    sigs=$(extract_bin_patch_sigs "$bin")

    local has_delayed_oom=0
    local has_hard_limit=0
    local has_safe_error_ex=0
    local has_incomplete_only=0
    local has_singleton=0

    echo "$sigs" | grep -q "zend_handle_delayed_oom" && has_delayed_oom=1
    echo "$sigs" | grep -q "memory_hard_limit_percent" && has_hard_limit=1
    if [ "$has_hard_limit" -eq 0 ] && [ "$is_cli" -eq 1 ] && [ "$major_ver" != "5" ]; then
        "$bin" -i 2>/dev/null | grep -qi "memory_hard_limit_percent" && has_hard_limit=1
    fi
    echo "$sigs" | grep -q "zend_mm_safe_error_ex" && has_safe_error_ex=1
    echo "$sigs" | grep -qE "incomplete_classes_only|__PHP_Incomplete_Class_Serialized" && has_incomplete_only=1
    echo "$sigs" | grep -qE "_array_init_singleton|zend_new_array_singleton" && has_singleton=1

    # 2. Check PHP 5.x (Zend Engine 2)
    if [ "$major_ver" = "5" ]; then
        if [ "$has_delayed_oom" -eq 1 ]; then
            echo "2|Full Soft-OOM Patch (avego / Delayed OOM, worker stays alive)"
            return
        elif [ "$has_safe_error_ex" -eq 1 ]; then
            if [ "$has_incomplete_only" -eq 1 ]; then
                echo "2|Enhanced Patch (_exit(1) on OOM + incomplete_classes_only)"
            else
                echo "2|Minimal Vendor Patch (_exit(1) on OOM, upload_progress disabled)"
            fi
            return
        elif [ "$has_incomplete_only" -eq 1 ] || [ "$has_singleton" -eq 1 ]; then
            echo "1|Partial Patch (rfc1867/session touched, but ZendMM allocator is UNPATCHED)"
            return
        fi
        echo "0|Unpatched"
        return
    fi

    # 3. Check PHP 7.x / 8.0 / 8.1 / <8.2.35 (Zend Engine 3/4)
    if [ "$has_hard_limit" -eq 1 ]; then
        echo "2|Full Soft-OOM Patch (avego / PHP 8.2.35 backport, worker stays alive)"
        return
    elif [ "$has_safe_error_ex" -eq 1 ]; then
        if [ "$has_incomplete_only" -eq 1 ]; then
            echo "2|Enhanced Patch (_exit(1) on OOM + incomplete_classes_only)"
        else
            echo "2|Minimal Vendor Patch (_exit(1) on OOM, upload_progress disabled)"
        fi
        return
    elif [ "$has_incomplete_only" -eq 1 ] || [ "$has_singleton" -eq 1 ]; then
        echo "1|Partial Patch (rfc1867/session touched, but ZendMM allocator is UNPATCHED)"
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

    local major_ver minor_ver branch
    major_ver=$(echo "$ver_num" | cut -d'.' -f1)
    minor_ver=$(echo "$ver_num" | cut -d'.' -f2)
    branch="${major_ver}.${minor_ver}"

    # Check CLI
    local cli_res cli_state cli_patch_desc
    cli_res=$(inspect_binary_patch "$cli_bin" "$major_ver" "$ver_num" 1)
    cli_state=$(echo "$cli_res" | cut -d'|' -f1)
    cli_patch_desc=$(echo "$cli_res" | cut -d'|' -f2)

    # Check CGI
    local cgi_exists=0 cgi_state=0 cgi_patch_desc=""
    if [ -n "$cgi_bin" ] && [ -x "$cgi_bin" ]; then
        cgi_exists=1
        local cgi_res
        cgi_res=$(inspect_binary_patch "$cgi_bin" "$major_ver" "$ver_num" 0)
        cgi_state=$(echo "$cgi_res" | cut -d'|' -f1)
        cgi_patch_desc=$(echo "$cgi_res" | cut -d'|' -f2)
    fi

    # Check FPM
    local fpm_exists=0 fpm_state=0 fpm_patch_desc="" fpm_running=0
    if [ -n "$fpm_bin" ] && [ -x "$fpm_bin" ]; then
        fpm_exists=1
        local fpm_res
        fpm_res=$(inspect_binary_patch "$fpm_bin" "$major_ver" "$ver_num" 0)
        fpm_state=$(echo "$fpm_res" | cut -d'|' -f1)
        fpm_patch_desc=$(echo "$fpm_res" | cut -d'|' -f2)

        local real_fpm
        real_fpm=$(readlink -f "$fpm_bin" 2>/dev/null || echo "$fpm_bin")
        if ps -eo args 2>/dev/null | grep -v grep | grep -qF "$fpm_bin" || \
           ps -eo args 2>/dev/null | grep -v grep | grep -qF "$real_fpm"; then
            fpm_running=1
        fi
    fi

    # Check LSPHP
    local lsphp_exists=0 lsphp_state=0 lsphp_patch_desc=""
    if [ -n "$lsphp_bin" ] && [ -x "$lsphp_bin" ]; then
        lsphp_exists=1
        local lsphp_res
        lsphp_res=$(inspect_binary_patch "$lsphp_bin" "$major_ver" "$ver_num" 0)
        lsphp_state=$(echo "$lsphp_res" | cut -d'|' -f1)
        lsphp_patch_desc=$(echo "$lsphp_res" | cut -d'|' -f2)
    fi

    # Check OpenSSL and SSL transports
    local ssl_ok=0 ssl_status="${RED}MISSING (no ssl:// transport)${NC}"
    if "$cli_bin" -r '$t=stream_get_transports(); exit(in_array("ssl", $t) && in_array("tls", $t) ? 0 : 1);' 2>/dev/null; then
        ssl_ok=1
        ssl_status="${GREEN}ACTIVE (OpenSSL ssl:// & tls:// available)${NC}"
    fi

    # Check session.upload_progress.enabled and session.serialize_handler (Zero 1 audit)
    local up_val ser_handler loaded_ini
    up_val=$("$cli_bin" -r "echo ini_get('session.upload_progress.enabled');" 2>/dev/null || true)
    ser_handler=$("$cli_bin" -r "echo ini_get('session.serialize_handler');" 2>/dev/null || true)
    loaded_ini=$("$cli_bin" -r "echo php_ini_loaded_file();" 2>/dev/null || true)

    local up_status up_json_state
    local bin_has_cancel=1
    if ! bin_has_string "$cli_bin" "cancel_upload"; then
        bin_has_cancel=0
    fi

    if [ "$branch" = "5.2" ] || [ "$branch" = "5.3" ]; then
        up_status="${GREEN}N/A in PHP ${branch} (upload_progress introduced in 5.4; CVE-2026-109618/19 still apply!)${NC}"
        up_json_state="not_applicable_php52_53"
    elif [ "$bin_has_cancel" -eq 0 ] && echo "$cli_patch_desc" | grep -q "Minimal Vendor Patch"; then
        up_status="${YELLOW}HARD-DISABLED in binary (dead-code eliminated via || 1)${NC}"
        up_json_state="hard_disabled_in_binary"
    elif [ "$up_val" = "0" ] || [ "$up_val" = "" ] || [ "$up_val" = "Off" ]; then
        up_status="${GREEN}DISABLED in php.ini (mitigates CVE-2026-115560 & Zero-1 session gaps)${NC}"
        up_json_state="disabled_in_ini"
    else
        if echo "$cli_patch_desc" | grep -qE "Full Soft-OOM|Enhanced|Official Upstream"; then
            up_status="${GREEN}ENABLED & ISOLATED (__PHP_Incomplete_Class_Serialized; handler=${ser_handler:-php})${NC}"
            up_json_state="enabled_and_isolated"
        else
            up_status="${RED}ENABLED & UNPROTECTED (On; handler=${ser_handler:-php})${NC}"
            up_json_state="enabled_unprotected"
        fi
    fi

    # Determine overall verdict across CLI, CGI, FPM
    local min_state="$cli_state"
    [ "$cgi_exists" -eq 1 ] && [ "$cgi_state" -lt "$min_state" ] && min_state="$cgi_state"
    [ "$fpm_exists" -eq 1 ] && [ "$fpm_state" -lt "$min_state" ] && min_state="$fpm_state"

    local verdict_code="VULNERABLE"
    local verdict_display=""

    if [ "$min_state" -eq 2 ]; then
        verdict_code="PATCHED"
        verdict_display="${GREEN}${BOLD}[SAFE / PATCHED]${NC}"
        TOTAL_PROTECTED=$((TOTAL_PROTECTED + 1))
    elif [ "$min_state" -eq 1 ]; then
        verdict_code="PARTIAL_PATCH"
        verdict_display="${YELLOW}${BOLD}[PARTIAL PATCH — ALLOCATOR STILL VULNERABLE]${NC}"
        TOTAL_PARTIAL=$((TOTAL_PARTIAL + 1))
        TOTAL_VULNERABLE=$((TOTAL_VULNERABLE + 1))
    else
        if [ "$up_json_state" = "disabled_in_ini" ]; then
            verdict_code="VULNERABLE_INI_MITIGATED"
            verdict_display="${RED}${BOLD}[UNPATCHED BINARY]${NC} ${YELLOW}(CVE-2026-115560 mitigated via php.ini, but CVE-2026-109618/19 OOM still vulnerable!)${NC}"
            TOTAL_MITIGATED=$((TOTAL_MITIGATED + 1))
            TOTAL_VULNERABLE=$((TOTAL_VULNERABLE + 1))
        else
            verdict_code="VULNERABLE"
            verdict_display="${RED}${BOLD}[DANGER / ACTION REQUIRED]${NC}"
            TOTAL_VULNERABLE=$((TOTAL_VULNERABLE + 1))
        fi
    fi

    if [ "$OPT_JSON" -eq 1 ]; then
        local item_json
        item_json=$(printf '{"label":"%s","version":"%s","cli_path":"%s","cli_patch":"%s","fpm_path":"%s","fpm_running":%s,"ssl_active":%s,"upload_progress":"%s","serialize_handler":"%s","php_ini":"%s","verdict":"%s"}' \
            "$(json_escape "$label")" \
            "$(json_escape "$ver_num")" \
            "$(json_escape "$cli_bin")" \
            "$(json_escape "$cli_patch_desc")" \
            "$(json_escape "${fpm_bin:-}")" \
            "$([ "$fpm_running" -eq 1 ] && echo "true" || echo "false")" \
            "$([ "$ssl_ok" -eq 1 ] && echo "true" || echo "false")" \
            "$(json_escape "$up_json_state")" \
            "$(json_escape "${ser_handler:-php}")" \
            "$(json_escape "${loaded_ini:-none}")" \
            "$(json_escape "$verdict_code")")
        JSON_ITEMS+=("$item_json")
        return
    fi

    echo -e "${BOLD}▶ Target: ${CYAN}${label}${NC} (${cli_bin})"
    echo -e "  Version        : ${BOLD}${ver_raw}${NC}"

    local check_type=""
    if [ "$major_ver" = "5" ]; then
        check_type="Zend Engine 2 (Delayed OOM / zend_handle_delayed_oom / zend_mm_safe_error_ex)"
    else
        check_type="Zend Engine 3/4 (memory_hard_limit_percent / zend_mm_safe_error_ex)"
    fi
    echo -e "  Audit mechanism: ${check_type}"
    echo -e "  SSL Transports : ${ssl_status}"
    echo -e "  Upload Progress: ${up_status}"

    # Print CLI Status
    if [ "$cli_state" -eq 2 ]; then
        echo -e "  ├─ CLI (${cli_bin}): ${GREEN}${BOLD}✔ PROTECTED${NC} [${cli_patch_desc}]"
    elif [ "$cli_state" -eq 1 ]; then
        echo -e "  ├─ CLI (${cli_bin}): ${YELLOW}${BOLD}⚠ PARTIAL${NC} [${cli_patch_desc}]"
    else
        echo -e "  ├─ CLI (${cli_bin}): ${RED}${BOLD}✘ VULNERABLE${NC}"
    fi

    # Print CGI Status if exists
    if [ "$cgi_exists" -eq 1 ]; then
        if [ "$cgi_state" -eq 2 ]; then
            echo -e "  ├─ CGI (${cgi_bin}): ${GREEN}${BOLD}✔ PROTECTED${NC} [${cgi_patch_desc}]"
        elif [ "$cgi_state" -eq 1 ]; then
            echo -e "  ├─ CGI (${cgi_bin}): ${YELLOW}${BOLD}⚠ PARTIAL${NC} [${cgi_patch_desc}]"
        else
            echo -e "  ├─ CGI (${cgi_bin}): ${RED}${BOLD}✘ VULNERABLE${NC}"
        fi
    fi

    # Print FPM Status if exists
    if [ "$fpm_exists" -eq 1 ]; then
        local fpm_run_tag=""
        [ "$fpm_running" -eq 1 ] && fpm_run_tag=" ${CYAN}(active in memory)${NC}"
        if [ "$fpm_state" -eq 2 ]; then
            echo -e "  ├─ FPM (${fpm_bin}): ${GREEN}${BOLD}✔ PROTECTED${NC} [${fpm_patch_desc}]${fpm_run_tag}"
        elif [ "$fpm_state" -eq 1 ]; then
            echo -e "  ├─ FPM (${fpm_bin}): ${YELLOW}${BOLD}⚠ PARTIAL${NC} [${fpm_patch_desc}]${fpm_run_tag}"
        else
            echo -e "  ├─ FPM (${fpm_bin}): ${RED}${BOLD}✘ VULNERABLE${NC}${fpm_run_tag}"
        fi
    fi

    # Print LSPHP Status if exists
    if [ "$lsphp_exists" -eq 1 ]; then
        if [ "$lsphp_state" -eq 2 ]; then
            echo -e "  ├─ LSI (${lsphp_bin}): ${GREEN}${BOLD}✔ PROTECTED${NC} [${lsphp_patch_desc}]"
        elif [ "$lsphp_state" -eq 1 ]; then
            echo -e "  ├─ LSI (${lsphp_bin}): ${YELLOW}${BOLD}⚠ PARTIAL${NC} [${lsphp_patch_desc}]"
        else
            echo -e "  ├─ LSI (${lsphp_bin}): ${RED}${BOLD}✘ VULNERABLE${NC}"
        fi
    fi

    echo -e "  └─ Verdict: ${verdict_display}\n"
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
                ""
        fi
    done
fi

# 5. Remi / RedHat SCL (/opt/remi/php* and /opt/rh/rh-php*)
for scl_base in /opt/remi/php* /opt/rh/rh-php*; do
    if [ -d "$scl_base" ] && [ -x "${scl_base}/root/usr/bin/php" ]; then
        label=$(basename "$scl_base")
        audit_php "RHEL/Remi ${label}" \
            "${scl_base}/root/usr/bin/php" \
            "${scl_base}/root/usr/bin/php-cgi" \
            "${scl_base}/root/usr/sbin/php-fpm" \
            ""
    fi
done

# 5b. CloudLinux alt-php (/opt/alt/php*)
if [ -d "/opt/alt" ]; then
    for php_dir in /opt/alt/php[0-9]*; do
        if [ -d "$php_dir" ] && [ -x "${php_dir}/usr/bin/php" ]; then
            label=$(basename "$php_dir")
            audit_php "CloudLinux alt-${label}" \
                "${php_dir}/usr/bin/php" \
                "${php_dir}/usr/bin/php-cgi" \
                "${php_dir}/usr/sbin/php-fpm" \
                "${php_dir}/usr/bin/lsphp"
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
    for php_dir in /usr/local/lsws/lsphp[0-9]*; do
        if [ -d "$php_dir" ] && [ -x "${php_dir}/bin/php" ]; then
            label=$(basename "$php_dir")
            audit_php "LiteSpeed ${label}" \
                "${php_dir}/bin/php" \
                "${php_dir}/bin/php-cgi" \
                "${php_dir}/sbin/php-fpm" \
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

# 9. HestiaCP / VestaCP / Ondrej Sury PPA / Debian / Ubuntu / RHEL versioned binaries
for cli_bin in /usr/bin/php[578].[0-9] /usr/bin/php[578][0-9]; do
    if [ -x "$cli_bin" ]; then
        v_suffix="${cli_bin#/usr/bin/php}"
        cgi_bin="/usr/bin/php-cgi${v_suffix}"
        [ ! -x "$cgi_bin" ] && cgi_bin="/usr/bin/php${v_suffix}-cgi"
        fpm_bin="/usr/sbin/php-fpm${v_suffix}"
        [ ! -x "$fpm_bin" ] && fpm_bin="/usr/sbin/php${v_suffix}-fpm"
        audit_php "System / Repo PHP ${v_suffix}" "$cli_bin" "$cgi_bin" "$fpm_bin" ""
    fi
done

# 10. Default System PHP (/usr/bin/php, /usr/local/bin/php)
if [ -x "/usr/bin/php" ]; then
    audit_php "Default System PHP (/usr/bin/php)" "/usr/bin/php" "/usr/bin/php-cgi" "/usr/sbin/php-fpm" ""
fi
if [ -x "/usr/local/bin/php" ]; then
    audit_php "Local Build PHP (/usr/local/bin/php)" "/usr/local/bin/php" "/usr/local/bin/php-cgi" "/usr/local/sbin/php-fpm" ""
fi

# 11. Deep scan (--all) for custom paths
if [ "$OPT_ALL" -eq 1 ]; then
    while IFS= read -r custom_cli; do
        [ -z "$custom_cli" ] && continue
        custom_dir=$(dirname "$(dirname "$custom_cli")")
        audit_php "Custom PHP (${custom_cli})" \
            "$custom_cli" \
            "${custom_dir}/bin/php-cgi" \
            "${custom_dir}/sbin/php-fpm" \
            "${custom_dir}/bin/lsphp"
    done < <(find /opt /www /usr/local /home /var /usr/src -maxdepth 5 -type f -name "php" -perm -111 2>/dev/null || true)
fi

# ==============================================================================
# Summary Report (JSON or Terminal)
# ==============================================================================
if [ "$OPT_JSON" -eq 1 ]; then
    items_joined=""
    for idx in "${!JSON_ITEMS[@]}"; do
        if [ "$idx" -gt 0 ]; then
            items_joined="${items_joined},"
        fi
        items_joined="${items_joined}${JSON_ITEMS[$idx]}"
    done
    printf '{"scanner_version":"%s","date":"%s","os":"%s","control_panels":"%s","web_servers":"%s","summary":{"total":%d,"protected":%d,"partial":%d,"ini_mitigated_only":%d,"vulnerable":%d},"installations":[%s]}\n' \
        "$(json_escape "$SCRIPT_VERSION")" \
        "$(json_escape "$SCRIPT_DATE")" \
        "$(json_escape "$OS_INFO")" \
        "$(json_escape "$CONTROL_PANELS")" \
        "$(json_escape "$WEB_SERVERS")" \
        "$TOTAL_CHECKED" \
        "$TOTAL_PROTECTED" \
        "$TOTAL_PARTIAL" \
        "$TOTAL_MITIGATED" \
        "$TOTAL_VULNERABLE" \
        "$items_joined"
    if [ "$TOTAL_VULNERABLE" -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
fi

echo -e "${BOLD}${CYAN}============================================================================${NC}"
echo -e "${BOLD}SUMMARY REPORT:${NC}"
echo -e "  Total PHP Installations Checked : ${BOLD}${TOTAL_CHECKED}${NC}"
echo -e "  Fully Protected (Patched)       : ${GREEN}${BOLD}${TOTAL_PROTECTED}${NC}"
[ "$TOTAL_PARTIAL" -gt 0 ] && echo -e "    ├─ Partially Patched          : ${YELLOW}${BOLD}${TOTAL_PARTIAL}${NC}"
[ "$TOTAL_MITIGATED" -gt 0 ] && echo -e "    ├─ INI-Mitigated Only         : ${YELLOW}${BOLD}${TOTAL_MITIGATED}${NC} (upload_progress=Off, OOM still unpatched)"

if [ "$TOTAL_VULNERABLE" -gt 0 ]; then
    echo -e "  Vulnerable (Action Required)    : ${RED}${BOLD}${TOTAL_VULNERABLE}${NC}"
    echo -e "${BOLD}${CYAN}============================================================================${NC}"
    echo -e "${RED}${BOLD}[!] WARNING: ${TOTAL_VULNERABLE} PHP installation(s) remain vulnerable to CVE-2026-109618 / 109619!${NC}"
    echo -e "    Patches & Manuals: ${CYAN}${REPO_URL}${NC}"
    echo -e "${BOLD}${CYAN}============================================================================${NC}"
    exit 1
else
    echo -e "  Vulnerable (Unpatched)          : ${GREEN}${BOLD}0${NC}"
    echo -e "${BOLD}${CYAN}============================================================================${NC}"
    echo -e "${GREEN}${BOLD}[✔] EXCELLENT: All detected PHP versions are fully protected!${NC}"
    echo -e "${BOLD}${CYAN}============================================================================${NC}"
    exit 0
fi
