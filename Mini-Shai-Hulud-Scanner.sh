#!/usr/bin/env bash
# ==============================================================================
# Mini Shai-Hulud Scanner v1.0
# Phát hiện mã độc Mini Shai-Hulud / Shai-Hulud supply chain attack
# Dành cho Linux servers, CI/CD runners, và developer workstations
# ==============================================================================

set -o pipefail

# --- Configuration -----------------------------------------------------------
VERSION="1.1.0"
SCAN_ROOT=""
REPORT_FILE=""
VERBOSE=0
QUICK=0
CHECK_PROCESS=0
CHECK_GITHUB=0
FOUND_THREATS=0

# Known malicious SHA-256 hashes
readonly KNOWN_HASHES=(
    # Mini Shai-Hulud Wave 4 - TanStack (May 2026)
    "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"  # router_init.js
    "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96"  # tanstack_runner.js
    "7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b"  # @tanstack/setup package.json
    # Mini Shai-Hulud Wave 3 - SAP CAP (April 2026)
    "4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34"  # setup.mjs
    "80a3d2877813968ef847ae73b5eeeb70b9435254e74d7f07d8cf4057f0a710ac"  # execution.js (mbt)
    "6f933d00b7d05678eb43c90963a80b8947c4ae6830182f89df31da9f568fea95"  # execution.js (@cap-js/sqlite)
    "29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7"  # /proc/mem dumper
    # Shai-Hulud 2.0 (November 2025)
    "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a"  # setup_bun.js
    "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068"  # bun_environment.js
    "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0"  # bun_environment.js (variant)
    "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd"  # bun_environment.js (variant 2)
    # Shai-Hulud 1.0 (September 2025)
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"  # bundle.js
    "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777"
    "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c"
    "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db"
)

# Known malicious tarball shasums
readonly KNOWN_TARBALLS=(
    "0af7415d65753f6aede8c9c0f39be478666b9c12"  # mbt@1.2.48
    "4b04304f6d51392e3f43856c94ca95800518a694"  # @cap-js/db-service@2.10.1
    "7b6a28e92149637e5d7c7f4a2d3e54acd507c929"  # @cap-js/sqlite@2.2.2
    "e80824a19f48d778a746571bb15279b5679fd61c"  # @cap-js/postgres@2.2.2
)

# IOC strings to search in files
readonly IOC_STRINGS=(
    "ctf-scramble-v2"
    "OhNoWhatsGoingOnWithGitHub"
    "A Mini Shai-Hulud has Appeared"
    "Sha1-Hulud: The Second Coming"
    "__DAEMONIZED"
    "tmp.987654321.lock"
    "dependabout/github_actions/format/setup-formatter"
    "dependabot/github_actions/format/"
    "cloudmtabot"
    # Wave 4 - TanStack specific
    "svksjrhjkcejg"
    "EveryBoiWeBuildIsAWormyBoi"
    "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner"
    "79ac49eedf774dd4b0cfa308722bc463cfe5885c"
    "voicproducoes"
    "filev2.getsession.org"
    "api.masscan.cloud"
    "git-tanstack.com"
    "litter.catbox.moe"
    "router_init.js"
    "tanstack_runner.js"
    "gh-token-monitor"
)

# Malicious file names to detect
readonly MALICIOUS_FILES=(
    "setup.mjs"
    "execution.js"
    "setup_bun.js"
    "bun_environment.js"
    "bundle.js"
    # Wave 4 - TanStack
    "router_init.js"
    "tanstack_runner.js"
)

# Persistence paths to check
readonly PERSISTENCE_PATHS=(
    ".claude/settings.json"
    ".vscode/tasks.json"
    ".github/workflows/format-check.yml"
    ".github/workflows/discussion.yaml"
    ".github/workflows/shai-hulud-workflow.yml"
    # Wave 4 - TanStack persistence
    ".github/workflows/codeql_analysis.yml"
    ".claude/router_runtime.js"
    ".claude/setup.mjs"
    ".vscode/setup.mjs"
    ".local/bin/gh-token-monitor.sh"
    ".config/systemd/user/gh-token-monitor.service"
    "Library/LaunchAgents/com.user.gh-token-monitor.plist"
)

# --- Terminal Colors ----------------------------------------------------------
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# --- Functions ----------------------------------------------------------------

usage() {
    cat << EOF
${BOLD}Mini Shai-Hulud Scanner v${VERSION}${NC}
Phát hiện mã độc Mini Shai-Hulud / Shai-Hulud supply chain attack
trên Linux servers, CI/CD runners, và developer workstations.

${BOLD}Usage:${NC} $(basename "$0") [OPTIONS] <SCAN_DIRECTORY>

${BOLD}Arguments:${NC}
    SCAN_DIRECTORY         Đường dẫn cần quét (bắt buộc)

${BOLD}Options:${NC}
    -q                    Quick scan (chỉ quét file *.js/*.mjs, bỏ qua hash file lớn)
    -p                    Kiểm tra process đang chạy (node->bun->python chain)
    -g                    Kiểm tra GitHub account cho dead-drop repos (cần gh CLI)
    -o <file>             Xuất report ra file
    -v                    Verbose mode — hiển thị chi tiết từng bước quét
    -h, --help            Hiển thị hướng dẫn này

${BOLD}Ví dụ:${NC}
    # Quét toàn bộ hệ thống
    sudo $(basename "$0") /

    # Quét project cụ thể
    $(basename "$0") /opt/app

    # Quét kèm process check + xuất report
    $(basename "$0") -p -o /tmp/scan-report.txt /home/user/project

    # Quick scan thư mục hiện tại
    $(basename "$0") -q .

    # Quét đầy đủ: process + GitHub
    $(basename "$0") -p -g /var/www

EOF
    exit 0
}

error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
threat(){ echo -e "${RED}${BOLD}[THREAT]${NC} $*"; FOUND_THREATS=$((FOUND_THREATS + 1)); }
header(){ echo -e "\n${WHITE}${BOLD}=== $* ===${NC}\n"; }

log_report() {
    echo "$*" >> "$REPORT_FILE"
}

# --- Dependency Check ---------------------------------------------------------
check_deps() {
    local missing=0

    for cmd in sha256sum find grep jq stat; do
        if ! command -v "$cmd" &>/dev/null; then
            error "Missing required tool: $cmd"
            missing=1
        fi
    done

    if [[ "$CHECK_GITHUB" -eq 1 ]] && ! command -v gh &>/dev/null; then
        error "gh CLI required for GitHub checking"
        missing=1
    fi

    if [[ "$missing" -eq 1 ]]; then
        exit 1
    fi
}

# --- Section 1: Hash Scanning -------------------------------------------------
scan_hashes() {
    header "1. Malicious File Hash Scan"

    # Build associative arrays for O(1) lookup
    local -A HASH_MAP=()
    for h in "${KNOWN_HASHES[@]}"; do HASH_MAP["$h"]="malware"; done
    for h in "${KNOWN_TARBALLS[@]}"; do HASH_MAP["$h"]="tarball"; done

    local scanned=0
    local file_list

    if [[ "$QUICK" -eq 1 ]]; then
        info "Quick mode: scanning only *.js, *.mjs, *.cjs, *.tgz files..."
        file_list=$(find "$SCAN_ROOT" -type f \( -name "*.js" -o -name "*.mjs" -o -name "*.cjs" -o -name "*.tgz" \) 2>/dev/null)
    else
        info "Scanning all files (this may take a while)..."
        file_list=$(find "$SCAN_ROOT" -type f -not -path "*/proc/*" -not -path "*/sys/*" -not -path "*/dev/*" 2>/dev/null)
    fi

    while IFS= read -r file; do
        [[ -z "$file" || ! -r "$file" ]] && continue
        scanned=$((scanned + 1))

        local hash
        hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
        [[ -z "$hash" ]] && continue

        local match_type="${HASH_MAP[$hash]:-}"
        if [[ -n "$match_type" ]]; then
            local fsize
            fsize=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo "?")
            if [[ "$match_type" == "tarball" ]]; then
                threat "KNOWN MALICIOUS TARBALL [$hash]: $file"
                log_report "TARBALL_MATCH|$hash|$file"
            else
                threat "KNOWN MALICIOUS HASH [$hash]: $file ($fsize bytes)"
                log_report "HASH_MATCH|$hash|$file|$fsize"
            fi
        fi
    done <<< "$file_list"

    info "Scanned $scanned files for known hashes"
}

# --- Section 2: IOC String Scan -----------------------------------------------
scan_ioc_strings() {
    header "2. IOC String Scan"

    [[ ! -d "$SCAN_ROOT" ]] && return

    # Build alternation pattern from all IOCs (escape regex special chars)
    local pattern=""
    for ioc in "${IOC_STRINGS[@]}"; do
        local escaped; escaped=$(printf '%s' "$ioc" | sed 's/[.[\*^$()+?{|]/\\&/g')
        [[ -n "$pattern" ]] && pattern="$pattern|"
        pattern="$pattern$escaped"
    done

    if [[ "$VERBOSE" -eq 1 ]]; then
        info "Combined IOC pattern: ${pattern:0:120}..."
    fi

    # Single grep pass over all target file types
    local matches
    matches=$(grep -rlnE --include="*.js" --include="*.mjs" --include="*.json" \
        --include="*.ts" --include="*.yml" --include="*.yaml" --include="*.sh" \
        --include="*.py" --include="*.txt" --include="*.md" \
        "$pattern" "$SCAN_ROOT" 2>/dev/null)

    if [[ -n "$matches" ]]; then
        while IFS= read -r match_file; do
            [[ -z "$match_file" ]] && continue
            [[ "$match_file" == "$REPORT_FILE" ]] && continue

            # Find which specific IOC matched
            local matched_lines
            matched_lines=$(grep -nE "$pattern" "$match_file" 2>/dev/null | head -5)
            while IFS= read -r mline; do
                [[ -z "$mline" ]] && continue
                local line_num="${mline%%:*}"
                local line_content="${mline#*:}"
                threat "IOC string found in: $match_file (line $line_num): ${line_content:0:120}"
                log_report "IOC_STRING|$match_file|$line_num|${line_content:0:200}"
            done <<< "$matched_lines"
        done <<< "$matches"
    elif [[ "$VERBOSE" -eq 1 ]]; then
        ok "No IOC strings found"
    fi
}

# --- Section 3: Malicious Filename Scan ---------------------------------------
scan_filenames() {
    header "3. Malicious Filename Scan"

    for mf in "${MALICIOUS_FILES[@]}"; do
        local found
        found=$(find "$SCAN_ROOT" -type f -name "$mf" -not -path "*/node_modules/.cache/*" 2>/dev/null)

        if [[ -n "$found" ]]; then
            while IFS= read -r f; do
                [[ -z "$f" ]] && continue
                local fsize
                fsize=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo "?")
                local fhash
                fhash=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')

                threat "Malicious filename: $f (size: $fsize bytes, hash: $fhash)"
                log_report "MALICIOUS_FILENAME|$mf|$f|$fsize|$fhash"
            done <<< "$found"
        elif [[ "$VERBOSE" -eq 1 ]]; then
            ok "No files named '$mf' found"
        fi
    done
}

# --- Section 4: Large Suspicious Files ----------------------------------------
scan_large_js() {
    header "4. Large JavaScript Files (>9MB)"

    local large_files
    large_files=$(find "$SCAN_ROOT" -type f \( -name "*.js" -o -name "*.mjs" -o -name "*.cjs" \) \
        -size +9M -not -path "*/node_modules/*" 2>/dev/null)

    if [[ -n "$large_files" ]]; then
        while IFS= read -r lf; do
            [[ -z "$lf" ]] && continue
            local fsize
            fsize=$(stat -c%s "$lf" 2>/dev/null || stat -f%z "$lf" 2>/dev/null || echo "?")
            local fhash
            fhash=$(sha256sum "$lf" 2>/dev/null | awk '{print $1}')

            threat "Suspicious large JS file (>9MB): $lf (size: $fsize bytes, hash: $fhash)"
            log_report "LARGE_JS|$lf|$fsize|$fhash"

            # Quick check for obfuscation indicators
            if grep -qF "ctf-scramble-v2" "$lf" 2>/dev/null; then
                threat "  -> FILE CONTAINS ctf-scramble-v2 CIPHER MARKER"
            fi
            if grep -qF "oven-sh/bun/releases" "$lf" 2>/dev/null; then
                threat "  -> FILE REFERENCES BUN DOWNLOAD URL"
            fi
        done <<< "$large_files"
    else
        ok "No large JS files found"
    fi
}

# --- Section 5: Preinstall/Prepare Script Audit ------------------------------------
# (Also covers Wave 4 optionalDependencies + prepare hook attack vector)
scan_preinstall() {
    header "5. Suspicious Preinstall Scripts in package.json"

    local pkg_files
    pkg_files=$(find "$SCAN_ROOT" -name "package.json" -not -path "*/node_modules/.cache/*" 2>/dev/null)

    if [[ -z "$pkg_files" ]]; then
        info "No package.json files found in scan root"
        return
    fi

    local checked=0
    while IFS= read -r pkg; do
        [[ -z "$pkg" || ! -r "$pkg" ]] && continue
        checked=$((checked + 1))

        # Check for preinstall scripts
        local has_preinstall
        has_preinstall=$(jq -r 'select(.scripts.preinstall != null) | .scripts.preinstall' "$pkg" 2>/dev/null)

        if [[ -n "$has_preinstall" && "$has_preinstall" != "null" ]]; then
            local pkg_name
            pkg_name=$(jq -r '.name // "unknown"' "$pkg" 2>/dev/null)
            local pkg_ver
            pkg_ver=$(jq -r '.version // "unknown"' "$pkg" 2>/dev/null)

            warn "Package [$pkg_name@$pkg_ver] has preinstall script: $has_preinstall"
            log_report "PREINSTALL_SCRIPT|$pkg_name|$pkg_ver|$has_preinstall|$pkg"

            if echo "$has_preinstall" | grep -qE "setup\.mjs|execution\.js|curl.*bun|wget.*bun"; then
                threat "  -> DANGEROUS: preinstall references known malicious file or downloads Bun"
            fi
        fi

        # Check for prepare scripts (Wave 4 TanStack vector)
        local has_prepare
        has_prepare=$(jq -r 'select(.scripts.prepare != null) | .scripts.prepare' "$pkg" 2>/dev/null)
        if [[ -n "$has_prepare" && "$has_prepare" != "null" ]]; then
            local pkg_name; pkg_name=$(jq -r '.name // "unknown"' "$pkg" 2>/dev/null)
            local pkg_ver; pkg_ver=$(jq -r '.version // "unknown"' "$pkg" 2>/dev/null)

            if echo "$has_prepare" | grep -qE "bun.*run.*tanstack_runner|bun.*run.*router_init|tanstack_runner\.js"; then
                threat "Wave 4 TanStack prepare hook: [$pkg_name@$pkg_ver] $has_prepare"
                log_report "WAVE4_PREPARE_HOOK|$pkg_name|$pkg_ver|$has_prepare|$pkg"
            elif echo "$has_prepare" | grep -qE "&& exit 1"; then
                warn "Suspicious prepare hook with exit 1: [$pkg_name@$pkg_ver] $has_prepare"
                log_report "SUSPICIOUS_PREPARE_HOOK|$pkg_name|$pkg_ver|$has_prepare|$pkg"
            fi
        fi

        # Check for Wave 4 malicious optionalDependencies
        local has_optional_dep
        has_optional_dep=$(jq -r 'select(.optionalDependencies != null) | .optionalDependencies | to_entries[] | "\(.key):\(.value)"' "$pkg" 2>/dev/null)
        if [[ -n "$has_optional_dep" ]]; then
            if echo "$has_optional_dep" | grep -qE "79ac49eedf774dd4b0cfa308722bc463cfe5885c|github:tanstack/router"; then
                local pkg_name; pkg_name=$(jq -r '.name // "unknown"' "$pkg" 2>/dev/null)
                threat "Wave 4 TanStack malicious optionalDependency in [$pkg_name]: $has_optional_dep"
                log_report "WAVE4_OPTIONAL_DEP|$pkg_name|$has_optional_dep|$pkg"
            fi
        fi

        # Check for compromised package versions
        local pkg_name_full
        pkg_name_full=$(jq -r '.name // ""' "$pkg" 2>/dev/null)

        case "$pkg_name_full" in
            # Wave 3 - SAP CAP
            "mbt")
                local ver; ver=$(jq -r '.version // ""' "$pkg" 2>/dev/null)
                [[ "$ver" == "1.2.48" ]] && threat "COMPROMISED VERSION: $pkg_name_full@$ver in $pkg"
                ;;
            "@cap-js/db-service")
                local ver; ver=$(jq -r '.version // ""' "$pkg" 2>/dev/null)
                [[ "$ver" == "2.10.1" ]] && threat "COMPROMISED VERSION: $pkg_name_full@$ver in $pkg"
                ;;
            "@cap-js/sqlite")
                local ver; ver=$(jq -r '.version // ""' "$pkg" 2>/dev/null)
                [[ "$ver" == "2.2.2" ]] && threat "COMPROMISED VERSION: $pkg_name_full@$ver in $pkg"
                ;;
            "@cap-js/postgres")
                local ver; ver=$(jq -r '.version // ""' "$pkg" 2>/dev/null)
                [[ "$ver" == "2.2.2" ]] && threat "COMPROMISED VERSION: $pkg_name_full@$ver in $pkg"
                ;;
            # Wave 4 - TanStack (key packages that are most likely to be used)
            "@tanstack/react-router")
                local ver; ver=$(jq -r '.version // ""' "$pkg" 2>/dev/null)
                [[ "$ver" == "1.169.5" || "$ver" == "1.169.8" ]] && threat "COMPROMISED VERSION (Wave 4 TanStack): $pkg_name_full@$ver in $pkg"
                ;;
            "@tanstack/vue-router")
                local ver; ver=$(jq -r '.version // ""' "$pkg" 2>/dev/null)
                [[ "$ver" == "1.169.5" || "$ver" == "1.169.8" ]] && threat "COMPROMISED VERSION (Wave 4 TanStack): $pkg_name_full@$ver in $pkg"
                ;;
            "@tanstack/solid-router")
                local ver; ver=$(jq -r '.version // ""' "$pkg" 2>/dev/null)
                [[ "$ver" == "1.169.5" || "$ver" == "1.169.8" ]] && threat "COMPROMISED VERSION (Wave 4 TanStack): $pkg_name_full@$ver in $pkg"
                ;;
            "@tanstack/router-core")
                local ver; ver=$(jq -r '.version // ""' "$pkg" 2>/dev/null)
                [[ "$ver" == "1.169.5" || "$ver" == "1.169.8" ]] && threat "COMPROMISED VERSION (Wave 4 TanStack): $pkg_name_full@$ver in $pkg"
                ;;
            "@tanstack/react-start")
                local ver; ver=$(jq -r '.version // ""' "$pkg" 2>/dev/null)
                [[ "$ver" == "1.167.68" || "$ver" == "1.167.71" ]] && threat "COMPROMISED VERSION (Wave 4 TanStack): $pkg_name_full@$ver in $pkg"
                ;;
            "@tanstack/router-plugin")
                local ver; ver=$(jq -r '.version // ""' "$pkg" 2>/dev/null)
                [[ "$ver" == "1.167.38" || "$ver" == "1.167.41" ]] && threat "COMPROMISED VERSION (Wave 4 TanStack): $pkg_name_full@$ver in $pkg"
                ;;
            "@tanstack/router-cli")
                local ver; ver=$(jq -r '.version // ""' "$pkg" 2>/dev/null)
                [[ "$ver" == "1.166.46" || "$ver" == "1.166.49" ]] && threat "COMPROMISED VERSION (Wave 4 TanStack): $pkg_name_full@$ver in $pkg"
                ;;
            "@tanstack/history")
                local ver; ver=$(jq -r '.version // ""' "$pkg" 2>/dev/null)
                [[ "$ver" == "1.161.9" || "$ver" == "1.161.12" ]] && threat "COMPROMISED VERSION (Wave 4 TanStack): $pkg_name_full@$ver in $pkg"
                ;;
            # Wave 4 - Mistral AI
            "@mistralai/mistralai")
                local ver; ver=$(jq -r '.version // ""' "$pkg" 2>/dev/null)
                [[ "$ver" == "2.2.3" || "$ver" == "2.2.4" ]] && threat "COMPROMISED VERSION (Wave 4 Mistral): $pkg_name_full@$ver in $pkg"
                ;;
            "@mistralai/mistralai-azure"|"@mistralai/mistralai-gcp")
                local ver; ver=$(jq -r '.version // ""' "$pkg" 2>/dev/null)
                [[ "$ver" == "1.7.2" || "$ver" == "1.7.3" ]] && threat "COMPROMISED VERSION (Wave 4 Mistral): $pkg_name_full@$ver in $pkg"
                ;;
            # Wave 4 - OpenSearch
            "@opensearch-project/opensearch")
                local ver; ver=$(jq -r '.version // ""' "$pkg" 2>/dev/null)
                [[ "$ver" == "3.6.2" ]] && threat "COMPROMISED VERSION (Wave 4 OpenSearch): $pkg_name_full@$ver in $pkg"
                ;;
        esac
    done <<< "$pkg_files"

    info "Checked $checked package.json files"
}

# --- Section 6: Persistence Artifacts -----------------------------------------
scan_persistence() {
    header "6. Persistence Mechanism Artifacts"

    local home_dirs=(
        "$HOME"
        "$SCAN_ROOT"
    )

    # Add /home/* if running as root
    if [[ "$EUID" -eq 0 ]]; then
        while IFS= read -r hd; do
            [[ -d "$hd" ]] && home_dirs+=("$hd")
        done < <(find /home -maxdepth 1 -mindepth 1 -type d 2>/dev/null)
    fi

    for hd in "${home_dirs[@]}"; do
        [[ -z "$hd" || ! -d "$hd" ]] && continue

        for ppath in "${PERSISTENCE_PATHS[@]}"; do
            local full_path="$hd/$ppath"
            if [[ -f "$full_path" ]]; then
                if [[ "$ppath" == *".claude/settings.json" ]]; then
                    local has_hook
                    has_hook=$(jq -r '.hooks.SessionStart // empty' "$full_path" 2>/dev/null)
                    if [[ -n "$has_hook" ]]; then
                        threat "Claude Code SessionStart hook: $full_path"
                        log_report "PERSISTENCE_CLAUDE_HOOK|$full_path|$has_hook"
                    fi
                elif [[ "$ppath" == *".vscode/tasks.json" ]]; then
                    local has_folder_open
                    has_folder_open=$(jq -r '.tasks[]? | select(.runOn == "folderOpen") | .command // empty' "$full_path" 2>/dev/null)
                    if [[ -n "$has_folder_open" ]]; then
                        threat "VS Code folderOpen task: $full_path -> $has_folder_open"
                        log_report "PERSISTENCE_VSCODE_TASK|$full_path|$has_folder_open"
                    fi
                elif [[ "$ppath" == *"format-check.yml" ]]; then
                    local has_secrets_dump
                    has_secrets_dump=$(grep -c "toJSON(secrets)" "$full_path" 2>/dev/null)
                    if [[ "$has_secrets_dump" -gt 0 ]]; then
                        threat "Dependabot impersonation workflow (secrets dump): $full_path"
                        log_report "PERSISTENCE_DEPENDABOT_WORKFLOW|$full_path"
                    fi
                elif [[ "$ppath" == *"codeql_analysis.yml" ]]; then
                    local has_codeql_dump
                    has_codeql_dump=$(grep -c "toJSON(secrets)" "$full_path" 2>/dev/null)
                    if [[ "$has_codeql_dump" -gt 0 ]]; then
                        threat "Wave 4 injected CodeQL workflow (secrets dump): $full_path"
                        log_report "PERSISTENCE_CODEQL_WORKFLOW|$full_path"
                    fi
                elif [[ "$ppath" == *"router_runtime.js" || "$ppath" == *"setup.mjs" ]]; then
                    threat "Wave 4 Claude Code / VS Code payload: $full_path"
                    log_report "PERSISTENCE_WAVE4_PAYLOAD|$full_path"
                elif [[ "$ppath" == *"gh-token-monitor"* ]]; then
                    threat "Wave 4 dead-man's switch service: $full_path (DISABLE BEFORE REVOKING TOKENS!)"
                    log_report "PERSISTENCE_DEADMAN_SWITCH|$full_path"
                else
                    warn "Suspicious persistence file: $full_path"
                    log_report "PERSISTENCE_FILE|$full_path"
                fi
            fi
        done
    done
}

# --- Section 7: Process & Runtime Detection -----------------------------------
scan_processes() {
    [[ "$CHECK_PROCESS" -eq 0 ]] && return

    header "7. Running Process Scan"

    # Check for node -> bun -> python process chain
    if command -v pgrep &>/dev/null; then
        local bun_procs
        bun_procs=$(pgrep -f "bun" 2>/dev/null || true)

        if [[ -n "$bun_procs" ]]; then
            while IFS= read -r pid; do
                [[ -z "$pid" ]] && continue
                local parent_chain
                parent_chain=$(ps -o pid,ppid,comm --no-headers -p "$pid" 2>/dev/null || true)

                # Check if bun was spawned from node/npm context
                local ppid
                ppid=$(echo "$parent_chain" | awk '{print $2}')
                local parent_cmd
                parent_cmd=$(ps -o comm= -p "$ppid" 2>/dev/null || echo "")

                if [[ "$parent_cmd" == "node" || "$parent_cmd" == "npm" ]]; then
                    threat "Bun process spawned from Node.js context: PID=$pid, Parent=$ppid ($parent_cmd)"
                    log_report "PROCESS_BUN_SPAWN|$pid|$ppid|$parent_cmd"
                fi
            done <<< "$bun_procs"
        else
            ok "No Bun processes running"
        fi
    else
        info "pgrep not available, skipping process check"
    fi

    # Check for daemon env var and lockfile
    if [[ -n "${__DAEMONIZED:-}" ]]; then
        threat "Environment variable __DAEMONIZED is set!"
        log_report "ENV_DAEMONIZED|set"
    fi

    if [[ -f "/tmp/tmp.987654321.lock" ]]; then
        threat "Malware lockfile exists: /tmp/tmp.987654321.lock"
        log_report "LOCKFILE|/tmp/tmp.987654321.lock"
    fi

    # Check for GitHub runner registered with malicious name
    if command -v pgrep &>/dev/null && pgrep -f "SHA1HULUD" >/dev/null 2>&1; then
        threat "GitHub Actions runner registered with name SHA1HULUD!"
        log_report "PROCESS_SHA1HULUD_RUNNER|found"
    fi
}

# --- Section 8: GitHub Account Check ------------------------------------------
scan_github() {
    [[ "$CHECK_GITHUB" -eq 0 ]] && return

    header "8. GitHub Account Dead-Drop Check"

    if ! command -v gh &>/dev/null; then
        error "GitHub CLI not available"
        return
    fi

    if ! gh auth status &>/dev/null 2>&1; then
        error "Not authenticated with GitHub. Run 'gh auth login' first."
        return
    fi

    info "Checking for dead-drop repositories..."
    local repos
    repos=$(gh repo list --public --limit 200 --json name,description 2>/dev/null)

    if [[ -n "$repos" ]]; then
        # Check for Mini Shai-Hulud description
        local suspicious
        suspicious=$(echo "$repos" | jq -r '.[] | select(.description | test("Mini Shai-Hulud|Shai-Hulud|Sha1-Hulud")) | "\(.name): \(.description)"' 2>/dev/null)

        if [[ -n "$suspicious" ]]; then
            while IFS= read -r repo_line; do
                [[ -z "$repo_line" ]] && continue
                threat "Suspicious GitHub repo (dead-drop indicator): $repo_line"
                log_report "GITHUB_DEADDROP_REPO|$repo_line"
            done <<< "$suspicious"
        else
            ok "No dead-drop repositories found"
        fi

        # Check for suspicious commit author
        info "Checking recent commit history for suspicious author..."
        local suspicious_commits
        suspicious_commits=$(gh api "search/commits?q=author:claude@users.noreply.github.com+committer-date:>2026-03-01" --jq '.total_count // 0' 2>/dev/null)

        if [[ "${suspicious_commits:-0}" -gt 0 ]]; then
            threat "Found $suspicious_commits commits from suspicious author (claude@users.noreply.github.com) since March 2026!"
            log_report "GITHUB_SUSPICIOUS_COMMITS|$suspicious_commits"
        else
            ok "No suspicious commits found"
        fi
    else
        info "Could not retrieve repository list"
    fi
}

# --- Section 9: Suspicious Environment Check ----------------------------------
scan_environment() {
    header "9. Environment & System Indicators"

    # Check environment variables
    local env_vars=("__DAEMONIZED" "NPM_TOKEN" "GH_TOKEN" "GITHUB_TOKEN")
    for ev in "${env_vars[@]}"; do
        if [[ -n "${!ev:-}" ]]; then
            if [[ "$ev" == "__DAEMONIZED" ]]; then
                threat "Malware daemon env var set: $ev"
                log_report "ENV_MALWARE|$ev"
            else
                warn "Sensitive token in environment: $ev (consider unsetting in non-interactive contexts)"
                log_report "ENV_SENSITIVE|$ev"
            fi
        fi
    done

    # Check for suspicious Bun binary downloaded outside package manager
    if command -v bun &>/dev/null; then
        local bun_path
        bun_path=$(command -v bun)
        warn "Bun runtime found at: $bun_path"
        # Check if bun was installed via system package manager
        if ! dpkg -S "$bun_path" &>/dev/null 2>&1 && ! rpm -qf "$bun_path" &>/dev/null 2>&1; then
            warn "  -> Bun was NOT installed via system package manager"
        fi
        log_report "BUN_INSTALLED|$bun_path"
    fi

    # Check npm cache for known compromised packages
    if command -v npm &>/dev/null; then
        local npm_cache
        npm_cache=$(npm config get cache 2>/dev/null || echo "$HOME/.npm")

        if [[ -d "$npm_cache/_cacache" ]]; then
            for tb_hash in "${KNOWN_TARBALLS[@]}"; do
                local found_in_cache
                found_in_cache=$(find "$npm_cache" -type f -name "*${tb_hash:0:12}*" 2>/dev/null | head -3)
                if [[ -n "$found_in_cache" ]]; then
                    threat "Known malicious tarball found in npm cache: $tb_hash"
                    log_report "NPM_CACHE_THREAT|$tb_hash|$found_in_cache"
                fi
            done
        fi

        # Wave 4: Check npm tokens for threat description
        if npm token list &>/dev/null 2>&1; then
            local threat_tokens
            threat_tokens=$(npm token list 2>/dev/null | grep -i "IfYouRevokeThisToken")
            if [[ -n "$threat_tokens" ]]; then
                threat "Wave 4 dead-man's switch npm token detected! DO NOT REVOKE BEFORE ISOLATING MACHINE."
                log_report "WAVE4_THREAT_TOKEN|$threat_tokens"
            fi
        fi
    fi

    # Wave 4: Check for dead-man's switch systemd service (Linux)
    if [[ -f "$HOME/.config/systemd/user/gh-token-monitor.service" ]]; then
        threat "Wave 4 dead-man's switch systemd service exists! Disable before revoking tokens: systemctl --user stop gh-token-monitor"
        log_report "WAVE4_SYSTEMD_SERVICE|$HOME/.config/systemd/user/gh-token-monitor.service"
    fi

    # Wave 4: Check for dead-man's switch LaunchAgent (macOS)
    if [[ -f "$HOME/Library/LaunchAgents/com.user.gh-token-monitor.plist" ]]; then
        threat "Wave 4 dead-man's switch LaunchAgent exists! Unload before revoking tokens: launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist"
        log_report "WAVE4_LAUNCHAGENT|$HOME/Library/LaunchAgents/com.user.gh-token-monitor.plist"
    fi

    # Wave 4: Check for dead-man's switch script
    if [[ -f "$HOME/.local/bin/gh-token-monitor.sh" ]]; then
        threat "Wave 4 dead-man's switch script exists: $HOME/.local/bin/gh-token-monitor.sh"
        log_report "WAVE4_MONITOR_SCRIPT|$HOME/.local/bin/gh-token-monitor.sh"
    fi
}

# --- Section 10: Dependency Version Check -------------------------------------
scan_dependency_versions() {
    header "10. Known Compromised Dependency Versions"

    local lock_files
    lock_files=$(find "$SCAN_ROOT" -maxdepth 4 \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) \
        -not -path "*/node_modules/*" 2>/dev/null)

    if [[ -z "$lock_files" ]]; then
        info "No lock files found in scan root"
        return
    fi

    declare -A COMPROMISED=(
        # Wave 3 - SAP CAP
        ["mbt@1.2.48"]="Mini Shai-Hulud Wave 3 (April 2026)"
        ["@cap-js/db-service@2.10.1"]="Mini Shai-Hulud Wave 3 (April 2026)"
        ["@cap-js/sqlite@2.2.2"]="Mini Shai-Hulud Wave 3 (April 2026)"
        ["@cap-js/postgres@2.2.2"]="Mini Shai-Hulud Wave 3 (April 2026)"
        # Wave 2
        ["@ctrl/tinycolor"]="Shai-Hulud 2.0 (November 2025)"
        # Wave 4 - TanStack (key packages)
        ["@tanstack/react-router"]="Mini Shai-Hulud Wave 4 (May 2026) - check version"
        ["@tanstack/vue-router"]="Mini Shai-Hulud Wave 4 (May 2026) - check version"
        ["@tanstack/solid-router"]="Mini Shai-Hulud Wave 4 (May 2026) - check version"
        ["@tanstack/router-core"]="Mini Shai-Hulud Wave 4 (May 2026) - check version"
        ["@tanstack/react-start"]="Mini Shai-Hulud Wave 4 (May 2026) - check version"
        ["@tanstack/router-plugin"]="Mini Shai-Hulud Wave 4 (May 2026) - check version"
        ["@tanstack/router-cli"]="Mini Shai-Hulud Wave 4 (May 2026) - check version"
        ["@tanstack/history"]="Mini Shai-Hulud Wave 4 (May 2026) - check version"
        ["@mistralai/mistralai"]="Mini Shai-Hulud Wave 4 (May 2026) - check version"
        ["@opensearch-project/opensearch"]="Mini Shai-Hulud Wave 4 (May 2026) - check version"
    )

    while IFS= read -r lockfile; do
        [[ -z "$lockfile" || ! -r "$lockfile" ]] && continue

        for pkg_spec in "${!COMPROMISED[@]}"; do
            local pkg_name="${pkg_spec%@*}"
            local pkg_ver="${pkg_spec#*@}"

            if grep -q "\"$pkg_name\"" "$lockfile" 2>/dev/null; then
                if [[ "$pkg_spec" == *"@"* ]] && grep -q "\"version\": \"$pkg_ver\"" "$lockfile" 2>/dev/null; then
                    threat "Compromised package in lockfile: $pkg_spec in $lockfile (${COMPROMISED[$pkg_spec]})"
                    log_report "LOCKFILE_COMPROMISED|$pkg_spec|$lockfile"
                elif [[ "$pkg_spec" != *"@"* ]]; then
                    warn "Potentially compromised package: $pkg_name in $lockfile (${COMPROMISED[$pkg_spec]})"
                    log_report "LOCKFILE_SUSPICIOUS|$pkg_name|$lockfile"
                fi
            fi
        done
    done <<< "$lock_files"
}

# --- Section 11: SSH & Credential File Exposure -------------------------------
scan_credential_exposure() {
    header "11. Credential File Exposure Check"

    local cred_patterns=(
        "~/.ssh/id_*"
        "*.pem"
        "*.p12"
        "*.pfx"
    )

    # Check permissions on sensitive files
    for pattern in "${cred_patterns[@]}"; do
        local found
        found=$(find "$HOME" -maxdepth 3 -path "$pattern" -type f 2>/dev/null | head -5)
        if [[ -n "$found" ]]; then
            while IFS= read -r cf; do
                [[ -z "$cf" ]] && continue
                local perms
                perms=$(stat -c "%a" "$cf" 2>/dev/null || echo "???")
                if [[ "$perms" != "600" && "$perms" != "400" ]]; then
                    warn "Weak permissions ($perms) on credential file: $cf"
                    log_report "CRED_WEAK_PERMS|$cf|$perms"
                fi
            done <<< "$found"
        fi
    done

    # Check for shell history exfiltration indicators
    local history_files=(
        "$HOME/.bash_history"
        "$HOME/.zsh_history"
        "$HOME/.mysql_history"
        "$HOME/.psql_history"
        "$HOME/.rediscli_history"
    )

    for hf in "${history_files[@]}"; do
        if [[ -f "$hf" ]]; then
            local hsize
            hsize=$(stat -c%s "$hf" 2>/dev/null || echo "0")
            if [[ "$hsize" -gt 10485760 ]]; then # >10MB suspicious
                warn "Unusually large history file: $hf ($hsize bytes)"
                log_report "LARGE_HISTORY|$hf|$hsize"
            fi
        fi
    done
}

# --- Main ---------------------------------------------------------------------
main() {
    echo -e "${BOLD}${MAGENTA}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║        Mini Shai-Hulud Scanner v${VERSION}                ║"
    echo "  ║  Supply Chain Attack Detection for Linux Systems    ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    info "Scan root: $SCAN_ROOT"
    info "Started at: $(date '+%Y-%m-%d %H:%M:%S %Z')"
    [[ "$QUICK" -eq 1 ]] && info "Mode: Quick Scan"
    [[ "$CHECK_PROCESS" -eq 1 ]] && info "Process check: Enabled"
    [[ "$CHECK_GITHUB" -eq 1 ]] && info "GitHub check: Enabled"

    if [[ -n "$REPORT_FILE" ]]; then
        info "Report file: $REPORT_FILE"
        echo "# Mini Shai-Hulud Scan Report - $(date '+%Y-%m-%d %H:%M:%S %Z')" > "$REPORT_FILE"
        echo "# Scan root: $SCAN_ROOT" >> "$REPORT_FILE"
        echo "#" >> "$REPORT_FILE"
    fi

    check_deps

    scan_hashes
    scan_ioc_strings
    scan_filenames
    scan_large_js
    scan_preinstall
    scan_persistence
    scan_processes
    scan_github
    scan_environment
    scan_dependency_versions
    scan_credential_exposure

    # --- Summary ---------------------------------------------------------------
    header "Scan Summary"

    if [[ "$FOUND_THREATS" -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}"
        echo "  ╔══════════════════════════════════════╗"
        echo "  ║   NO THREATS DETECTED               ║"
        echo "  ║   System appears clean              ║"
        echo "  ╚══════════════════════════════════════╝"
        echo -e "${NC}"
    else
        echo -e "${RED}${BOLD}"
        echo "  ╔══════════════════════════════════════╗"
        echo "  ║   !! THREATS DETECTED !!            ║"
        printf "  ║   %-34s ║\n" "$FOUND_THREATS potential threat(s) found"
        echo "  ╚══════════════════════════════════════╝"
        echo -e "${NC}"

        echo ""
        warn "Recommended immediate actions:"
        echo "  1. ISOLATE MACHINE FIRST (disconnect network)"
        echo "  2. Check for dead-man's switch BEFORE revoking tokens:"
        echo "     systemctl --user stop gh-token-monitor.service 2>/dev/null"
        echo "     launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist 2>/dev/null"
        echo "  3. Rotate ALL credentials (npm tokens, GitHub PATs, cloud API keys)"
        echo "  4. Revoke npm tokens: npm token list && npm token revoke <id>"
        echo "  5. Check GitHub account: gh repo list --public | grep -iE 'shai|hulud|kanly|sietch|ghola'"
        echo "  6. Review commit history for claude@users.noreply.github.com"
        echo "  7. Remove persistence artifacts (.claude/, .vscode/tasks.json, codeql_analysis.yml)"
        echo "  8. Check for optionalDependencies with github:tanstack/router URL"
        echo "  9. Run: npm install --ignore-scripts && npm audit"
    fi

    if [[ -n "$REPORT_FILE" ]]; then
        echo ""
        info "Report saved to: $REPORT_FILE"
    fi

    return "$FOUND_THREATS"
}

# --- Argument Parsing ---------------------------------------------------------
# Show help if no arguments provided
if [[ $# -eq 0 ]]; then
    usage
fi

# Handle --help before getopts (getopts only handles short flags)
for arg in "$@"; do
    if [[ "$arg" == "--help" ]]; then
        usage
    fi
done

while getopts "qpgo:vh" opt; do
    case "$opt" in
        q) QUICK=1 ;;
        p) CHECK_PROCESS=1 ;;
        g) CHECK_GITHUB=1 ;;
        o) REPORT_FILE="$OPTARG" ;;
        v) VERBOSE=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))

# Directory argument is required
if [[ $# -eq 0 ]]; then
    error "Missing scan directory. Use --help for usage."
    echo ""
    echo "Example: $(basename "$0") /path/to/scan"
    echo "         $(basename "$0") -q ."
    exit 1
fi

SCAN_ROOT="$1"

# Resolve to absolute path
SCAN_ROOT="$(cd "$SCAN_ROOT" 2>/dev/null && pwd || echo "$SCAN_ROOT")"

if [[ ! -d "$SCAN_ROOT" ]]; then
    error "Directory not found: $SCAN_ROOT"
    exit 1
fi

main
