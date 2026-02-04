#!/bin/bash
# Shell Guardian Installer
# By Orion & Aaron - 2026-02-03

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${HOME}/.local/bin"
GUARDIAN_PATH="${INSTALL_DIR}/guardian.sh"

echo "🛡️  Shell Guardian Installer"
echo "================================"
echo ""

# Create install directory
mkdir -p "$INSTALL_DIR"

# Copy guardian script
cp "${SCRIPT_DIR}/guardian.sh" "$GUARDIAN_PATH"
chmod +x "$GUARDIAN_PATH"

echo "✅ Installed guardian.sh to ${GUARDIAN_PATH}"
echo ""

# Detect shell
SHELL_NAME=$(basename "$SHELL")
SHELL_RC=""

case "$SHELL_NAME" in
    zsh)
        SHELL_RC="${HOME}/.zshrc"
        ;;
    bash)
        SHELL_RC="${HOME}/.bashrc"
        ;;
    *)
        echo "⚠️  Unknown shell: $SHELL_NAME"
        echo "   Manually add the hook to your shell profile."
        ;;
esac

# Generate hook code
HOOK_CODE="
# Shell Guardian - Terminal Security
# Added by installer on $(date)
_guardian_preexec() {
    local cmd=\"\$1\"
    [[ \"\${GUARDIAN:-1}\" == \"0\" ]] && return 0
    if ! \"${GUARDIAN_PATH}\" check \"\$cmd\"; then
        return 1
    fi
}
if [[ -n \"\$ZSH_VERSION\" ]]; then
    autoload -Uz add-zsh-hook
    add-zsh-hook preexec _guardian_preexec
fi
"

echo ""
echo "To activate Shell Guardian, add this to your ${SHELL_RC}:"
echo ""
echo "────────────────────────────────────────"
echo "$HOOK_CODE"
echo "────────────────────────────────────────"
echo ""
echo "Or run:"
echo "  echo '$HOOK_CODE' >> ${SHELL_RC}"
echo ""
echo "Then restart your shell or run: source ${SHELL_RC}"
echo ""
echo "🛡️  Guardian stands ready!"
