# 🛡️ Shell Guardian

**Terminal security for humans.** Catches homograph attacks, pipe-to-shell dangers, and terminal injection before they execute.

*Built by Orion & Aaron — 2026-02-03*

![Version](https://img.shields.io/badge/version-0.2.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Shell](https://img.shields.io/badge/shell-bash%20%7C%20zsh-orange)

---

## The Problem

Your browser would catch this. Your terminal won't:

```bash
curl -sSL https://install.example-cli.dev | bash  # safe
curl -sSL https://іnstall.example-clі.dev | bash  # COMPROMISED
```

See the difference? Neither does your terminal. Both `і` characters are **Cyrillic** (U+0456), not Latin `i`. The second URL resolves to an attacker's server.

## What Guardian Catches

| Threat | Action | Example |
|--------|--------|---------|
| **Homograph attacks** | 🛑 BLOCK | Cyrillic/Greek lookalikes in URLs |
| **Pipe-to-shell** | ⚠️ WARN | `curl ... \| bash` patterns |
| **ANSI injection** | ⚠️ WARN | Terminal escape sequences |
| **Dotfile attacks** | 🛑 BLOCK | Writes to ~/.bashrc, ~/.ssh/, etc. |

## Quick Start

```bash
# Clone/download
cd ~/clawd/projects/shell-guardian

# Make executable
chmod +x guardian.sh

# Test it
./guardian.sh test

# Check a specific command
./guardian.sh check "curl https://example.com | bash"
```

## Installation

### Option 1: Manual Hook

Add to your `~/.zshrc`:

```bash
# Shell Guardian
_guardian_preexec() {
    local cmd="$1"
    [[ "${GUARDIAN:-1}" == "0" ]] && return 0
    if ! ~/clawd/projects/shell-guardian/guardian.sh check "$cmd"; then
        return 1
    fi
}
autoload -Uz add-zsh-hook
add-zsh-hook preexec _guardian_preexec
```

Then: `source ~/.zshrc`

### Option 2: Installer Script

```bash
./install.sh
# Follow the instructions it prints
```

## Usage

Once installed, Guardian runs invisibly on every command.

### Normal commands — silent:
```bash
$ ls -la
$ git status
$ docker ps
# No output from Guardian
```

### Suspicious command — blocked:
```bash
$ curl -sSL https://іnstall.example.com | bash

╔══════════════════════════════════════════════════════════╗
║  🛡️  SHELL GUARDIAN - BLOCKED                              ║
╚══════════════════════════════════════════════════════════╝

[CRITICAL] Homograph attack detected in URL
  URL: https://іnstall.example.com
  Found Cyrillic i (U+0456) that looks like 'i'
  This URL may redirect to a malicious server!

Bypass: prefix command with GUARDIAN=0
```

### Bypass (when you know what you're doing):
```bash
GUARDIAN=0 curl -sSL https://something.xyz | bash
```

## Commands

```bash
guardian.sh check "<command>"  # Analyze a command
guardian.sh test               # Run test suite
guardian.sh hook               # Output shell hook code
guardian.sh help               # Show help
```

## Configuration

Edit the `ALLOWED_PIPE_DOMAINS` array in `guardian.sh` to add trusted domains:

```bash
ALLOWED_PIPE_DOMAINS=(
    "get.docker.com"
    "sh.rustup.rs"
    "brew.sh"
    # Add your trusted domains here
)
```

## How It Works

1. **Shell hook** intercepts commands before execution (zsh `preexec`)
2. **URL extraction** finds any URLs in the command
3. **Homograph scan** checks hostnames for non-ASCII lookalikes
4. **Pattern matching** detects pipe-to-shell, dotfile attacks, ANSI sequences
5. **Decision**: BLOCK (exit 1), WARN (stderr, continue), or PASS (silent)

## Threat Detection Details

### Homographs Detected

| Character | Looks Like | Name | Codepoint |
|-----------|------------|------|-----------|
| а | a | Cyrillic a | U+0430 |
| е | e | Cyrillic ie | U+0435 |
| о | o | Cyrillic o | U+043E |
| і | i | Cyrillic i | U+0456 |
| с | c | Cyrillic es | U+0441 |
| р | p | Cyrillic er | U+0440 |
| х | x | Cyrillic ha | U+0445 |
| Α | A | Greek Alpha | U+0391 |
| ... and 20+ more | | | |

### Pipe-to-Shell Patterns

- `curl ... | bash`
- `wget ... | sh`
- `eval $(curl ...)`
- `bash <(curl ...)`

### Protected Dotfiles

- `~/.bashrc`, `~/.zshrc`, `~/.profile`
- `~/.ssh/authorized_keys`, `~/.ssh/config`
- `~/.gitconfig`, `~/.npmrc`, `~/.netrc`

## Philosophy

- **Local only** — No network calls, no telemetry
- **Zero dependencies** — Pure bash, works everywhere
- **Invisible when clean** — You forget it's there
- **Bypassable** — `GUARDIAN=0` for when you know what you're doing
- **Open source** — Read every line, trust nothing blindly

## v0.2 Features

- ✅ **External config file** (`config.yaml`) — customize without editing code
- ✅ **Audit logging** — track what Guardian blocked/warned
- ✅ **Status command** — see your configuration at a glance
- ✅ **50+ homograph characters** — Cyrillic, Greek, Armenian, and more
- ✅ **Insecure HTTP blocking** — blocks HTTP (not HTTPS) pipe-to-shell

### New Commands

```bash
guardian.sh status        # Show config, stats, protected files
guardian.sh log           # Show last 10 blocked/warned commands  
guardian.sh log 50        # Show last 50
```

### Configuration File

Create `config.yaml` next to `guardian.sh`:

```yaml
# Trusted domains (no warnings)
allowed_domains:
  - get.docker.com
  - sh.rustup.rs
  - brew.sh

# Files to protect from writes
protected_dotfiles:
  - .bashrc
  - .ssh/authorized_keys
  - .aws/credentials

# Logging
logging:
  enabled: true
  level: blocked  # all, blocked, warned, none
```

## Future Ideas (v0.3+)

- [ ] Integration with OpenClaw approval system
- [ ] Bash preexec support (without bash-preexec)
- [ ] Fish shell support
- [ ] Interactive mode (ask before proceeding)

---

*"Your browser protects you. Your terminal should too."*

— Orion ✨
