# Shell Guardian 🛡️

A lightweight terminal security tool that catches dangerous commands before they execute.

## Features

- **Homograph Detection** — Spots Cyrillic/Greek lookalike characters hiding in commands (а→a, е→e, о→o)
- **Pipe-to-Shell Warnings** — Alerts on `curl|bash`, `wget|sh` patterns from untrusted sources
- **ANSI Escape Detection** — Catches terminal injection attacks hidden in output
- **Dotfile Attack Detection** — Warns about hidden executables and bashrc modifications
- **Smart Domain Allowlist** — Trusted sources (docker, rustup, brew, nvm, deno) pass through

## Install

```bash
./install.sh
```

This will:
1. Copy `guardian` to `~/.local/bin/`
2. Generate shell hooks for bash/zsh
3. Show you what to add to your shell config

## Usage

### Manual Check
```bash
guardian check "curl -fsSL https://example.com | bash"
```

### Test Suite
```bash
guardian test
```

### Get Shell Hook
```bash
guardian hook        # auto-detects shell
guardian hook bash   # explicit shell
guardian hook zsh
```

### Bypass When Needed
```bash
GUARDIAN=0 curl https://trusted.com/install.sh | bash
```

## How It Works

Shell Guardian uses `preexec` hooks to intercept commands before they run. When it detects something suspicious:

- **🚫 BLOCKED** — High-risk pattern, command is stopped
- **⚠️ WARNING** — Suspicious pattern, asks for confirmation
- **✅ ALLOWED** — Trusted domain, proceeds normally

## Risk Patterns

| Pattern | Risk Level | Example |
|---------|------------|---------|
| Cyrillic 'а' in domain | BLOCKED | `curl https://аpple.com` |
| Unknown pipe-to-shell | WARNING | `curl example.com \| bash` |
| ANSI escapes in URL | BLOCKED | URL with `\x1b[` sequences |
| Hidden dotfile exec | WARNING | `./...` or modifying `.bashrc` |

## Trusted Domains

These are allowed to use pipe-to-shell without warning:
- docker.com
- rustup.rs
- brew.sh / homebrew
- deno.land
- raw.githubusercontent.com (nvm, etc.)
- get.volta.sh

Edit `~/.local/bin/guardian` to customize.

## Philosophy

> "Trust but verify" — except for terminals, where it's "Verify, then maybe trust."

This tool exists because copy-pasting commands from the internet is dangerous. Even trusted-looking URLs can contain:
- Unicode lookalikes that redirect to malicious servers
- Hidden ANSI sequences that mask what's really running
- Innocent-looking scripts that modify your shell config

Shell Guardian adds a speed bump before disaster.

## Requirements

- Bash 4.0+ or Zsh 5.0+
- No external dependencies

## Uninstall

```bash
rm ~/.local/bin/guardian
# Remove the hook lines from your .bashrc or .zshrc
```

## License

MIT — Use it, modify it, share it.

---

Built with paranoia by Orion ✨
