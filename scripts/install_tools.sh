#!/usr/bin/env bash
#
# install_tools.sh — install the full toolchain (recon + active + offensive)
#                    for the web-timeline pipeline.
#
# Strategy:
#   * Prefer Homebrew formulae (fast, prebuilt) for tools that ship one.
#   * Fall back to `go install` for the rest.
#   * Verify each binary at the end and print a status table.
#
# Safe to re-run: every step is idempotent (brew/go skip already-installed tools).
#
set -uo pipefail

GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'
log()  { printf '%s==>%s %s\n' "$YELLOW" "$RST" "$*"; }
ok()   { printf '%s ok %s %s\n' "$GREEN" "$RST" "$*"; }
warn() { printf '%s!!!%s %s\n' "$RED" "$RST" "$*"; }

# Where `go install` drops binaries.
GOBIN="$(go env GOPATH 2>/dev/null)/bin"
[ -d "$HOME/go/bin" ] && GOBIN="${GOBIN:-$HOME/go/bin}"
export PATH="$PATH:${GOBIN:-$HOME/go/bin}"

brew_install() {
  local formula="$1"
  if brew list --formula "$formula" >/dev/null 2>&1; then
    ok "$formula (brew, already installed)"
  else
    log "brew install $formula"
    brew install "$formula" >/dev/null 2>&1 && ok "$formula (brew)" || warn "$formula (brew failed)"
  fi
}

go_install() {
  local bin="$1" pkg="$2"
  if command -v "$bin" >/dev/null 2>&1; then
    ok "$bin (already installed)"
  else
    log "go install $pkg"
    go install "$pkg" >/dev/null 2>&1 && ok "$bin (go)" || warn "$bin (go install failed)"
  fi
}

# Build a tool from source with the pure-Go DNS resolver (CGO disabled).
# ProjectDiscovery's prebuilt/brew binaries use a cgo resolver that SIGSEGVs on
# recent macOS; a CGO_ENABLED=0 source build avoids that entirely. Always
# rebuilds so a broken binary earlier on PATH is superseded.
go_install_nocgo() {
  local bin="$1" pkg="$2"
  # Drop any broken Homebrew copy that would shadow the go build on PATH.
  brew list --formula "$bin" >/dev/null 2>&1 && \
    brew uninstall --ignore-dependencies "$bin" >/dev/null 2>&1
  log "CGO_ENABLED=0 go install $pkg"
  if CGO_ENABLED=0 go install "$pkg" >/dev/null 2>&1; then
    ok "$bin (go, cgo-free)"
  else
    warn "$bin (cgo-free go install failed)"
  fi
}

# --- 0. Prerequisites -------------------------------------------------------
command -v brew >/dev/null 2>&1 || { warn "Homebrew is required. https://brew.sh"; exit 1; }

log "Installing Go + native scanners via Homebrew"
brew_install go
brew_install nmap          # deep port/service/version scanning
brew_install libpcap       # naabu SYN-scan dependency
brew_install amass         # OWASP subdomain enumeration
brew_install exploitdb     # searchsploit — offline Exploit-DB for enrichment

# These ProjectDiscovery tools are safe from brew (no cgo resolver at runtime).
for f in subfinder nuclei katana; do
  brew_install "$f"
done

# gowitness (screenshots) + others live in brew too when available.
brew_install gowitness

# Offensive tier: web-app attack + password-cracking tools.
log "Installing web-app attack + cracking tools (active/offensive tiers)"
brew_install sqlmap        # SQL injection detection + exploitation
brew_install hydra         # online credential attacks
brew_install john-jumbo    # John the Ripper (jumbo) — hash cracking + unshadow
brew_install dalfox        # XSS scanning / confirmation

# Refresh PATH now that Go may have just been installed.
GOBIN="$(go env GOPATH 2>/dev/null)/bin"; export PATH="$PATH:$GOBIN"

# dnsx / httpx / naabu MUST be built cgo-free (see go_install_nocgo comment).
log "Building DNS/HTTP/port tools with the pure-Go resolver"
go_install_nocgo dnsx  github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go_install_nocgo httpx github.com/projectdiscovery/httpx/cmd/httpx@latest
go_install_nocgo naabu github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

log "Installing remaining tools via 'go install'"
go_install assetfinder github.com/tomnomnom/assetfinder@latest
go_install waybackurls  github.com/tomnomnom/waybackurls@latest
go_install gau          github.com/lc/gau/v2/cmd/gau@latest
# Fallbacks in case any brew formula was unavailable on this platform:
command -v subfinder >/dev/null 2>&1 || go_install subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
command -v nuclei    >/dev/null 2>&1 || go_install nuclei    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
command -v katana    >/dev/null 2>&1 || go_install katana    github.com/projectdiscovery/katana/cmd/katana@latest
# dalfox ships a Go package too — fall back to it if the brew formula was unavailable.
command -v dalfox    >/dev/null 2>&1 || go_install dalfox    github.com/hahwul/dalfox/v2@latest

# nuclei templates (idempotent; updates if already present).
if command -v nuclei >/dev/null 2>&1; then
  log "Updating nuclei templates"
  nuclei -update-templates -silent >/dev/null 2>&1 && ok "nuclei templates" || warn "nuclei templates update failed"
fi

# --- Verification -----------------------------------------------------------
echo
log "Verification"
tools=(nmap amass subfinder dnsx naabu httpx nuclei katana gowitness assetfinder waybackurls gau searchsploit sqlmap dalfox hydra john)
missing=0
for t in "${tools[@]}"; do
  if command -v "$t" >/dev/null 2>&1; then
    ok "$(printf '%-14s' "$t") $DIM$(command -v "$t")$RST"
  else
    warn "$(printf '%-14s' "$t") MISSING"
    missing=$((missing+1))
  fi
done

echo
if [ "$missing" -eq 0 ]; then
  ok "All tools installed. If any 'go install' tool is missing from PATH, add: export PATH=\"\$PATH:$GOBIN\""
else
  warn "$missing tool(s) missing — the pipeline will skip stages that need them and note it in the report."
fi
