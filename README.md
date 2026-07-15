# ceh-automation

A staged **domain reconnaissance pipeline**. Feed it one or more root domains and
it produces a normalized JSON dataset plus a browsable HTML report covering
subdomains, DNS, open ports/services, HTTP fingerprints, crawled content,
screenshots, vulnerability findings, and — for each CVE found — links to any
**public exploits / proof-of-concept code** that exist for it.

Use it two ways: a **CLI** (`recon.py`) for scripting and automation, or a
**local web dashboard** (`serve.py`) to launch scans from a form, watch them
stream live, and browse every past run.

> ⚖️ **Authorized use only.** Run this against domains you own or have explicit
> written permission to test (your lab, an in-scope bug-bounty program, a signed
> engagement). Active stages send real scan traffic and are gated behind
> `--active`. You are responsible for staying in scope and within the law.

## Pipeline

```
domains ─▶ 1 subdomains ─▶ 2 resolve ─▶ 3 ports* ─▶ 4 http probe ─▶ 5 crawl
        ─▶ 6 screenshots ─▶ 7 vulns* ─▶ 8 exploits ─▶  results.json + report.html
```

`*` = **active** stage (intrusive traffic) — only runs with `--active`.

| # | Stage        | Tools                              | Active |
|---|--------------|------------------------------------|:------:|
| 1 | subdomains   | subfinder, assetfinder, amass, crt.sh | no  |
| 2 | resolve      | dnsx                               | no     |
| 3 | ports        | naabu, nmap (`-sV`)                | **yes**|
| 4 | http_probe   | httpx                              | no     |
| 5 | crawl        | katana, waybackurls, gau           | no     |
| 6 | screenshots  | gowitness                          | no     |
| 7 | vulns        | nuclei                             | **yes**|
| 8 | exploits     | searchsploit, trickest/cve (GitHub PoCs) | no |

Stage 8 reads the CVEs nuclei attaches to each finding and looks up public
exploits for them (offline Exploit-DB via `searchsploit`, plus the community
`trickest/cve` GitHub PoC map), attaching the links to the report.

Any missing tool is detected and its stage is skipped (and noted in the report),
so the pipeline degrades gracefully.

## Setup

```bash
# 1. External recon tools (Homebrew + go install)
bash scripts/install_tools.sh

# 2. Python deps (use a virtualenv — modern macOS/Homebrew Python is
#    "externally managed" and blocks a bare pip install)
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt

# 3. Confirm what's installed
./.venv/bin/python recon.py --list-tools
```

The only Python dependencies are PyYAML, Jinja2 and Flask (for the dashboard);
all scanning is done by the external CLI tools. Replace `./.venv/bin/python`
with `python3` below if you installed the deps globally.

## Usage

```bash
# Passive recon (safe defaults — no intrusive traffic)
python3 recon.py example.com

# Full active pipeline (port + vuln scanning) — authorization required
python3 recon.py example.com --active

# Multiple targets from a file, custom config + output dir
python3 recon.py -f domains.txt --config config.yaml -o output --active

# Unattended / CI (skip the active-mode confirmation prompt)
python3 recon.py example.com --active --yes
```

## Web dashboard

Prefer a UI? Launch the dashboard and drive everything from the browser:

```bash
./.venv/bin/python serve.py            # http://127.0.0.1:8765
```

- **Dashboard** — every past run as a card (targets, counts, severity, exploits)
- **New scan** — enter domains, toggle active mode (with an authorization check), submit
- **Live run** — watch the stage log stream in real time (server-sent events)
- **Report view** — the full HTML report, framed in-app

It reads the same `output/` directory the CLI writes, so CLI and dashboard stay
in sync. It binds to `localhost` and runs Flask's development server — fine for
personal use, but don't expose it on an untrusted network (it can launch scans).

## Output

Each run writes to `output/<target>/<timestamp>/`:

```
results.json          # normalized, machine-readable dataset
report.html           # styled, browsable report (open in a browser)
subdomains/ resolve/ ports/ http_probe/ crawl/
screenshots/ vulns/ exploits/   # per-stage raw output + command logs (audit trail)
```

`results.json` is written incrementally after every stage, so long runs are
crash-safe and inspectable mid-flight.

## Configuration

All behaviour is tunable via [`config.yaml`](config.yaml): stage toggles, thread
counts, rate limits, port ranges, nuclei severities/tags, crawl depth, and
per-stage timeouts. CLI flags (`--active`, `-o`) override the config.

## Layout

```
recon.py                     # CLI entrypoint
serve.py                     # web dashboard entrypoint
config.yaml                  # default configuration
requirements.txt
scripts/install_tools.sh     # toolchain installer
pipeline/
  config.py  models.py  runner.py  orchestrator.py  util.py
  stages/    # one module per pipeline stage (subdomains … exploits)
  report/    # HTML report renderer + Jinja template
  web/       # Flask dashboard (app + templates)
```

## Troubleshooting

**`dnsx` / `httpx` / `naabu` crash with `SIGSEGV ... during cgo execution`.**
ProjectDiscovery's prebuilt (and Homebrew) binaries use a cgo-based DNS resolver
that segfaults on recent macOS. `scripts/install_tools.sh` already works around
this by rebuilding those three from source with the pure-Go resolver:

```bash
CGO_ENABLED=0 go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
CGO_ENABLED=0 go install github.com/projectdiscovery/httpx/cmd/httpx@latest
CGO_ENABLED=0 go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

Remove any Homebrew copies afterward (`brew uninstall dnsx httpx naabu`) so the
working `~/go/bin` builds win on `PATH`.

**`go install` tools not found.** Ensure the Go bin dir is on `PATH`:
`export PATH="$PATH:$(go env GOPATH)/bin"`.

**A stage is skipped as "missing tool".** Run `recon.py --list-tools`; the port
scan and vuln stages also require `--active`.
