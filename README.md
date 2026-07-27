# web-timeline

A staged, **tiered web-application offensive-security pipeline**. Feed it target
domains and it runs an end-to-end workflow — passive reconnaissance → active
scanning & enumeration → **exploitation** — producing a normalized JSON dataset
and a browsable HTML report that leads with impact: extracted credentials,
dumped data, triggered payloads, and confirmed CVEs.

It orchestrates best-in-class external tools (ProjectDiscovery suite, sqlmap,
dalfox, hydra, nuclei, John the Ripper) behind one uniform stage interface, a
single typed result model, and a strict **three-tier safety gate**.

Use it two ways: a **CLI** (`recon.py`) for scripting/automation, or a **local
web dashboard** (`serve.py`) to launch scans, watch them stream live, and browse
past runs.

> ⚖️ **Authorized use only.** Run this against systems you own or have explicit
> written permission to test (your lab, an in-scope bug-bounty program, a signed
> engagement). Active and offensive tiers send real attack traffic. You are
> responsible for staying in scope and within the law.

---

## Tiered execution model

Every stage declares a **tier**. A run has a ceiling; a stage only executes if
its tier is at or below that ceiling. The ceiling is raised by explicit opt-in,
and each escalation requires authorization — enforced in the pipeline core **and
server-side** in the dashboard (not merely a disabled UI control).

| Tier | Ceiling flag | What it does | Traffic |
|------|--------------|--------------|---------|
| **passive** | *(default)* | OSINT, DNS, HTTP fingerprint, crawl, screenshots, exploit lookup | nothing an IDS would flag as an attack |
| **active** | `--active` | port/vuln scanning, SQLi/XSS **detection** | real scan probes |
| **offensive** | `--exploit` | data extraction, credential attacks, CVE exploitation | real attacks |

`--exploit` implies `--active`. Higher-tier stages **self-skip** (and say so in
the report) when the ceiling is lower — so a passive run can never reach an
offensive stage.

```
                     ┌── passive ──────────────────────────────────────────────┐
domains ─▶ subdomains ─▶ resolve ─▶ http_probe ─▶ crawl ─▶ screenshots ─▶ exploits(lookup)
                     └─────────────────┬──────────────┬────────────────────────┘
        ┌── active (--active) ─────────┴──────────────┴───────────────┐
        │  ports    vulns    sqli_detect    xss_detect                │
        └──────────────┬──────────────┬───────────────┬───────────────┘
        ┌── offensive (--exploit) ─────┴──────────────┴───────────────┐
        │  sqli_exploit   xss_confirm   auth_attack   exploit_run   crack
        └──────────────────────────────────────────────────────────────┘
```

---

## Stages, methods & tools

| # | Stage | Tier | Method | Tools |
|---|-------|------|--------|-------|
| 1 | `subdomains` | passive | subdomain discovery via passive sources + certificate transparency | subfinder, assetfinder, amass, crt.sh |
| 2 | `resolve` | passive | DNS resolution; keeps only live hosts, records A/CNAME | dnsx |
| 3 | `ports` | active | fast TCP port scan + service/version detection | naabu, nmap `-sV` |
| 4 | `http_probe` | passive | HTTP(S) probing, fingerprint, TLS/CDN metadata | httpx |
| 5 | `crawl` | passive | active crawl + historical URL harvesting (params for later stages) | katana, waybackurls, gau |
| 6 | `screenshots` | passive | headless screenshots of live endpoints | gowitness |
| 7 | `vulns` | active | templated vulnerability/misconfig scanning | nuclei |
| 8 | `sqli_detect` | active | tests parameterized URLs for SQL injection | sqlmap `--batch --smart` |
| 9 | `xss_detect` | active | tests parameters for reflected/verified XSS | dalfox |
| 10 | `exploits` | passive | maps each CVE → public exploits/PoCs (pointers only) | searchsploit, trickest/cve |
| 11 | `sqli_exploit` | **offensive** | resumes confirmed injections and **extracts data** (bounded) | sqlmap `--dump` |
| 12 | `xss_confirm` | **offensive** | headless-verifies payloads (+ optional blind-XSS callback) | dalfox |
| 13 | `auth_attack` | **offensive** | online password guessing on login surfaces | hydra (http-basic, wp/form) |
| 14 | `exploit_run` | **offensive** | fires vetted CVE templates; stages PoCs + MSF script | nuclei (+ searchsploit/MSF artifacts) |
| 15 | `crack` | **offensive** | extracts hashes from dumps and cracks them | John the Ripper |

**Attack chains that emerge:**
- **SQLi:** `sqli_detect` → `sqli_exploit` (dump) → `crack` → cracked credentials
- **XSS:** `xss_detect` → `xss_confirm` (triggered-payload proof)
- **Auth:** `auth_attack` → validated credentials
- **CVE:** `vulns` → `exploits` (lookup) → `exploit_run` (vetted execution)

Any missing tool is detected and its stage is skipped (and noted in the report),
so the pipeline **degrades gracefully** rather than crashing.

---

## Design

- **Uniform stage contract.** Every stage subclasses `Stage` with a declared
  `name`, `tier`, `tools`, and `depends_on`, and one `execute()` method. The base
  class handles tier gating, tool-availability skips, timing, and bookkeeping.
- **One typed result model.** Stages parse native tool output into shared
  dataclasses (`Host`, `Service`, `HttpEndpoint`, `Finding`, `Exploit`,
  `Credential`, `Secret`, `Loot`) so the aggregator and report never care which
  tool produced a fact.
- **Safe tool boundary.** Every external call is an argument list (never a shell
  string), runs under an enforced per-stage timeout, distinguishes timeout /
  missing-tool / non-zero-exit, and writes an audit trail (`*.cmd`, `*.stdout`,
  `*.stderr`) per stage.
- **Crash-safe.** `results.json` is rewritten after every stage, so a long run is
  inspectable and resumable-by-hand mid-flight.
- **Bounded offense.** Extraction and attack volume are capped by config
  (row limits, URL caps, hash caps); the most destructive actions (sqlmap
  `--os-shell`, blind-XSS callbacks) are **opt-in flags**, off by default.

---

## Setup

```bash
# 1. External tools (Homebrew + go install; sqlmap/dalfox/hydra/john via pkg mgr)
bash scripts/install_tools.sh

# 2. Python deps (use a virtualenv)
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt

# 3. Confirm what's installed (per-tool availability)
./.venv/bin/python recon.py --list-tools
```

The only Python dependencies are PyYAML, Jinja2 and Flask; all scanning and
exploitation is done by the external CLI tools.

---

## Usage

```bash
# Passive recon (safe default — no attack traffic)
python3 recon.py example.com

# Active tier: scanning + SQLi/XSS detection — authorization required
python3 recon.py example.com --active

# Offensive tier: full exploitation (dump, crack, auth, CVE) — WRITTEN authorization
python3 recon.py example.com --exploit

# Multiple targets, custom config + output dir, unattended (skip prompt)
python3 recon.py -f domains.txt --config config.yaml -o output --exploit --yes
```

Both `--active` and `--exploit` show a typed confirmation prompt (escalated
wording for offensive) unless `--yes` is passed.

### Web dashboard

```bash
./.venv/bin/python serve.py            # http://127.0.0.1:8765
```

Dashboard of past runs · new-scan form (with a **server-enforced** authorization
check for active/offensive) · live streaming stage log (SSE) · in-app report.
Binds to `localhost` and runs Flask's dev server — don't expose it on an
untrusted network (it can launch attacks).

---

## Output

Each run writes to `output/<target>/<timestamp>/`:

```
results.json     # normalized, machine-readable dataset (incl. credentials/loot)
report.html      # styled report; leads with offensive results when present
subdomains/ resolve/ ports/ http_probe/ crawl/ screenshots/ vulns/
sqli_detect/ xss_detect/ exploits/ sqli_exploit/ xss_confirm/
auth_attack/ exploit_run/ crack/     # per-stage raw output + command audit trail
```

The report surfaces **credentials**, **extracted loot** (with links to dumped
artifacts), **leaked secrets**, findings by severity, screenshots, endpoints,
services, hosts, and a per-stage execution log.

---

## Configuration

All behaviour is tunable via [`config.yaml`](config.yaml): tier/stage toggles,
threads, rate limits, port ranges, nuclei severities/tags, crawl depth, per-stage
timeouts, and per-tool knobs — sqlmap level/risk and dump-row cap, dalfox
workers/blind callback, hydra wordlists/form spec, John wordlist, exploit_run
engines. CLI flags (`--active`, `--exploit`, `-o`) override config.

---

## Limitations & honest caveats

- **Not a replacement for a human tester.** It automates a *methodology*, not
  judgment. Detection stages produce candidates; confirmation stages reduce but
  don't eliminate false positives. Review before you report.
- **Tool-dependent.** Output parsing is best-effort against each tool's current
  schema; a major tool version bump can change output and silently reduce
  coverage until parsers are updated. (Recorded fixtures/parser tests are on the
  roadmap.)
- **`auth_attack` login discovery is heuristic** — reliable for HTTP-basic (401)
  and WordPress; other form logins need an `auth_form` spec. Default wordlists
  are intentionally tiny (point them at real lists for a serious run).
- **`exploit_run` never auto-executes untrusted PoCs by design.** Automated
  exploitation runs only through vetted nuclei templates; GitHub/Exploit-DB PoCs
  and a Metasploit resource script are **staged for manual review**, not
  detonated. This is a deliberate trust boundary, not an oversight.
- **Execution is currently sequential** (a valid topological order). Concurrent
  DAG execution of independent branches is designed (every stage declares
  `depends_on`) but not yet enabled.
- **Scope safety is opt-in, not enforced network-side.** The tiers gate *intent*;
  they do not stop you from pointing it at something you shouldn't. That's on you.

---

## Roadmap

Surface-wideners (`osint_harvest`, `js_recon`, `content_discovery`,
`param_discovery`), concurrent DAG execution, `--resume`, run-to-run diffing,
recorded parser fixtures + CI (ruff/mypy/pytest), and packaging as an installable
console script. See [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) for the
per-phase methodology, tool rationale, and detailed limitations.

---

## Layout

```
recon.py                     # CLI entrypoint
serve.py                     # web dashboard entrypoint
config.yaml                  # default configuration
scripts/install_tools.sh     # toolchain installer
pipeline/
  config.py  models.py  runner.py  orchestrator.py  util.py
  stages/    # one module per stage (subdomains … exploit_run, crack)
  report/    # HTML report renderer + Jinja template
  web/       # Flask dashboard (app + templates)
docs/
  METHODOLOGY.md             # phases, methods, tools, limitations (deep dive)
```
