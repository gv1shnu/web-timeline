# Progress / status

Working notes for continuing this build. Last updated **2026-08-09**.

> **Repo state:** on `main` at `7580d2b` ("add offensive side"). Uncommitted in
> the working tree on top of that: an in-progress `exploit_run` MSF
> module-resolution feature (see "In flight" below) **and** the new
> `correlate` stage described in this update. Nothing has been committed this
> session — explicitly asked not to.

---

## 2026-08-09 session — pre-exploitation correlation

**Why:** exploitation itself is meant to be carried out by approved human
professionals, not this pipeline. So the highest-leverage automation work is
maximizing the *pre-exploitation* picture — connecting the isolated facts
every stage already collects into compound, chained leads — so a human's
first move is obvious before they ever touch the offensive tier.

**Added: `correlate` stage** (`pipeline/stages/correlate.py`) — passive tier,
zero external tools, zero additional target traffic. Runs after `exploits`,
before the offensive stages. Six heuristics, each producing an `Insight`
(new model: `id/title/category/severity/confidence/hosts/evidence/rationale/
next_step` — every insight ends in an explicit human verification step, never
an automated trigger):

1. `subdomain-takeover` — dangling CNAME fingerprinted against ~30 claimable
   third-party services.
2. `sensitive-exposure` — crawled URLs matching VCS/env/backup/key/debug/
   admin/API-schema path patterns.
3. `injection-surface` — query-parameter *names* matching SSRF/redirect,
   LFI/RFI, IDOR, command-injection conventions.
4. `exposed-service` — DB/management ports directly reachable, escalated when
   the same host is also CDN-fronted (origin-exposure signal).
5. `shadow-it` — internal-sounding hostnames (staging/CI/admin/observability)
   live on the public internet.
6. `vuln-rollup` — hosts with ≥2 CVE-tagged findings rolled into one
   prioritized target with an exploit-availability tally.

Wired end-to-end: `models.py` (`Insight`, `ReconResults.insights`, summary
counts), `stages/__init__.py` (STAGE_CLASSES order), `config.py`/`config.yaml`
(`correlate` toggle, `correlate_max_evidence`, timeout), and a new report
section (`report.html.j2`, amber-accented, right above the offensive-results
section). Smoke-tested standalone against synthetic `ReconResults` (all 6
heuristics fire correctly) and the full CLI still runs (`--list-tools`
unaffected).

**Also fixed while reading the codebase:** `config.yaml` was missing the
`exploit_run_msf_resolve` key that `config.py`/`exploit_run.py` already
supported (the in-flight MSF-resolution feature — see "In flight" below).

**Deliberately not done this session** (would raise complexity meaningfully —
good stopping point per instruction to pause and introspect before going
further):
- No new network calls added (no CISA KEV / EPSS / NVD enrichment yet, though
  `exploits`/`vuln-rollup` are the natural place for it — see Backlog).
- No `HttpEndpoint.headers` capture (would let `correlate` add a
  missing-security-headers heuristic; `http_probe`/httpx doesn't capture
  headers today).
- No js_recon / secrets-in-JS stage (the `Secret` model already exists but
  nothing populates it yet).

## In flight (uncommitted, from before this session)
`exploit_run` gained Metasploit module resolution: `msfconsole search
cve:<id>` against the *local* module DB (no target traffic) to turn CVE
findings into concrete candidate MSF modules, staged for manual review —
never auto-fired. Touches `pipeline/stages/exploit_run.py`, `pipeline/
runner.py` (tool_path now prefers the Go-built cgo-free binaries),
`scripts/install_tools.sh` (gowitness via `go install`, Metasploit via brew
cask), README/METHODOLOGY. This was functionally complete except the
`config.yaml` doc gap fixed above.

---

## Done

**Foundation (Phase 0)**
- Three-tier gate `passive < active < offensive`, enforced in the pipeline core
  (`Stage.run` → `Config.stage_allowed`) — not just the UI.
- `--exploit` CLI flag (implies `--active`) with an escalated confirmation prompt.
- **Server-side authorization** in the Flask `/scan` endpoint (previously the
  authorization check was client-side JS only — a direct POST bypassed it).
- `Stage` contract gains `tier` and `depends_on`; new models `Credential`,
  `Secret`, `Loot`; `ReconResults.offensive`.

**Active-tier detectors**
- `sqli_detect` (sqlmap `--batch --smart`), `xss_detect` (dalfox).

**Offensive-tier stages (gated behind `--exploit`)**
- `sqli_exploit` — sqlmap `--dump`, bounded rows → `Loot`.
- `xss_confirm` — dalfox headless verification (+ optional blind callback) → proof `Loot`.
- `auth_attack` — hydra (HTTP-basic + WordPress/form) → validated `Credential`s.
- `exploit_run` — nuclei fires vetted CVE templates; GitHub/EDB PoCs + a Metasploit
  resource script are **staged for review, never auto-executed**.
- `crack` — harvests hashes from SQLi dumps, John cracks them → `Credential`s.

**Report / UX**
- HTML report leads with an **Offensive results** section (credentials / loot /
  secrets) + `OFFENSIVE` badge + summary cards; CLI summary shows the tallies.

**Docs / config / tooling**
- README rewritten (tiers, 15-stage table, limitations); `docs/METHODOLOGY.md`
  deep-dive; `config.yaml` documents every new knob; `install_tools.sh` installs
  sqlmap/dalfox/hydra/john; renamed `ceh-automation` → `web-timeline` (v0.2.0).

## Verified (smoke tests, this session)
- Tier gating matrix: passive/active runs never reach offensive stages; only
  `--exploit` unlocks them. 15 stages; config round-trips; toggles match 1:1.
- Parsers: dalfox JSON (array/JSONL/junk), crack hash-shape detection + CSV
  username pairing, hydra credential lines, exploit_run staging artifacts.
- Report renders offensive loot/credentials/secrets end-to-end.

## Pipeline order (current)
```
subdomains → resolve → ports → http_probe → crawl → screenshots
  → vulns → sqli_detect → xss_detect → exploits
  → sqli_exploit → xss_confirm → auth_attack → exploit_run → crack
```

---

## Backlog (not started)
1. **Surface-wideners** (feed the offensive stages more attack surface):
   `osint_harvest` (theHarvester → real userlists for `auth_attack`), `js_recon`
   (secrets), `content_discovery` (ffuf), `param_discovery` (arjun), `cms_scan` (wpscan).
2. **Concurrent DAG execution** — every stage already declares `depends_on`;
   execution is still sequential (a valid topological order). Needs thread-safe
   result merges before parallelizing.
3. **`--resume`** (incremental `results.json` writes already make this cheap) and
   **run-to-run diffing** (added/removed subdomains, ports, findings).
4. **Recorded parser fixtures + CI** (ruff / mypy / pytest, offline).
5. **Packaging** — `pyproject.toml` + console-script entry point, pinned deps,
   record resolved external-tool versions per run.

## Key design decisions (don't regress these)
- **Tier gate is enforced in the core**, not the UI. Any new stage must set its
  `tier` correctly (`active`/`offensive`) or it defaults to passive.
- **`exploit_run` never auto-executes untrusted PoCs.** Auto-run is vetted engines
  only (nuclei); third-party PoCs are staged. This is deliberate — do not "fix" it
  into fetch-and-run.
- **Offense is bounded by default:** dump-row caps, URL caps, hash caps; sqlmap
  `--os-shell` and blind-XSS callback are opt-in config flags, off by default.

## Files touched (for whoever picks this up)
- Modified: `README.md`, `config.yaml`, `recon.py`, `pipeline/__init__.py`,
  `config.py`, `models.py`, `orchestrator.py`, `stages/__init__.py`, `stages/base.py`,
  `report/templates/report.html.j2`, `web/app.py`, `web/templates/new_scan.html`,
  `scripts/install_tools.sh`.
- New: `pipeline/stages/{sqli,xss,auth,crack,exploit_run}.py`,
  `docs/METHODOLOGY.md`, `docs/PROGRESS.md`.
