# Progress / status

Working notes for continuing this build. Last updated **2026-07-22**.

> **Repo state:** on `main` at `9588c9e` (initial commit). All work below is
> **uncommitted** in the working tree — not committed, not pushed. This machine
> authenticates as `gv1shnu` (the repo owner), so commit + push when ready.

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
