# Methodology

How `web-timeline` maps a web-application penetration-testing workflow onto an
automated, tiered pipeline — the reasoning behind each phase, the tools chosen,
what each stage produces, and where the automation stops being trustworthy.

This document is deliberately honest about limitations. Automated offensive
tooling that overstates its coverage is dangerous; the value is in a repeatable,
auditable methodology, not in pretending to replace a tester.

---

## The tiered model

Web-app testing escalates in intrusiveness: you *look*, then you *probe*, then
you *exploit*. Collapsing those into one "run everything" switch is how people
accidentally attack out-of-scope systems. `web-timeline` makes the escalation
explicit and enforced.

| Tier | Intent | Reversibility | Gate |
|------|--------|---------------|------|
| **passive** | Understand the target without touching it like an attacker | Fully safe | default |
| **active** | Find weaknesses by probing | Low impact, but detectable/logged | `--active` + confirm |
| **offensive** | Prove impact by exploiting | Can extract data, lock accounts, alter state | `--exploit` + confirm |

The gate is implemented in the pipeline core (`Stage.run` → `Config.stage_allowed`)
so it cannot be bypassed by a UI toggle, a crafted web request, or a misconfigured
template. `--exploit` implies `--active`; there is no way to reach an offensive
stage from a passive run.

---

## Phase 1 — Passive reconnaissance

**Objective:** build a picture of the attack surface using only public data and
standard requests — nothing an intrusion-detection system would flag as an attack.

| Stage | Method | Tools | Produces |
|-------|--------|-------|----------|
| `subdomains` | Passive DNS aggregation + certificate-transparency log mining | subfinder, assetfinder, amass, crt.sh | `Host` list |
| `resolve` | DNS resolution to drop dead names, keep A/CNAME | dnsx | resolved hosts |
| `http_probe` | HTTP(S) fingerprinting: status, title, tech, server, TLS, CDN | httpx | `HttpEndpoint` list |
| `crawl` | Live crawl + historical URL harvesting (the parameter source for injection stages) | katana, waybackurls, gau | `CrawlUrl` list |
| `screenshots` | Headless rendering for fast visual triage | gowitness | endpoint screenshots |
| `exploits` | For each CVE already known, look up public exploits — **pointers only** | searchsploit, trickest/cve | `Exploit` pointers |

**Why these tools:** the ProjectDiscovery suite is the de-facto standard for
fast, scriptable, JSON-emitting recon. crt.sh needs no API key and surfaces
subdomains that never appear in DNS brute-forcing. `gau`/`waybackurls` recover
historical parameterized URLs — the single most valuable input to the SQLi/XSS
stages, because they reveal parameters the live site no longer links to.

**Limitations:** passive discovery is only as complete as public data. crt.sh is
flaky (handled by degrading quietly). `http_probe` is classed passive because a
normal HTTP GET is not an attack, but it *is* a request to the target — true
zero-touch OSINT would stop at `subdomains`/`resolve`.

---

## Phase 2 — Active scanning & detection

**Objective:** find weaknesses by probing. This tier sends real traffic and is
detectable; it requires `--active`.

| Stage | Method | Tools | Produces |
|-------|--------|-------|----------|
| `ports` | Fast connect-scan, then service/version detection on open ports | naabu, nmap `-sV` | `Service` list |
| `vulns` | Templated vulnerability/misconfiguration/exposure scanning | nuclei | `Finding` list (with CVEs) |
| `sqli_detect` | Test parameterized URLs for SQL injection (detection only) | sqlmap `--batch --smart` | high-severity `Finding` per injectable param |
| `xss_detect` | Test parameters for reflected/verified XSS | dalfox | `Finding` per XSS candidate |

**Method notes:** detection stages consume the crawl output — any URL with a
query string is a candidate. sqlmap runs per-URL so results map cleanly back to
the exact injection point; dalfox runs in bulk file mode. Both cap the number of
URLs tested (`sqli_max_urls`, `xss_max_urls`) to bound runtime.

**Detection vs. exploitation split:** `sqli_detect`/`xss_detect` deliberately
stop at *confirming a parameter is injectable*. Extraction/triggering is a
separate, higher-tier stage. This mirrors how a careful tester works — confirm
the vulnerability class first, exploit deliberately second — and it keeps the
active tier from crossing into data extraction.

**Limitations:** templated and heuristic detection produces candidates, not
proof. nuclei coverage depends on template freshness. sqlmap `--level`/`--risk`
default low (1/1) for speed — raise them for depth at the cost of time and noise.

---

## Phase 3 — Offensive exploitation

**Objective:** prove impact. This tier extracts data, guesses credentials, and
executes exploits; it requires `--exploit` and written authorization.

| Stage | Method | Tools | Produces |
|-------|--------|-------|----------|
| `sqli_exploit` | Resume confirmed injections, extract data (bounded rows) | sqlmap `--dump` | `Loot` (dumped tables) |
| `xss_confirm` | Headless-verify payloads actually fire; optional blind-XSS callback | dalfox | `Loot` (triggered-payload proof) |
| `auth_attack` | Online password guessing against discovered login surfaces | hydra | validated `Credential`s |
| `exploit_run` | Fire vetted CVE templates; stage PoCs + MSF script for review | nuclei (+ searchsploit/MSF) | `Loot` (exploit proof) + staged artifacts |
| `crack` | Extract hashes from dumps, identify type, crack | John the Ripper | cracked `Credential`s |

**The SQLi → crack chain** is the flagship: `sqli_exploit` reuses sqlmap's cached
session (no re-detection) to dump tables into CSV; `crack` walks those CSVs,
heuristically pulls hash-shaped values (bcrypt / MySQL / md5 / sha1 / sha256),
pairs each with a username-ish column, and feeds John. Extraction proves the
vulnerability; cracking proves the consequence.

**`auth_attack` discovery** is heuristic by necessity: HTTP-basic targets are any
endpoint that answered `401`; WordPress `wp-login.php` has a known form spec;
other form logins require a user-supplied `auth_form` hydra spec. Default
wordlists are intentionally tiny common sets — this stage is a proof-of-concept
for credential attacks, not a serious brute-forcer until pointed at real lists.

**`exploit_run` and the untrusted-code boundary.** This is the most important
safety decision in the project. Public PoC code (from arbitrary GitHub repos) is
untrusted: it can be backdoored, can compromise the *operator's* machine, or can
damage the target unpredictably. So automated exploitation runs **only** through
vetted, declarative nuclei templates. The GitHub/Exploit-DB PoCs and a generated
Metasploit resource script are **staged for manual review** — fetched/organized,
never auto-executed. Inverting this (blind auto-detonation of internet code) was
explicitly declined even under a "run everything" directive, because no competent
operator executes unread code unattended.

**Bounded by default.** `sqlmap_dump_max_rows` caps extraction; `--os-shell`
(OS command execution) and `xss_blind_callback` (out-of-band interaction) are
opt-in config flags, off by default. The offensive tier is full-capability but
not needlessly destructive.

---

## Data model

Every stage normalizes native tool output into shared dataclasses, so the report
and aggregator are tool-agnostic:

`Host` · `Service` · `HttpEndpoint` · `CrawlUrl` · `Finding` · `Exploit` ·
`Credential` · `Secret` · `Loot` · `StageRun`

`Credential`, `Secret`, and `Loot` are the offensive-tier spine: cracked/guessed
logins, leaked keys, and references to extracted artifacts. They flow into
`results.json` and lead the HTML report.

---

## Known limitations (consolidated)

1. **Parsers track tool schemas.** Best-effort parsing; a major tool version bump
   can silently reduce coverage until updated. Recorded fixtures + parser tests
   are on the roadmap.
2. **Sequential execution.** Stages run in topological order but not yet
   concurrently, though every stage already declares its `depends_on`.
3. **False positives survive detection.** Confirmation stages reduce them; human
   review is still required before reporting.
4. **Login-form coverage is partial** (basic-auth + WordPress + configured specs).
5. **No network-side scope enforcement.** Tiers gate intent, not reachability —
   staying in scope is the operator's responsibility.
6. **Offensive stages need the tools installed and authorization given** — they
   self-skip loudly otherwise, which is a feature, not a bug.

---

## Roadmap → maturity

- **Surface-wideners:** `osint_harvest` (real userlists for `auth_attack`),
  `js_recon` (secrets from JS), `content_discovery` (ffuf), `param_discovery`
  (arjun) — each feeds the existing offensive stages more attack surface.
- **Concurrent DAG execution** of independent branches (deps already declared).
- **`--resume`** (incremental writes already make this cheap) and **run-to-run
  diffing** for recurring authorized monitoring.
- **Recorded fixtures + CI** (ruff / mypy / pytest, offline) so tool-schema drift
  is caught, not absorbed.
- **Packaging** as an installable console script with pinned dependencies and
  recorded external-tool versions per run.
