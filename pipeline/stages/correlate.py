"""Stage 10 — cross-stage vulnerability correlation (passive, zero traffic).

Every other passive/active stage produces isolated facts: a host, an open
port, a CVE-tagged finding, a crawled URL. On their own those are a checklist.
The value a human pentester adds early is connecting them — "this dangling
CNAME + this exposed backup file + these three CVEs on the same host is one
attack path, not four unrelated bullet points."

This stage does exactly that correlation, entirely offline, over data the
pipeline already collected (no new requests to the target — it is the
capstone of the *pre-exploitation* phase, not another probe). It never
attacks anything and never feeds `--exploit` stages automatically; every
Insight it produces ends with an explicit human next step for an authorized
tester to verify manually.

Heuristics:
  * subdomain-takeover  — dangling CNAME to a claimable third-party service
  * sensitive-exposure  — crawled URLs matching known-sensitive path patterns
    (VCS metadata, env files, backups, admin panels, debug/API-surface endpoints)
  * injection-surface   — query parameters whose *names* strongly suggest
    SSRF/open-redirect, LFI/RFI, IDOR or command-injection sinks
  * exposed-service      — database/management ports reachable directly,
    cross-referenced against CDN fronting on the same host
  * shadow-it            — internal-sounding hostnames (staging/admin/CI/
    observability tooling) that are nonetheless live on the public internet
  * vuln-rollup           — hosts carrying multiple CVE-tagged findings,
    rolled into one prioritized target instead of N flat rows
  * exploit-route         — per-host, ranks the confirmed/candidate findings
    already on record (sqli, xss, CVE+public-exploit, login surfaces) into a
    recommended order of *this pipeline's own offensive-tier stages* — a
    plan, never an execution trigger
"""

from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import parse_qs, urlsplit

from ..models import Insight, StageRun
from .base import Stage, StageContext

# -- subdomain takeover: CNAME target -> (service label, base confidence) ----
TAKEOVER_FINGERPRINTS: dict[str, tuple[str, str]] = {
    "github.io": ("GitHub Pages", "high"),
    "herokuapp.com": ("Heroku", "high"),
    "herokudns.com": ("Heroku DNS", "high"),
    "s3.amazonaws.com": ("AWS S3", "high"),
    "s3-website": ("AWS S3 website endpoint", "high"),
    "cloudfront.net": ("AWS CloudFront", "medium"),
    "azurewebsites.net": ("Azure App Service", "high"),
    "azure-api.net": ("Azure API Management", "medium"),
    "cloudapp.net": ("Azure Cloud Service", "medium"),
    "trafficmanager.net": ("Azure Traffic Manager", "medium"),
    "myshopify.com": ("Shopify", "high"),
    "unbouncepages.com": ("Unbounce", "high"),
    "wordpress.com": ("WordPress.com", "medium"),
    "ghost.io": ("Ghost(Pro)", "medium"),
    "surge.sh": ("Surge.sh", "high"),
    "bitbucket.io": ("Bitbucket Pages", "high"),
    "tumblr.com": ("Tumblr", "medium"),
    "zendesk.com": ("Zendesk", "medium"),
    "statuspage.io": ("Statuspage", "medium"),
    "wpengine.com": ("WP Engine", "medium"),
    "pantheonsite.io": ("Pantheon", "medium"),
    "readme.io": ("ReadMe", "medium"),
    "readthedocs.io": ("Read the Docs", "low"),
    "webflow.io": ("Webflow", "medium"),
    "netlify.app": ("Netlify", "high"),
    "vercel.app": ("Vercel", "high"),
    "firebaseapp.com": ("Firebase Hosting", "high"),
    "appspot.com": ("Google App Engine", "medium"),
    "helpscoutdocs.com": ("Help Scout Docs", "medium"),
    "intercom.help": ("Intercom", "medium"),
    "ngrok.io": ("ngrok", "medium"),
    "uservoice.com": ("UserVoice", "medium"),
    "freshdesk.com": ("Freshdesk", "medium"),
    "cargocollective.com": ("Cargo Collective", "medium"),
    "fastly.net": ("Fastly", "low"),
}

# -- sensitive crawl-URL path patterns: category -> (regex, severity, why) ---
EXPOSURE_PATTERNS: dict[str, tuple[re.Pattern, str, str]] = {
    "vcs-exposure": (
        re.compile(r"/\.(git|svn|hg)(/|$)", re.I), "critical",
        "Version-control metadata is web-reachable — commonly reconstructable into "
        "full source history, and history often contains rotated-but-not-revoked "
        "credentials."),
    "env-secrets": (
        re.compile(r"/\.env(\.[\w.-]+)?(\?|$)", re.I), "critical",
        "An environment file is web-reachable — these routinely hold DB "
        "connection strings, API keys and signing secrets in plaintext."),
    "backup-exposure": (
        re.compile(r"\.(bak|old|orig|swp|sql|sql\.gz|dump|tar\.gz|tgz|zip|7z)(\?|$)", re.I),
        "high",
        "A backup/archive artifact is web-reachable — may contain full source "
        "or a database dump."),
    "credential-file": (
        re.compile(r"(\.aws/credentials|id_rsa$|id_dsa$|\.pem(\?|$)|\.ppk(\?|$)|\.htpasswd(\?|$)|\.npmrc(\?|$))", re.I),
        "critical",
        "A key/credential-shaped filename is web-reachable."),
    "debug-endpoint": (
        re.compile(r"(/debug(/|$)|/_profiler|/trace\.axd|/elmah\.axd|/actuator(/|$)|/__debug__)", re.I),
        "high",
        "A debug/diagnostics endpoint is reachable — these frequently leak stack "
        "traces, config, or (Spring Boot Actuator env/heapdump, Werkzeug console) "
        "provide a direct path to RCE."),
    "admin-panel": (
        re.compile(r"(/wp-admin/|/wp-login\.php|/phpmyadmin|/administrator/|/manager/html|/cpanel|/adminer)", re.I),
        "medium",
        "An administrative interface is reachable — a natural target for "
        "default-credential or credential-stuffing attacks."),
    "api-surface": (
        re.compile(r"(/swagger|/openapi\.(json|yaml)|/api-docs|/graphql\b)", re.I),
        "medium",
        "A machine-readable API schema/introspection endpoint is exposed — maps "
        "the entire API surface (including unlinked operations) for free."),
}

# -- dangerous query-parameter names: category -> (names, severity, why) -----
PARAM_PATTERNS: dict[str, tuple[set[str], str, str]] = {
    "ssrf-redirect": (
        {"url", "uri", "path", "dest", "destination", "redirect", "redirect_uri",
         "continue", "return", "returnurl", "return_url", "next", "image", "img",
         "proxy", "callback", "target", "out", "view", "site", "feed", "fetch"},
        "high",
        "Parameter name suggests the server fetches or redirects to a caller-"
        "supplied URL — classic SSRF / open-redirect sink."),
    "lfi-rfi": (
        {"file", "page", "template", "include", "doc", "document", "folder",
         "dir", "load", "filename", "filepath", "download"},
        "high",
        "Parameter name suggests filesystem path handling — candidate for "
        "local/remote file inclusion or path traversal."),
    "idor": (
        {"id", "uid", "user_id", "userid", "account", "account_id", "order_id",
         "invoice", "invoice_id", "profile_id", "doc_id", "member_id", "customer_id"},
        "medium",
        "Parameter references an object by a (likely sequential/guessable) ID — "
        "candidate for insecure direct object reference / authorization bypass "
        "by enumeration."),
    "command-injection": (
        {"cmd", "exec", "command", "ping", "run", "shell", "system"},
        "critical",
        "Parameter name suggests it may reach a shell/system call — candidate "
        "for OS command injection."),
}

# -- sensitive open ports: port -> (label, severity) --------------------------
SENSITIVE_PORTS: dict[int, tuple[str, str]] = {
    23: ("Telnet", "critical"),
    1433: ("MSSQL", "high"),
    3306: ("MySQL", "high"),
    5432: ("PostgreSQL", "high"),
    5601: ("Kibana", "medium"),
    5984: ("CouchDB", "high"),
    6379: ("Redis", "critical"),
    2375: ("Docker API (unauthenticated by default)", "critical"),
    2379: ("etcd", "critical"),
    8020: ("Hadoop NameNode", "high"),
    9200: ("Elasticsearch", "high"),
    9300: ("Elasticsearch transport", "high"),
    11211: ("Memcached", "high"),
    27017: ("MongoDB", "critical"),
    27018: ("MongoDB", "critical"),
}

INTERNAL_KEYWORDS = [
    "dev", "develop", "staging", "stage", "test", "uat", "qa", "preprod",
    "internal", "intranet", "corp", "vpn", "admin", "jenkins", "gitlab",
    "git", "jira", "confluence", "grafana", "kibana", "sonarqube", "argocd",
    "rancher", "portainer", "airflow", "metabase", "superset", "nexus",
    "artifactory", "teamcity", "bamboo", "adminer", "phpmyadmin", "backend",
    "old", "beta", "demo", "sandbox",
]


class CorrelateStage(Stage):
    name = "correlate"
    tools: list[str] = []
    tier = "passive"           # pure analysis over already-collected data
    requires_any_tool = False
    depends_on = ["resolve", "ports", "http_probe", "crawl", "vulns", "exploits"]

    def execute(self, ctx: StageContext, record: StageRun) -> str:
        cap = ctx.config.correlate_max_evidence
        insights: list[Insight] = []
        insights += self._subdomain_takeover(ctx)
        insights += self._sensitive_exposure(ctx, cap)
        insights += self._injection_surface(ctx, cap)
        insights += self._exposed_services(ctx)
        insights += self._shadow_it(ctx)
        insights += self._vuln_rollup(ctx, cap)
        insights += self._exploit_routes(ctx, cap)

        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        insights.sort(key=lambda i: order.get(i.severity, 5))

        ctx.results.insights.extend(insights)
        record.produced = len(insights)
        self._write_summary(ctx, insights)

        by_cat = defaultdict(int)
        for i in insights:
            by_cat[i.category] += 1
        breakdown = ", ".join(f"{n} {c}" for c, n in sorted(by_cat.items()))
        return f"{len(insights)} correlated insight(s)" + (f" ({breakdown})" if breakdown else "")

    # -- 1. dangling CNAME / subdomain takeover ---------------------------
    def _subdomain_takeover(self, ctx: StageContext) -> list[Insight]:
        out = []
        for host in ctx.results.hosts.values():
            if not host.cname or host.ips:
                continue
            cname = host.cname.lower().rstrip(".")
            match = next((sig for sig in TAKEOVER_FINGERPRINTS if cname.endswith(sig)), None)
            if match:
                service, confidence = TAKEOVER_FINGERPRINTS[match]
                title = f"Possible subdomain takeover: {host.name} -> {service}"
                rationale = (f"{host.name} has a CNAME to {host.cname} (fingerprinted as "
                             f"{service}) but no A record resolves — the DNS record is "
                             f"dangling. If the {service} resource was deprovisioned, an "
                             f"attacker can claim it and serve content under {host.name}.")
            else:
                service, confidence = "unrecognized third-party service", "low"
                title = f"Dangling CNAME on {host.name}"
                rationale = (f"{host.name} has a CNAME to {host.cname} with no resolving "
                             f"A record. Not a fingerprinted takeover pattern, but a dangling "
                             f"pointer is always worth a manual look.")
            out.append(Insight(
                id=f"takeover-{host.name}", title=title, category="takeover",
                severity="high" if confidence == "high" else "medium",
                confidence=confidence, hosts=[host.name],
                evidence=[f"{host.name}  CNAME->  {host.cname}  (no A record)"],
                rationale=rationale,
                next_step=("Authorized tester only: confirm the CNAME target is truly "
                            "unclaimed (e.g. resolve/browse it, check the provider's "
                            f"'not found'/'no such app' page for {service}) before any "
                            "claim attempt — never auto-claim third-party resources."),
            ))
        return out

    # -- 2. sensitive path exposure in crawled URLs ------------------------
    def _sensitive_exposure(self, ctx: StageContext, cap: int) -> list[Insight]:
        hits: dict[str, list[str]] = defaultdict(list)
        for cu in ctx.results.crawl_urls:
            path_q = cu.url.split("://", 1)[-1]
            for category, (pattern, _sev, _why) in EXPOSURE_PATTERNS.items():
                if pattern.search(path_q):
                    hits[category].append(cu.url)

        out = []
        for category, urls in hits.items():
            _pattern, severity, why = EXPOSURE_PATTERNS[category]
            urls = sorted(dict.fromkeys(urls))
            hosts = sorted({urlsplit(u).hostname for u in urls if urlsplit(u).hostname})
            out.append(Insight(
                id=f"exposure-{category}", title=f"{category.replace('-', ' ').title()} "
                    f"({len(urls)} URL{'s' if len(urls) != 1 else ''})",
                category="exposure", severity=severity,
                confidence="medium",  # crawl-derived URL, not yet an HTTP-verified 200
                hosts=hosts[:cap], evidence=urls[:cap], rationale=why,
                next_step=("Authorized tester: fetch each URL manually to confirm it is "
                            "live and actually returns the sensitive content (a crawled "
                            "URL can 404) before treating this as confirmed exposure."),
            ))
        return out

    # -- 3. dangerous parameter names on crawled URLs ----------------------
    def _injection_surface(self, ctx: StageContext, cap: int) -> list[Insight]:
        hits: dict[str, list[str]] = defaultdict(list)
        for cu in ctx.results.crawl_urls:
            try:
                parts = urlsplit(cu.url)
                if not parts.query:
                    continue
                keys = {k.lower() for k in parse_qs(parts.query).keys()}
            except ValueError:
                continue
            for category, (names, _sev, _why) in PARAM_PATTERNS.items():
                if keys & names:
                    hits[category].append(cu.url)

        out = []
        for category, urls in hits.items():
            names, severity, why = PARAM_PATTERNS[category]
            urls = sorted(dict.fromkeys(urls))
            hosts = sorted({urlsplit(u).hostname for u in urls if urlsplit(u).hostname})
            out.append(Insight(
                id=f"injsurface-{category}",
                title=f"{category.replace('-', ' ').title()} parameter surface "
                    f"({len(urls)} URL{'s' if len(urls) != 1 else ''})",
                category="injection-surface", severity=severity, confidence="low",
                hosts=hosts[:cap], evidence=urls[:cap], rationale=why,
                next_step=("Prioritize these URLs for manual/`sqli_detect`/`xss_detect` "
                            "review — parameter *naming* is a heuristic, not proof; a human "
                            "or the active-tier detectors must confirm actual injectability."),
            ))
        return out

    # -- 4. exposed management/database services ---------------------------
    def _exposed_services(self, ctx: StageContext) -> list[Insight]:
        cdn_hosts = {e.host for e in ctx.results.endpoints if e.cdn and e.host}
        out = []
        for svc in ctx.results.services:
            if svc.state != "open" or svc.port not in SENSITIVE_PORTS:
                continue
            label, severity = SENSITIVE_PORTS[svc.port]
            behind_cdn = svc.host in cdn_hosts
            title = f"{label} directly reachable on {svc.host}:{svc.port}"
            rationale = (f"{svc.host}:{svc.port} ({label}"
                         f"{', ' + svc.product if svc.product else ''}"
                         f"{' ' + svc.version if svc.version else ''}) is open to the network "
                         "this scan ran from. Databases and management planes should never "
                         "be directly internet-reachable.")
            if behind_cdn:
                rationale += (f" Notably, {svc.host}'s web traffic is CDN-fronted — the CDN "
                              f"protects HTTP(S) but this port bypasses it and hits the "
                              "origin directly, which also suggests the true origin IP is "
                              "exposed.")
                severity = "critical"
            out.append(Insight(
                id=f"exposed-svc-{svc.host}-{svc.port}", title=title,
                category="exposure", severity=severity,
                confidence="high" if svc.product else "medium",
                hosts=[svc.host],
                evidence=[f"{svc.host}:{svc.port}/{svc.protocol} "
                         f"{svc.product or ''} {svc.version or ''}".strip()],
                rationale=rationale,
                next_step="Verify with the client whether this exposure is intentional; "
                          "if not, this is a network/firewall-config finding to report "
                          "immediately — no exploitation needed to demonstrate impact.",
            ))
        return out

    # -- 5. shadow IT: internal-sounding hostnames live on the internet ----
    def _shadow_it(self, ctx: StageContext) -> list[Insight]:
        live_hosts = {e.host for e in ctx.results.endpoints if e.status and e.host}
        out = []
        for host in ctx.results.hosts.values():
            if not (host.resolved or host.name in live_hosts):
                continue
            labels = host.name.split(".")
            matched = [kw for kw in INTERNAL_KEYWORDS
                       if any(kw == lbl or lbl.startswith(kw + "-") or lbl.startswith(kw + ".")
                              for lbl in labels)]
            if not matched:
                continue
            out.append(Insight(
                id=f"shadowit-{host.name}",
                title=f"Internal-sounding host exposed: {host.name}",
                category="shadow-it", severity="medium", confidence="low",
                hosts=[host.name],
                evidence=[f"{host.name} — matched keyword(s): {', '.join(matched)}"
                          + (f" — live: {host.name in live_hosts}" if host.name in live_hosts else "")],
                rationale=("Hostname suggests a non-production or internal-tooling asset "
                           "(CI, observability, admin, staging) that is nonetheless "
                           "resolvable/live on the public internet. These assets are "
                           "systematically under-hardened relative to the production edge."),
                next_step="Confirm it's genuinely internal-only tooling exposed by mistake "
                          "(vs. an intentionally public staging env) before flagging.",
            ))
        return out

    # -- 6. per-host CVE rollup ---------------------------------------------
    def _vuln_rollup(self, ctx: StageContext, cap: int) -> list[Insight]:
        by_host: dict[str, list] = defaultdict(list)
        for f in ctx.results.findings:
            if not f.cves:
                continue
            host = f.host or (urlsplit(f.matched_at).hostname if f.matched_at else None)
            if host:
                by_host[host].append(f)

        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        out = []
        for host, findings in by_host.items():
            if len(findings) < 2:
                continue
            cves = sorted({c for f in findings for c in f.cves})
            worst = min((f.severity for f in findings), key=lambda s: sev_rank.get(s, 5))
            exploitable = [f for f in findings if f.exploits]
            evidence = [f"{f.template_id}: {', '.join(f.cves)} ({f.severity})"
                       + (" [public exploit available]" if f.exploits else "")
                       for f in sorted(findings, key=lambda f: sev_rank.get(f.severity, 5))]
            out.append(Insight(
                id=f"rollup-{host}",
                title=f"{host}: {len(cves)} CVEs across {len(findings)} findings",
                category="vuln-rollup", severity=worst,
                confidence="high",
                hosts=[host], evidence=evidence[:cap],
                rationale=(f"{host} carries {len(findings)} distinct CVE-tagged findings "
                           f"({len(exploitable)} with a public exploit already resolved) — "
                           "treat this as one priority target with a compounded attack "
                           "surface, not N isolated line items. Multiple weaknesses on the "
                           "same host often chain (e.g. an info-leak confirms a version that "
                           "makes an adjacent CVE's exploit reliable)."),
                next_step="Sequence manual/professional exploitation attempts on this host "
                          "by likely impact, starting from the exploit-backed CVEs.",
            ))
        return out

    # -- 7. exploit routes: rank confirmed/candidate findings per host into --
    #      an ordered plan against this pipeline's own offensive-tier stages
    def _exploit_routes(self, ctx: StageContext, cap: int) -> list[Insight]:
        sqli: dict[str, list] = defaultdict(list)
        xss: dict[str, list] = defaultdict(list)
        cve_exploitable: dict[str, list] = defaultdict(list)
        cve_only: dict[str, list] = defaultdict(list)
        for f in ctx.results.findings:
            host = f.host or (urlsplit(f.matched_at).hostname if f.matched_at else None)
            if not host:
                continue
            if f.template_id == "sqli":
                sqli[host].append(f)
            elif f.template_id == "xss":
                xss[host].append(f)
            elif f.cves:
                (cve_exploitable if f.exploits else cve_only)[host].append(f)

        auth_surfaces: dict[str, list] = defaultdict(list)
        for e in ctx.results.endpoints:
            if not e.host:
                continue
            if e.status == 401:
                auth_surfaces[e.host].append((e.url, "HTTP Basic (401)"))
            elif e.url and "wp-login.php" in e.url.lower():
                auth_surfaces[e.host].append((e.url, "WordPress login form"))

        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        hosts = set(sqli) | set(xss) | set(cve_exploitable) | set(cve_only) | set(auth_surfaces)
        out = []
        for host in sorted(hosts):
            steps: list[tuple[int, str]] = []
            worst = "unknown"

            def bump(sev: str) -> None:
                nonlocal worst
                if sev_rank.get(sev, 5) < sev_rank.get(worst, 5):
                    worst = sev

            for f in sqli.get(host, []):
                extra = [t for t in f.tags if t not in ("sqli", "injection")]
                steps.append((0, f"sqli_exploit (sqlmap --dump) on {f.matched_at} — "
                             f"confirmed injectable ({', '.join(extra) or 'param'}); chain "
                             "into crack for any hash-shaped dumped columns."))
                bump(f.severity)
            for f in xss.get(host, []):
                state = "already verified" if "verified" in f.tags else "reflected, needs confirmation"
                steps.append((0, f"xss_confirm (dalfox headless verify) on {f.matched_at} — {state}."))
                bump(f.severity)
            for f in cve_exploitable.get(host, []):
                steps.append((1, f"exploit_run (vetted nuclei template {f.template_id}) — "
                             f"{', '.join(f.cves)}: {len(f.exploits)} public exploit(s) already "
                             "resolved."))
                bump(f.severity)
            for url, mode in auth_surfaces.get(host, []):
                steps.append((2, f"auth_attack (hydra) against {url} — {mode} discovered; point "
                             "auth_userlist/auth_passlist at real wordlists for a serious attempt."))
                bump("medium")
            for f in cve_only.get(host, []):
                steps.append((3, f"manual research on {', '.join(f.cves)} ({f.template_id}) — "
                             "no public exploit resolved yet; check the vendor advisory / NVD "
                             "directly."))
                bump(f.severity)

            if not steps:
                continue
            steps.sort(key=lambda s: s[0])
            ordered = [s[1] for s in steps][:cap]
            out.append(Insight(
                id=f"route-{host}",
                title=f"Exploit route: {host} ({len(steps)} vector{'s' if len(steps) != 1 else ''})",
                category="exploit-route", severity=worst, confidence="high",
                hosts=[host],
                evidence=[f"{i + 1}. {step}" for i, step in enumerate(ordered)],
                rationale=(f"{host} already has {len(steps)} independent exploitation vector(s) "
                           "on record from the pre-exploitation stages. Ranked by confirmation "
                           "strength — confirmed injection, then resolved public exploit, then "
                           "credential surface, then needs-manual-research — and mapped directly "
                           "onto this pipeline's own offensive-tier stages, so an approved "
                           "operator can go straight to the highest-value action."),
                next_step="Validate each step manually before running --exploit; this ordering "
                          "is a planning aid for an approved human operator, not an execution "
                          "trigger.",
            ))
        return out

    # -- audit trail ---------------------------------------------------------
    def _write_summary(self, ctx: StageContext, insights: list[Insight]) -> None:
        sdir = ctx.stage_dir(self.name)
        lines = []
        for i in insights:
            lines.append(f"# [{i.severity.upper()}] {i.title}  ({i.category}, "
                        f"confidence={i.confidence})")
            lines.append(i.rationale)
            for e in i.evidence:
                lines.append(f"  - {e}")
            lines.append(f"  -> next step: {i.next_step}")
            lines.append("")
        (sdir / "insights.txt").write_text("\n".join(lines), encoding="utf-8")
