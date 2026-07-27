"""web-timeline: a staged, tiered web-application offensive-security pipeline.

Input : one or more target domains.
Output: normalized JSON + a browsable HTML report spanning three gated tiers —
        passive recon, active scanning/enumeration, and offensive exploitation
        (SQLi/XSS/auth/CVE) with extracted credentials and loot.

Tiers escalate only on explicit opt-in: passive by default, `--active` for
scanning, `--exploit` for exploitation (authorization required at each step).
"""

__version__ = "0.2.0"

#: HTTP User-Agent for the pipeline's own (key-free) outbound lookups.
USER_AGENT = f"web-timeline/{__version__}"
