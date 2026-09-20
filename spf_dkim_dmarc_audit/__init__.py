"""Email authentication DNS audit: SPF, DKIM, DMARC, MX, MTA-STS, TLS-RPT, BIMI.

The whole implementation lives in :mod:`spf_dkim_dmarc_audit.cli`, so the
installed console script and the repo-root ``audit.py`` wrapper run exactly the
same code rather than two copies of it.

Standard library only: no third-party dependencies, read-only, no network
traffic beyond DNS (and an optional MTA-STS policy fetch).
"""
