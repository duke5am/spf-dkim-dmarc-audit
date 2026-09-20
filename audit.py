#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""audit.py - Email Authentication DNS Audit & Fix CLI.

This wrapper exists so `python3 audit.py --domain example.com` keeps working
from a clone. The same CLI is installed as the `spf-dkim-dmarc-audit` console
script; the implementation lives in `spf_dkim_dmarc_audit/cli.py` so that the
installed package and the checkout are the same code, not two versions of it.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from spf_dkim_dmarc_audit.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
