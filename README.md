# spf-dkim-dmarc-audit

[![PyPI](https://img.shields.io/pypi/v/spf-dkim-dmarc-audit)](https://pypi.org/project/spf-dkim-dmarc-audit/)

Audit a domain's **SPF, DKIM and DMARC** against live DNS, with explanations and
a concrete fix for every finding. No dependencies — it speaks DNS itself.

```bash
pip install spf-dkim-dmarc-audit         # from PyPI, Python 3.9+
spf-dkim-dmarc-audit --domain example.com
spf-dkim-dmarc-audit --domain example.com --dkim-selector s1 --json
spf-dkim-dmarc-audit --test-spf "v=spf1 include:_spf.google.com -all"
```

Or straight from a clone, no install — the same code either way:

```bash
git clone https://github.com/duke5am/spf-dkim-dmarc-audit
cd spf-dkim-dmarc-audit
python3 audit.py --domain example.com
python3 audit.py --domain example.com --dkim-selector s1 --json
python3 audit.py --test-spf "v=spf1 include:_spf.google.com -all"
```

```
 Email authentication audit: github.com
 audit.py 1.0.0  |  19 DNS queries  |  0.82s

POSTURE
    SPF     1 record(s), 10 lookup-causing term(s), terminal '~'
    DMARC   p=quarantine sp=reject pct=100  rua=mailto:dmarc@github.com
    MX      0 github-com.mail.protection.outlook.com
```

## What it catches that a naive check misses

**The 10-lookup SPF limit, counted recursively.** SPF allows at most 10
DNS-lookup-causing terms including those *inside* your `include:` chains, and
exceeding it is a `permerror` — meaning SPF stops working entirely. Counting only
your own top-level terms undercounts badly. This walks the whole chain with a
recursion cap and cycle detection:

```
[spf] count= 1  include:spf.protection.outlook.com (depth 0, from github.com)
[spf] count= 6  exists:%{i}._spf.mta.salesforce.com (depth 1, from _spf.salesforce.com)
[spf] count=10  include:ab.sendgrid.net            (depth 1, from sendgrid.net)
```

github.com sits at exactly 10 — one provider away from breaking.

**Duplicate DMARC records silently disable your policy.** Publishing two `v=DMARC1`
records does not give you the stricter one, it gives you *none of them* — policy
discovery terminates. Run against a real domain:

```
[CRITICAL] Multiple DMARC records: the policy is not applied at all
```

**`p=none` with no reporting address** — monitoring that reports nowhere.

**Revoked versus missing DKIM keys.** An empty `p=` tag is a *revoked* key; a name
that returns NODATA is a *missing* one. They need different fixes, and conflating
them wastes an afternoon.

**An `include:` target that publishes no SPF record** — that include can never
match, so the senders it was meant to authorise fail.

## Exit codes

`0` no findings above the threshold · `1` findings present · `2` bad input (an
invalid domain is rejected up front rather than producing a report full of
"none published" for a name that cannot exist) · `3` no resolver answered, so
nothing was checked.

## Honest limits

- **It can only see DNS.** It cannot see your sending reputation or inbox
  placement. "It goes to spam" is usually a reputation or alignment problem, not
  a missing record.
- **DKIM selectors must be supplied** (`--dkim-selector`). Selectors cannot be
  enumerated from DNS — no tool can do this, and any that claims to is guessing.
- **Message readers differ.** The 10-lookup limit mandates a `permerror`; how a
  given receiver then treats the message is up to that receiver.
- **The lookup count is worst-case.** A receiver may stop earlier if an earlier
  mechanism matches. Worst case is the number that matters when you do not know
  the sending IP.
- Read-only: it never modifies DNS and never sends mail.

## The full pack

The paid kit adds copy-paste DNS record templates for seven mail providers
(with the note that DKIM selectors and public keys come from the provider's
console and cannot be invented), the safe migration path from `p=none` to
`p=reject`, the common-breakages catalogue, the plain-language glossary, and 184
tests on 49 recorded real-DNS fixtures.

<!-- RELATED:START -->

## Related tools

- **[google-oauth-verification-preflight](https://github.com/duke5am/google-oauth-verification-preflight)** — Preflight an OAuth consent screen before submitting for Google verification: scope classification, branding requirements and the common rejection reasons.
  *(if you were searching for "google oauth verification rejected")*

All 28 tools in this set, grouped by what they check: **[dev-tools-index](https://duke5am.github.io/dev-tools-index/)**

If you arrived here searching for one of these, this is the tool: **spf dkim dmarc check** · **spf lookup limit exceeded** · **dmarc policy audit** · **why do my emails go to spam**

<!-- RELATED:END -->

→ **[Email Auth DNS Audit & Fix Templates](https://duke5am.gumroad.com/l/27-email-auth-dns)** — $34 on Gumroad <!-- GUMROAD-LINK -->
