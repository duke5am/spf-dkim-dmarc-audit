"""Tests for the `spf-dkim-dmarc-audit` CLI.

Run from the repo root:

    python3 -m unittest discover -s tests -v

This tool takes no input FILES - its input is domain names on the command line
and live DNS - so the "bad input" cases here are a malformed domain name, a
domain that cannot exist, and no domain at all. Every one of them must exit
non-zero with a readable message and must NOT print a Python traceback.

Tests that need real DNS are skipped when DNS is unreachable, so the suite is
deterministic offline and still exercises live DNS when it can. The tests that
do use live DNS query only `example.com` (reserved by RFC 2606 for exactly this
purpose) and `example.invalid` (a name that cannot exist), never a real
customer domain.
"""
import json
import os
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from spf_dkim_dmarc_audit import cli  # noqa: E402

AUDIT_PY = os.path.join(REPO, "audit.py")


def run_cli(*args, timeout=180):
    """Run the checkout's own CLI as a subprocess and return the CompletedProcess."""
    return subprocess.run(
        [sys.executable, AUDIT_PY, *args],
        cwd=REPO, capture_output=True, text=True, timeout=timeout,
    )


def _dns_available():
    try:
        resolver = cli.Resolver(timeout=4.0, retries=0)
        return resolver.query("example.com", cli.QTYPE["TXT"]).ok
    except Exception:
        return False


DNS_OK = _dns_available()
needs_dns = unittest.skipUnless(DNS_OK, "no DNS access from this machine")


class _FakeResolver(object):
    """Answers every TXT query with one canned record, so counting logic can be
    tested without touching DNS."""

    def __init__(self, spf_record):
        self.spf_record = spf_record

    def txt(self, name):
        return _txt_response(name, [self.spf_record])

    def query(self, name, qtype):
        return _txt_response(name, [])


def _txt_response(name, texts):
    resp = cli.Response(name, cli.QTYPE["TXT"])
    resp.rcode = "NOERROR"
    resp.rcode_num = 0
    resp.transport = "test"
    resp.server = "test"
    for text in texts:
        resp.answers.append(cli.RR(name, cli.QTYPE["TXT"], 1, 300, b"", [text]))
    return resp


def _der(tag, payload):
    """Minimal DER TLV encoder (definite length, short or long form)."""
    n = len(payload)
    if n < 0x80:
        return bytes([tag, n]) + payload
    length_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length_bytes)]) + length_bytes + payload


class TestBadInput(unittest.TestCase):
    """Every bad invocation must fail loudly and never traceback."""

    def assert_clean_failure(self, proc, expected_code):
        combined = proc.stdout + proc.stderr
        self.assertNotIn("Traceback", combined,
                         "CLI printed a Python traceback:\n" + combined)
        self.assertEqual(proc.returncode, expected_code,
                         "unexpected exit code; output was:\n" + combined)
        self.assertTrue(proc.stderr.strip(), "nothing was written to stderr")

    def test_no_arguments_is_an_error(self):
        self.assert_clean_failure(run_cli(), 2)

    def test_domain_without_a_dot_is_rejected(self):
        for bad in ("notadomain", "localhost", "-", ".", ".."):
            with self.subTest(domain=bad):
                proc = run_cli("--domain", bad)
                self.assertNotIn("Traceback", proc.stdout + proc.stderr)
                self.assertNotEqual(proc.returncode, 0)

    def test_domain_that_is_an_ip_literal_is_rejected(self):
        for bad in ("192.0.2.1", "198.51.100.7"):
            with self.subTest(domain=bad):
                proc = run_cli("--domain", bad)
                self.assert_clean_failure(proc, 2)
                self.assertIn("IP address", proc.stderr)

    def test_domain_with_a_space_or_slash_is_rejected(self):
        for bad in ("has space.com", "http://example.com", "a/b.com"):
            with self.subTest(domain=bad):
                proc = run_cli("--domain", bad)
                self.assertNotIn("Traceback", proc.stdout + proc.stderr)
                self.assertEqual(proc.returncode, 2)

    def test_invalid_label_characters_are_rejected(self):
        # '!' is not a valid DNS label character.
        proc = run_cli("--domain", "bad!label.example.com")
        self.assert_clean_failure(proc, 2)
        self.assertIn("valid DNS label", proc.stderr)

    def test_unknown_flag_is_rejected(self):
        proc = run_cli("--definitely-not-a-flag")
        self.assertNotIn("Traceback", proc.stdout + proc.stderr)
        self.assertEqual(proc.returncode, 2)


class TestOfflinePositiveCases(unittest.TestCase):
    """Cases that need no DNS at all."""

    def test_version_flag(self):
        proc = run_cli("--version")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("audit.py 1.0.0", proc.stdout)

    def test_help_flag(self):
        proc = run_cli("--help")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--domain", proc.stdout)
        self.assertIn("--test-spf", proc.stdout)

    def test_proposed_record_without_lookup_terms_needs_zero_lookups(self):
        proc = run_cli("--test-spf", "v=spf1 ip4:192.0.2.0/24 -all")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Proposed SPF record check", proc.stdout)
        self.assertIn("Lookup-causing terms : 0  (RFC 7208 limit: 10)", proc.stdout)
        self.assertIn("Within the lookup limit (0 of 10)", proc.stdout)

    def test_json_output_is_valid_json(self):
        proc = run_cli("--json", "--test-spf", "v=spf1 ip4:192.0.2.0/24 -all")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["tool"], "audit.py")
        self.assertEqual(payload["spf_tests"][0]["record"], "v=spf1 ip4:192.0.2.0/24 -all")
        self.assertEqual(payload["spf_tests"][0]["lookup_count"], 0)
        self.assertFalse(payload["spf_tests"][0]["over_limit"])


class TestSpfLookupCounting(unittest.TestCase):
    """The lookup counter is the expensive-in-production part; test it directly."""

    def test_eleven_includes_is_over_the_rfc_limit(self):
        record = "v=spf1 " + " ".join(
            "include:spf%d.example.com" % i for i in range(11)) + " -all"
        state = cli.count_spf_lookups(record, "example.com", _FakeResolver("v=spf1 -all"))
        self.assertEqual(state.count, 11)
        self.assertTrue(state.over_limit)

    def test_ten_includes_is_exactly_at_the_limit(self):
        record = "v=spf1 " + " ".join(
            "include:spf%d.example.com" % i for i in range(10)) + " -all"
        state = cli.count_spf_lookups(record, "example.com", _FakeResolver("v=spf1 -all"))
        self.assertEqual(state.count, 10)
        self.assertFalse(state.over_limit)
        self.assertTrue(state.near_limit)

    def test_include_loop_is_detected_rather_than_followed_forever(self):
        # Every domain in the walk publishes the same record, which includes the
        # next one, so the walk must stop on the repeat instead of recursing.
        loop = "v=spf1 include:sub.example.com -all"
        state = cli.count_spf_lookups(loop, "example.com", _FakeResolver(loop))
        self.assertLessEqual(state.count, 4)
        self.assertTrue(state.cycles, "a self-referencing include chain was not reported")
        self.assertFalse(state.depth_exceeded)

    def test_include_with_no_spf_at_target_is_a_permerror(self):
        state = cli.count_spf_lookups(
            "v=spf1 include:empty.example.com -all", "example.com",
            _FakeResolver("some other txt record"))
        self.assertTrue(any("permerror" in e for e in state.errors),
                        "missing SPF at an include target was not reported: %r" % state.errors)


class TestParsers(unittest.TestCase):
    """Pure functions: no DNS, no subprocess."""

    def test_parse_spf_accepts_a_valid_record(self):
        res = cli.parse_spf("v=spf1 include:_spf.google.com -all")
        self.assertTrue(res.valid_version)
        self.assertEqual(res.errors, [])
        self.assertEqual(len(res.mechanisms), 2)
        self.assertIsNotNone(res.all_term)

    def test_parse_spf_rejects_a_non_spf_record(self):
        res = cli.parse_spf("google-site-verification=abc123")
        self.assertFalse(res.valid_version)
        self.assertTrue(res.errors)

    def test_parse_spf_flags_an_unescaped_percent(self):
        # RFC 7208 section 7.1: a literal '%' must be written '%%'. The trailing
        # '%' here is neither '%%' nor a '%{...}' macro, so it is a permerror.
        res = cli.parse_spf("v=spf1 include:%{d}% -all")
        self.assertTrue(any("unescaped" in e for e in res.errors), res.errors)

    def test_parse_spf_accepts_an_escaped_percent(self):
        res = cli.parse_spf("v=spf1 a:example.com exists:%{i}._spf.%% -all")
        self.assertEqual([e for e in res.errors if "unescaped" in e], [])

    def test_parse_dmarc_accepts_a_valid_record(self):
        res = cli.parse_dmarc("v=DMARC1; p=reject; rua=mailto:dmarc@example.com")
        self.assertTrue(res.valid)
        self.assertEqual(res.p, "reject")
        self.assertTrue(res.enforcing)

    def test_parse_dmarc_rejects_a_missing_p_tag(self):
        res = cli.parse_dmarc("v=DMARC1; rua=mailto:dmarc@example.com")
        self.assertFalse(res.valid)
        self.assertTrue(res.errors)

    def test_encode_name_round_trips_a_label(self):
        self.assertEqual(cli.encode_name("example.com"),
                         b"\x07example\x03com\x00")

    def test_encode_name_rejects_an_over_long_label(self):
        with self.assertRaises(cli.DNSProtocolError):
            cli.encode_name("a" * 64 + ".com")

    def test_rsa_modulus_bits_reads_a_synthetic_2048_bit_key(self):
        # Build a DER SubjectPublicKeyInfo by hand: SEQUENCE { AlgorithmIdentifier,
        # BIT STRING { SEQUENCE { INTEGER modulus, INTEGER exponent } } }. The
        # modulus has a leading 0x00 (DER sign byte) that must not be counted.
        modulus = _der(0x02, b"\x00" + b"\xab" * 256)
        exponent = _der(0x02, b"\x01\x00\x01")
        rsa_public_key = _der(0x30, modulus + exponent)
        bit_string = _der(0x03, b"\x00" + rsa_public_key)
        algorithm = _der(0x30, _der(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01")
                         + _der(0x05, b""))
        spki = _der(0x30, algorithm + bit_string)
        self.assertEqual(cli.rsa_modulus_bits(spki), 2048)

    def test_rsa_modulus_bits_returns_none_on_garbage(self):
        # Documented contract: an unparseable key yields None, it never raises.
        self.assertIsNone(cli.rsa_modulus_bits(b"not der at all"))
        self.assertIsNone(cli.rsa_modulus_bits(b""))
        self.assertIsNone(cli.rsa_modulus_bits(b"\x30\xff"))

    def test_registrable_like_handles_a_two_label_suffix(self):
        self.assertEqual(cli.registrable_like("mail.example.co.uk"), "example.co.uk")
        self.assertEqual(cli.registrable_like("example.com"), "example.com")


class TestLiveDns(unittest.TestCase):
    """Exercised against RFC 2606 / RFC 6761 reserved names only."""

    @needs_dns
    def test_audit_of_the_reserved_example_domain_succeeds(self):
        proc = run_cli("--domain", "example.com")
        combined = proc.stdout + proc.stderr
        self.assertNotIn("Traceback", combined)
        self.assertEqual(proc.returncode, 0, combined)
        self.assertIn("Email authentication audit: example.com", proc.stdout)
        self.assertIn("POSTURE", proc.stdout)

    @needs_dns
    def test_json_report_for_the_reserved_example_domain_is_valid(self):
        proc = run_cli("--domain", "example.com", "--json")
        self.assertNotIn("Traceback", proc.stdout + proc.stderr)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["domains"][0]["domain"], "example.com")
        self.assertIn("spf", payload["domains"][0])

    @needs_dns
    def test_a_domain_that_cannot_exist_fails_on_a_critical_finding(self):
        # example.invalid is reserved: it can never be delegated, so NXDOMAIN is
        # the only possible correct answer. With --fail-on critical the exit code
        # must be 1, and the report must still be a report, not a traceback.
        proc = run_cli("--domain", "example.invalid", "--fail-on", "critical", "--timeout", "5")
        combined = proc.stdout + proc.stderr
        self.assertNotIn("Traceback", combined)
        self.assertEqual(proc.returncode, 1, combined)
        self.assertIn("NXDOMAIN", proc.stdout)


if __name__ == "__main__":
    unittest.main()
