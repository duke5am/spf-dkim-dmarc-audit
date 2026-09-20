#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
audit.py - Email Authentication DNS Audit & Fix CLI.

Audits SPF, DKIM, DMARC, MX, MTA-STS, TLS-RPT and BIMI records for one or more
domains by querying live DNS (READ-ONLY) and reports findings with a severity
and a concrete, copy-pasteable fix.

Design goals:
  * Zero third-party dependencies. Standard library only (Python 3.8+).
  * Read-only. This tool never modifies DNS and never sends email.
  * Honest. Every finding states what was actually observed in DNS. Where a
    check is a heuristic or an inference, it says so.

See README.md for what is verified against live DNS and what is documented
from RFC reasoning.

Part of "Email Auth DNS Audit & Fix Templates".
"""

import argparse
import base64
import binascii
import json
import os
import random
import re
import socket
import struct
import sys
import time
import urllib.error
import urllib.request

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

QTYPE = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
    "AAAA": 28, "SRV": 33, "CAA": 257, "OPT": 41, "SPF": 99, "TLSA": 52,
    "HTTPS": 65, "SVCB": 64, "DS": 43, "DNSKEY": 48,
}
QTYPE_REV = {v: k for k, v in QTYPE.items()}

RCODE = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
    5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH",
    10: "NOTZONE", 16: "BADVERS",
}

# Severity ordering. Higher number = more urgent.
SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "OK": 0}

# Default public resolvers used only if the system resolver cannot be read.
FALLBACK_RESOLVERS = ["8.8.8.8", "1.1.1.1"]

# SPF: terms that consume one of the 10 allowed DNS lookups.
# RFC 7208 section 4.6.4: include, a, mx, ptr, exists, and the redirect modifier.
SPF_LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}

# Hard recursion guard for the SPF lookup counter. The RFC limit is 10 terms,
# so a chain deeper than this cannot be valid; the guard exists so that a
# malicious or accidentally looping chain can never hang the tool.
SPF_MAX_INCLUDE_DEPTH = 10

# RFC 7208 section 4.6.4: implementations SHOULD limit "void lookups"
# (NXDOMAIN, or NOERROR with an empty answer) to two.
SPF_VOID_LOOKUP_LIMIT = 2

DEFAULT_TIMEOUT = 5.0
DEFAULT_RETRIES = 1
EDNS_UDP_SIZE = 1232  # conservative EDNS0 buffer: avoids most truncation


class DNSError(Exception):
    """Base class for all resolver errors raised by this module."""


class DNSTimeout(DNSError):
    pass


class DNSNetworkError(DNSError):
    pass


class DNSProtocolError(DNSError):
    pass


# ---------------------------------------------------------------------------
# DNS wire format: encoding
# ---------------------------------------------------------------------------

def encode_name(name):
    """Encode a domain name into DNS wire format labels."""
    name = name.strip().rstrip(".")
    if name == "":
        return b"\x00"
    out = b""
    for label in name.split("."):
        try:
            raw = label.encode("idna") if not label.isascii() else label.encode("ascii")
        except (UnicodeError, UnicodeDecodeError):
            raise DNSProtocolError("cannot encode domain label %r" % label)
        if len(raw) > 63:
            raise DNSProtocolError("label longer than 63 octets: %r" % label)
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(qname, qtype, use_edns=True, qid=None):
    if qid is None:
        qid = random.randrange(0, 65536)
    arcount = 1 if use_edns else 0
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, arcount)
    body = encode_name(qname) + struct.pack(">HH", qtype, 1)
    if use_edns:
        # OPT pseudo-RR: root name, type 41, class = UDP payload size, TTL 0.
        body += b"\x00" + struct.pack(">HHIH", 41, EDNS_UDP_SIZE, 0, 0)
    return qid, header + body


# ---------------------------------------------------------------------------
# DNS wire format: parsing
# ---------------------------------------------------------------------------

def _read_name(msg, offset, depth=0):
    """Decode a (possibly compressed) name. Returns (name, next_offset)."""
    if depth > 32:
        raise DNSProtocolError("too many compression pointers (possible loop)")
    labels = []
    next_offset = None
    while True:
        if offset >= len(msg):
            raise DNSProtocolError("truncated name at offset %d" % offset)
        length = msg[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(msg):
                raise DNSProtocolError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | msg[offset + 1]
            if next_offset is None:
                next_offset = offset + 2
            if pointer >= len(msg):
                raise DNSProtocolError("compression pointer out of range")
            name, _ = _read_name(msg, pointer, depth + 1)
            labels.append(name)
            break
        if length & 0xC0:
            raise DNSProtocolError("reserved label length bits set")
        offset += 1
        if length == 0:
            break
        if offset + length > len(msg):
            raise DNSProtocolError("truncated label")
        labels.append(msg[offset:offset + length].decode("latin-1"))
        offset += length
    name = ".".join([l for l in labels if l != ""])
    return name, (next_offset if next_offset is not None else offset)


def _decode_txt(rdata):
    """TXT rdata is one or more length-prefixed character-strings."""
    strings = []
    i = 0
    while i < len(rdata):
        ln = rdata[i]
        i += 1
        if i + ln > len(rdata):
            strings.append(rdata[i:].decode("latin-1"))
            break
        strings.append(rdata[i:i + ln].decode("latin-1"))
        i += ln
    return strings


class RR(object):
    """A single decoded resource record."""

    __slots__ = ("name", "rtype", "rclass", "ttl", "rdata", "value")

    def __init__(self, name, rtype, rclass, ttl, rdata, value):
        self.name = name
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdata = rdata
        self.value = value

    @property
    def type_name(self):
        return QTYPE_REV.get(self.rtype, "TYPE%d" % self.rtype)

    def text(self):
        """Human-readable rdata, mirroring the familiar dig presentation."""
        v = self.value
        if self.rtype in (16, 99):  # TXT, SPF
            return " ".join('"%s"' % s.replace("\\", "\\\\").replace('"', '\\"') for s in v)
        if self.rtype == 15:  # MX
            return "%d %s" % (v[0], v[1])
        if self.rtype == 1:
            return v
        if self.rtype == 28:
            return v
        if self.rtype in (2, 5, 12):
            return v
        if self.rtype == 6:
            return "%s %s %d %d %d %d %d" % v
        if self.rtype == 257:  # CAA
            return '%d %s "%s"' % (v[0], v[1], v[2])
        return repr(v)

    def to_dict(self):
        return {
            "name": self.name, "type": self.type_name, "ttl": self.ttl,
            "value": self.value if not isinstance(self.value, bytes) else
                     base64.b64encode(self.value).decode("ascii"),
            "text": self.text(),
        }


def _parse_rr(msg, offset):
    name, offset = _read_name(msg, offset)
    if offset + 10 > len(msg):
        raise DNSProtocolError("truncated resource record header")
    rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", msg[offset:offset + 10])
    offset += 10
    if offset + rdlength > len(msg):
        raise DNSProtocolError("truncated rdata")
    rdata = msg[offset:offset + rdlength]
    end = offset + rdlength

    if rtype in (16, 99):
        value = _decode_txt(rdata)
    elif rtype == 15:
        if rdlength < 3:
            raise DNSProtocolError("bad MX rdata")
        pref = struct.unpack(">H", rdata[:2])[0]
        target, _ = _read_name(msg, offset + 2)
        value = [pref, target or "."]   # a zero-length exchange is the RFC 7505 null MX
    elif rtype == 1:
        if rdlength != 4:
            raise DNSProtocolError("bad A rdata length")
        value = ".".join(str(b) for b in rdata)
    elif rtype == 28:
        if rdlength != 16:
            raise DNSProtocolError("bad AAAA rdata length")
        value = ":".join("%02x%02x" % (rdata[i], rdata[i + 1]) for i in range(0, 16, 2))
    elif rtype in (2, 5, 12):
        value, _ = _read_name(msg, offset)
        value = value or "."
    elif rtype == 6:
        mname, o2 = _read_name(msg, offset)
        rname, o3 = _read_name(msg, o2)
        if o3 + 20 > len(msg):
            raise DNSProtocolError("bad SOA rdata")
        serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", msg[o3:o3 + 20])
        value = [mname, rname, serial, refresh, retry, expire, minimum]
    elif rtype == 257:
        if rdlength < 2:
            raise DNSProtocolError("bad CAA rdata")
        flags = rdata[0]
        taglen = rdata[1]
        tag = rdata[2:2 + taglen].decode("latin-1")
        val = rdata[2 + taglen:].decode("latin-1")
        value = [flags, tag, val]
    else:
        value = rdata

    rr = RR(name, rtype, rclass, ttl, rdata, value)
    return rr, end


class Response(object):
    """A parsed DNS response."""

    def __init__(self, name, qtype):
        self.name = name
        self.qtype = qtype
        self.qid = None
        self.rcode = None          # string, e.g. "NOERROR"
        self.rcode_num = None
        self.truncated = False
        self.recursion_available = False
        self.answers = []
        self.authority = []
        self.additional = []
        self.elapsed = 0.0
        self.transport = None
        self.server = None
        self.error = None          # set when the query could not be completed
        self.error_kind = None     # "timeout" | "network" | "protocol" | "servfail"

    # -- convenience -------------------------------------------------------
    @property
    def ok(self):
        return self.error is None

    @property
    def nxdomain(self):
        return self.rcode == "NXDOMAIN"

    @property
    def nodata(self):
        """NOERROR but the answer section holds nothing of the requested type."""
        if self.rcode != "NOERROR":
            return False
        return not any(r.rtype == self.qtype for r in self.answers)

    @property
    def void(self):
        """RFC 7208 'void lookup': NXDOMAIN, or NOERROR with an empty answer."""
        return self.nxdomain or self.nodata

    @property
    def type_name(self):
        return QTYPE_REV.get(self.qtype, "TYPE%d" % self.qtype)

    def of_type(self, rtype):
        return [r for r in self.answers if r.rtype == rtype]

    def first_txt(self):
        """All TXT character-strings of the first TXT answer, concatenated."""
        for r in self.answers:
            if r.rtype == self.qtype and self.qtype in (16, 99):
                return "".join(r.value)
        return None

    def txt_strings(self):
        """One entry per TXT record; each entry is its character-strings joined."""
        out = []
        for r in self.answers:
            if r.rtype == self.qtype and self.qtype in (16, 99):
                out.append("".join(r.value))
        return out

    def describe_error(self):
        if self.error is None:
            return None
        if self.error_kind == "timeout":
            return "no reply within %.1fs (%s, %s)" % (self.elapsed, self.transport, self.server)
        if self.error_kind == "network":
            return "network error via %s: %s" % (self.server, self.error)
        if self.error_kind == "servfail":
            return "SERVFAIL from %s" % self.server
        return "protocol error from %s: %s" % (self.server, self.error)


def parse_response(msg, name, qtype):
    resp = Response(name, qtype)
    if len(msg) < 12:
        raise DNSProtocolError("response shorter than a DNS header (%d bytes)" % len(msg))
    (qid, flags, qdcount, ancount, nscount, arcount) = struct.unpack(">HHHHHH", msg[:12])
    resp.qid = qid
    resp.truncated = bool((flags >> 9) & 1)
    resp.recursion_available = bool((flags >> 7) & 1)
    base_rcode = flags & 0x0F

    offset = 12
    for _ in range(qdcount):
        _qname, offset = _read_name(msg, offset)
        offset += 4  # qtype + qclass

    def read_section(count):
        nonlocal offset
        out = []
        for _ in range(count):
            rr, offset = _parse_rr(msg, offset)
            out.append(rr)
        return out

    resp.answers = read_section(ancount)
    resp.authority = read_section(nscount)
    resp.additional = read_section(arcount)

    # Extended rcode lives in the high byte of the OPT record's TTL.
    ext = 0
    for rr in resp.additional:
        if rr.rtype == 41:
            ext = (rr.ttl >> 24) & 0xFF
            break
    full = (ext << 4) | base_rcode
    resp.rcode_num = full
    resp.rcode = RCODE.get(full, "RCODE%d" % full)
    return resp

# ---------------------------------------------------------------------------
# Resolver: UDP + EDNS0 with TCP fallback, or DNS-over-HTTPS
# ---------------------------------------------------------------------------

def system_resolvers():
    """Best-effort read of the system resolver list. Never raises."""
    servers = []
    try:
        with open("/etc/resolv.conf", "r") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    addr = parts[1]
                    if addr not in servers:
                        servers.append(addr)
    except OSError:
        pass
    return servers


class Resolver(object):
    """A small, dependency-free DNS client.

    Transport order for each query:
      1. UDP with an EDNS0 OPT record advertising a 1232-octet buffer.
      2. If the reply has TC=1 (truncated), retry the same server over TCP.
      3. On timeout or network failure, try the next configured server.

    If a DoH endpoint is supplied, that is used instead of UDP/TCP.
    """

    def __init__(self, servers=None, timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES,
                 doh_endpoint=None, tcp_only=False, verbose=False, logger=None):
        self.servers = list(servers) if servers else system_resolvers()
        if not self.servers:
            self.servers = list(FALLBACK_RESOLVERS)
            self.used_fallback_resolvers = True
        else:
            self.used_fallback_resolvers = False
        self.timeout = timeout
        self.retries = retries
        self.doh_endpoint = doh_endpoint
        self.tcp_only = tcp_only
        self.verbose = verbose
        self._log = logger or (lambda *a, **k: None)
        self._cache = {}
        self.query_count = 0
        self.network_failures = 0

    # -- low level ---------------------------------------------------------

    def _send_udp(self, server, packet):
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            sock.settimeout(self.timeout)
            sock.sendto(packet, (server, 53))
            data, _ = sock.recvfrom(65535)
            return data
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _send_tcp(self, server, packet):
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((server, 53))
            sock.sendall(struct.pack(">H", len(packet)) + packet)
            head = self._recv_exact(sock, 2)
            length = struct.unpack(">H", head)[0]
            return self._recv_exact(sock, length)
        finally:
            try:
                sock.close()
            except OSError:
                pass

    @staticmethod
    def _recv_exact(sock, count):
        buf = b""
        while len(buf) < count:
            chunk = sock.recv(count - len(buf))
            if not chunk:
                raise DNSNetworkError("connection closed after %d of %d bytes" % (len(buf), count))
            buf += chunk
        return buf

    def _send_doh(self, packet):
        req = urllib.request.Request(
            self.doh_endpoint, data=packet,
            headers={"Content-Type": "application/dns-message",
                     "Accept": "application/dns-message"},
            method="POST")
        with urllib.request.urlopen(req, timeout=max(self.timeout, 10.0)) as fh:
            return fh.read()

    # -- query -------------------------------------------------------------

    def query(self, name, qtype, use_cache=True):
        """Query `name` for `qtype`. Returns a Response. Never raises."""
        name = name.strip().rstrip(".")
        if isinstance(qtype, str):
            qtype = QTYPE.get(qtype.upper(), qtype)
        key = (name.lower(), qtype)
        if use_cache and key in self._cache:
            return self._cache[key]

        self.query_count += 1
        resp = Response(name, qtype)
        start = time.time()

        if self.doh_endpoint:
            attempts = [("doh", self.doh_endpoint)]
        else:
            attempts = [("udp", s) for s in self.servers]
        if self.tcp_only and not self.doh_endpoint:
            attempts = [("tcp", s) for s in self.servers]

        last_error = None
        last_kind = None

        for attempt in range(self.retries + 1):
            for transport, server in attempts:
                try:
                    qid, packet = build_query(name, qtype, use_edns=(transport == "udp"))
                    if transport == "udp":
                        data = self._send_udp(server, packet)
                    elif transport == "tcp":
                        data = self._send_tcp(server, packet)
                    else:
                        data = self._send_doh(packet)

                    parsed = parse_response(data, name, qtype)
                    if parsed.qid != qid:
                        raise DNSProtocolError("transaction ID mismatch (spoofed or stale reply?)")

                    # Truncated UDP reply: redo the same question over TCP.
                    if parsed.truncated and transport == "udp":
                        self._log("  truncated UDP reply from %s, retrying over TCP" % server)
                        data = self._send_tcp(server, packet)
                        parsed = parse_response(data, name, qtype)

                    parsed.transport = transport
                    parsed.server = server
                    parsed.elapsed = time.time() - start
                    if parsed.rcode in ("SERVFAIL", "REFUSED", "NOTIMP"):
                        parsed.error = parsed.rcode
                        parsed.error_kind = "servfail"
                    self._cache[key] = parsed
                    return parsed

                except socket.timeout:
                    last_error, last_kind = "timeout", "timeout"
                    self._log("  timeout querying %s via %s" % (server, transport))
                except (DNSProtocolError, DNSNetworkError) as exc:
                    last_error, last_kind = str(exc), "network"
                    self._log("  %s querying %s via %s: %s" % (transport, server, transport, exc))
                except urllib.error.URLError as exc:
                    last_error, last_kind = str(exc.reason if hasattr(exc, "reason") else exc), "network"
                    self._log("  DoH error via %s: %s" % (server, last_error))
                except OSError as exc:
                    last_error, last_kind = str(exc), "network"
                    self._log("  socket error querying %s via %s: %s" % (name, transport, exc))
                except Exception as exc:  # never let the resolver raise
                    last_error, last_kind = "%s: %s" % (type(exc).__name__, exc), "protocol"
                    self._log("  unexpected resolver error for %s: %s" % (name, last_error))

        resp.error = last_error or "query failed"
        resp.error_kind = last_kind or "network"
        resp.transport = attempts[0][0]
        resp.server = attempts[0][1]
        resp.elapsed = time.time() - start
        self.network_failures += 1
        self._cache[key] = resp
        return resp

    # -- typed helpers -----------------------------------------------------

    def txt(self, name):
        return self.query(name, QTYPE["TXT"])

    def txt_records(self, name):
        """Follow a CNAME if present, then return TXT records.

        Returns (records, cname_target, response). `records` is a list of
        strings, one per TXT RR, character-strings concatenated.
        """
        resp = self.query(name, QTYPE["TXT"])
        if not resp.ok:
            return [], None, resp
        txts = resp.txt_strings()
        if txts:
            return txts, None, resp
        # No TXT in the answer: chase a CNAME explicitly (some clients and
        # some providers publish the _dmarc / _domainkey name as a CNAME).
        cnames = resp.of_type(QTYPE["CNAME"])
        if cnames:
            target = cnames[0].value
            sub = self.query(target, QTYPE["TXT"])
            if sub.ok:
                merged = Response(name, QTYPE["TXT"])
                merged.__dict__.update(sub.__dict__)
                merged.name = name
                return sub.txt_strings(), target, merged
            return [], target, sub
        return [], None, resp

    def mx(self, name):
        return self.query(name, QTYPE["MX"])

    def txt_type99(self, name):
        """Legacy SPF RR type (99), obsoleted by RFC 7208 section 3.1."""
        return self.query(name, QTYPE["SPF"])

    def exists(self, name, qtype):
        """True if at least one record of qtype exists at name."""
        resp = self.query(name, qtype)
        if not resp.ok or resp.rcode != "NOERROR":
            return False
        return bool(resp.of_type(qtype))

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

class Finding(object):
    """One audit result: what was observed, why it matters, and the fix."""

    __slots__ = ("fid", "severity", "area", "title", "observed", "why", "fix", "refs")

    def __init__(self, fid, severity, area, title, observed, why, fix, refs=None):
        self.fid = fid
        self.severity = severity
        self.area = area
        self.title = title
        self.observed = observed
        self.why = why
        self.fix = fix
        self.refs = refs or []

    def to_dict(self):
        return {
            "id": self.fid, "severity": self.severity, "area": self.area,
            "title": self.title, "observed": self.observed, "why": self.why,
            "fix": self.fix, "refs": self.refs,
        }


def finding(fid, severity, area, title, observed, why, fix, refs=None):
    return Finding(fid, severity, area, title, observed, why, fix, refs)


# ---------------------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------------------

_MACRO_RE = re.compile(r"%[{%]")

# A deliberately small list of multi-label public suffixes, used only for the
# "is this reporting address external?" heuristic. It is not a substitute for
# the Public Suffix List; see README.md.
_TWO_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "co.jp", "ne.jp", "or.jp",
    "com.au", "net.au", "org.au", "co.nz", "net.nz", "org.nz", "com.br",
    "com.cn", "com.tw", "co.in", "co.za", "com.mx", "com.ar", "com.tr",
    "co.kr", "com.sg", "com.hk", "co.il", "com.pl", "com.ua", "co.id",
}


def registrable_like(domain):
    """Approximate the Organizational Domain. Heuristic, documented as such."""
    labels = [l for l in domain.lower().strip(".").split(".") if l]
    if len(labels) <= 2:
        return ".".join(labels)
    last_two = ".".join(labels[-2:])
    if last_two in _TWO_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return last_two


def parent_domains(domain):
    """Yield successive parent domains, nearest first. example.a.b -> a.b, b."""
    labels = [l for l in domain.strip(".").split(".") if l]
    for i in range(1, len(labels)):
        parent = ".".join(labels[i:])
        if parent:
            yield parent


def has_macro(text):
    return bool(_MACRO_RE.search(text or ""))


# ---------------------------------------------------------------------------
# SPF: parsing
# ---------------------------------------------------------------------------

SPF_MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
SPF_MODIFIERS_KNOWN = {"redirect", "exp"}
_MODIFIER_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]*$")


class SPFTerm(object):
    __slots__ = ("raw", "qualifier", "name", "arg", "cidr", "is_modifier", "kind")

    def __init__(self, raw, qualifier, name, arg, cidr, is_modifier, kind):
        self.raw = raw
        self.qualifier = qualifier
        self.name = name
        self.arg = arg
        self.cidr = cidr
        self.is_modifier = is_modifier
        self.kind = kind  # "mechanism" | "modifier" | "unknown-mechanism" | "junk"

    @property
    def causes_lookup(self):
        if self.is_modifier:
            return self.name == "redirect"
        return self.name in SPF_LOOKUP_MECHANISMS

    def to_dict(self):
        return {"raw": self.raw, "qualifier": self.qualifier, "name": self.name,
                "arg": self.arg, "cidr": self.cidr, "modifier": self.is_modifier,
                "kind": self.kind, "causes_lookup": self.causes_lookup}


class SPFParseResult(object):
    def __init__(self):
        self.valid_version = False
        self.terms = []
        self.errors = []       # would be permerror
        self.warnings = []

    @property
    def mechanisms(self):
        return [t for t in self.terms if not t.is_modifier and t.kind != "junk"]

    @property
    def modifiers(self):
        return [t for t in self.terms if t.is_modifier]

    def get_modifier(self, name):
        for t in self.modifiers:
            if t.name == name:
                return t
        return None

    @property
    def all_term(self):
        for t in self.mechanisms:
            if t.name == "all":
                return t
        return None


def _split_spf_term(token):
    """Split one SPF term into (qualifier, name, arg, cidr, is_modifier)."""
    qualifier = ""
    body = token
    if body[:1] in ("+", "-", "~", "?"):
        qualifier, body = body[0], body[1:]

    # Mechanism? name is followed by end, ':', '/' or '=' and must be known.
    m = re.match(r"^([A-Za-z][A-Za-z0-9]*)([:/=]?)(.*)$", body, re.DOTALL)
    if m and m.group(1).lower() in SPF_MECHANISMS:
        name, sep, rest = m.group(1).lower(), m.group(2), m.group(3)
        arg, cidr = None, None
        if sep == ":":
            if "/" in rest:
                arg, cidr = rest.split("/", 1)
            else:
                arg = rest
        elif sep == "/":
            cidr = rest
        elif sep == "=":
            # e.g. "a=..." is not valid syntax for a mechanism.
            return qualifier, name, None, None, False, "unknown-mechanism"
        return qualifier, name, arg, cidr, False, "mechanism"

    # Modifier? name "=" value
    if "=" in body:
        name, _, value = body.partition("=")
        if _MODIFIER_NAME_RE.match(name):
            return "", name.lower(), value, None, True, "modifier"

    return qualifier, (body.split(":", 1)[0].split("=", 1)[0] or body), None, None, False, "unknown-mechanism"


def _unescaped_percent_at(text):
    """Return the index of a '%' that is not part of '%%' or a '%{...}' macro.

    RFC 7208 section 7.1: a literal percent sign must be written '%%'. Scanned
    left to right so that the second '%' of an escaped pair is not mistaken for
    an error, which a naive lookahead regex gets wrong.
    """
    i = 0
    while i < len(text):
        if text[i] == "%":
            nxt = text[i + 1] if i + 1 < len(text) else ""
            if nxt == "%":
                i += 2
                continue
            if nxt == "{":
                close = text.find("}", i + 2)
                if close == -1:
                    return i
                i = close + 1
                continue
            return i
        i += 1
    return -1


def parse_spf(record):
    """Parse an SPF record. Returns SPFParseResult. Never raises."""
    res = SPFParseResult()
    if record is None:
        res.errors.append("no record")
        return res

    text = " ".join(record.split())
    if not text:
        res.errors.append("empty record")
        return res

    tokens = text.split(" ")
    version = tokens[0]
    if version.lower() != "v=spf1":
        res.errors.append("record does not begin with 'v=spf1' (found %r); it is not an SPF record" % version)
        return res
    res.valid_version = True

    if len(tokens) == 1:
        res.warnings.append("record contains only the version tag and no mechanisms")

    seen_all = 0
    for token in tokens[1:]:
        if token == "":
            continue
        qualifier, name, arg, cidr, is_modifier, kind = _split_spf_term(token)
        term = SPFTerm(token, qualifier, name, arg, cidr, is_modifier, kind)
        res.terms.append(term)

        if kind == "unknown-mechanism":
            res.errors.append("unknown mechanism or malformed term %r -> permerror" % token)
            continue
        if kind == "junk":
            res.errors.append("unparseable term %r -> permerror" % token)
            continue

        if not is_modifier:
            if name == "all":
                seen_all += 1
                if seen_all > 1:
                    res.errors.append("more than one 'all' mechanism -> permerror")
                if qualifier not in ("", "+", "-", "~", "?"):
                    res.errors.append("invalid qualifier %r on 'all'" % qualifier)
            if name in ("include", "exists") and not arg:
                res.errors.append("'%s' requires a domain argument (e.g. %s:example.com) -> permerror"
                                  % (name, name))
            if name in ("a", "mx", "ptr") and arg is not None and arg == "":
                res.errors.append("'%s:' has an empty domain argument -> permerror" % name)
            if cidr is not None:
                if name not in ("a", "mx", "ip4", "ip6", "ptr"):
                    res.errors.append("'%s' does not accept a CIDR length (/ %s) -> permerror" % (name, cidr))
                else:
                    try:
                        bits = int(cidr)
                        limit = 128 if name == "ip6" else 32
                        if bits < 0 or bits > limit:
                            res.errors.append("CIDR length /%s out of range for '%s' -> permerror" % (cidr, name))
                    except ValueError:
                        res.errors.append("CIDR length '/%s' is not a number -> permerror" % cidr)
            # Unescaped '%' outside a macro is a syntax error.
            if _unescaped_percent_at(token) != -1:
                res.errors.append("unescaped '%%' in %r (RFC 7208 section 7.1 requires '%%%%') "
                                  "-> permerror" % token)
        else:
            if name == "redirect" and not arg:
                res.errors.append("'redirect=' has an empty target -> permerror")
            if name not in SPF_MODIFIERS_KNOWN:
                res.warnings.append("unknown modifier %r is ignored by receivers" % token)

    if res.get_modifier("redirect") and res.all_term:
        res.warnings.append("both 'all' and 'redirect=' are present; receivers stop at the first "
                            "matching mechanism, so 'all' normally wins and 'redirect=' is never used")
    return res


# ---------------------------------------------------------------------------
# SPF: recursive DNS lookup counting (RFC 7208 section 4.6.4)
# ---------------------------------------------------------------------------

class SPFLookupCount(object):
    """Static count of lookup-causing SPF terms, including nested includes.

    This is a WORST-CASE count: it walks every lookup-causing term reachable
    from the root record, including mechanisms that a particular receiver might
    never evaluate because an earlier mechanism already matched. That is the
    number that matters when you do not know which sending IP will be checked,
    and it is the number SPF implementations are bounded by.

    RC = recursion cap (SPF_MAX_INCLUDE_DEPTH). `depth_exceeded` records that
    the cap was hit, so the total is a lower bound in that case.
    """

    def __init__(self):
        self.count = 0
        self.void_lookups = 0
        self.terms = []            # every counted term, with provenance
        self.tree = []             # flattened include/redirect walk order
        self.errors = []           # conditions that produce permerror
        self.notes = []
        self.depth_exceeded = False
        self.cycles = []
        self.max_depth_seen = 0
        self.skipped_macros = 0
        self.dns_errors = []

    @property
    def over_limit(self):
        return self.count > 10

    @property
    def near_limit(self):
        return 8 <= self.count <= 10

    @property
    def over_void_limit(self):
        return self.void_lookups > SPF_VOID_LOOKUP_LIMIT

    def to_dict(self):
        return {
            "lookup_count": self.count, "over_limit": self.over_limit,
            "near_limit": self.near_limit,
            "void_lookups": self.void_lookups, "void_limit": SPF_VOID_LOOKUP_LIMIT,
            "over_void_limit": self.over_void_limit,
            "depth_exceeded": self.depth_exceeded, "max_depth": self.max_depth_seen,
            "cycles": self.cycles, "errors": self.errors, "notes": self.notes,
            "dns_errors": self.dns_errors,
            "skipped_macro_terms": self.skipped_macros,
            "terms": self.terms, "tree": self.tree,
        }


def count_spf_lookups(record, domain, resolver, max_depth=SPF_MAX_INCLUDE_DEPTH, verbose_log=None):
    """Walk an SPF record and every include:/redirect= target it references.

    Returns an SPFLookupCount. Never raises: DNS problems are recorded as
    notes/errors rather than exceptions.
    """
    state = SPFLookupCount()
    log = verbose_log or (lambda *a, **k: None)
    seen_domains = set()

    def walk(text, current_domain, depth, via):
        state.max_depth_seen = max(state.max_depth_seen, depth)
        parsed = parse_spf(text)
        state.tree.append({"domain": current_domain, "depth": depth, "via": via,
                           "record": text, "terms_found": len(parsed.mechanisms)})
        log("    [spf] depth=%d domain=%s via=%s" % (depth, current_domain, via))

        # redirect first or last does not matter for a static count; keep source order.
        ordered = list(parsed.mechanisms)
        redirect = parsed.get_modifier("redirect")
        if redirect is not None:
            ordered.append(redirect)

        for term in ordered:
            if not term.causes_lookup:
                continue

            # ---- count the term
            state.count += 1
            entry = {
                "term": term.raw, "mechanism": term.name,
                "domain": term.arg or current_domain,
                "depth": depth, "source_record": current_domain,
                "index": state.count, "kind": "redirect" if term.is_modifier else "mechanism",
            }
            state.terms.append(entry)
            log("    [spf] count=%2d  %-28s (depth %d, from %s)" %
                (state.count, term.raw, depth, current_domain))

            target = term.arg or current_domain

            # ---- terms whose argument contains macros cannot be resolved statically
            if has_macro(target):
                state.skipped_macros += 1
                state.notes.append("%s:%s at depth %d uses macros and was not resolved further"
                                   % (term.name, term.arg or "", depth))
                entry["resolved"] = "macro-not-resolved"
                continue

            if term.is_modifier and term.name == "redirect":
                target_records = _fetch_spf_records(resolver, target, state, entry)
                if target_records is None:
                    continue
                if not target_records:
                    state.errors.append("redirect=%s publishes no SPF record -> permerror" % target)
                    continue
                if len(target_records) > 1:
                    state.errors.append("redirect=%s publishes multiple SPF records -> permerror" % target)
                    continue
                if target in seen_domains:
                    state.cycles.append(target)
                    entry["resolved"] = "cycle"
                    continue
                if depth + 1 > max_depth:
                    state.depth_exceeded = True
                    entry["resolved"] = "depth-cap"
                    continue
                seen_domains.add(target)
                entry["resolved"] = "recursed"
                walk(target_records[0], target, depth + 1, "redirect=%s" % target)
                continue

            if term.name == "include":
                target_records = _fetch_spf_records(resolver, target, state, entry)
                if target_records is None:
                    continue
                if not target_records:
                    state.errors.append(
                        "include:%s publishes no SPF record -> permerror "
                        "(RFC 7208 section 5.2); this include can never match" % target)
                    entry["resolved"] = "no-spf-at-target"
                    continue
                if len(target_records) > 1:
                    state.errors.append("include:%s publishes multiple SPF records -> permerror" % target)
                    entry["resolved"] = "multiple-spf-at-target"
                    continue
                if target in seen_domains:
                    state.cycles.append(target)
                    entry["resolved"] = "cycle"
                    continue
                if depth + 1 > max_depth:
                    state.depth_exceeded = True
                    entry["resolved"] = "depth-cap"
                    continue
                seen_domains.add(target)
                entry["resolved"] = "recursed"
                walk(target_records[0], target, depth + 1, "include:%s" % target)
                continue

            # ---- a / mx / ptr / exists: probe the underlying lookup for voids
            if term.name == "a":
                resp = resolver.query(target, QTYPE["A"])
            elif term.name == "mx":
                resp = resolver.query(target, QTYPE["MX"])
            elif term.name == "exists":
                resp = resolver.query(target, QTYPE["A"])
            else:  # ptr depends on the connecting IP, which we do not have
                state.notes.append("ptr:%s depends on the sending IP and was not resolved" % (term.arg or ""))
                entry["resolved"] = "not-statically-resolvable"
                continue

            if not resp.ok:
                state.dns_errors.append("%s:%s -> %s" % (term.name, term.arg or "", resp.describe_error()))
                entry["resolved"] = "dns-error"
            elif resp.void:
                state.void_lookups += 1
                entry["resolved"] = "void-lookup"
                state.notes.append("%s:%s is a void lookup (%s) [void lookup #%d]"
                                   % (term.name, target, resp.rcode or "no records", state.void_lookups))
            else:
                entry["resolved"] = "resolved"

    def _fetch_spf_records(resolver, target, state, entry):
        resp = resolver.txt(target)
        if not resp.ok:
            state.dns_errors.append("TXT %s -> %s" % (target, resp.describe_error()))
            entry["resolved"] = "dns-error"
            return None
        if resp.void:
            state.void_lookups += 1
            entry["resolved"] = "void-lookup"
            state.notes.append("%s is a void lookup (%s) [void lookup #%d]"
                               % (target, resp.rcode or "no TXT records", state.void_lookups))
            return []
        records = [t for t in resp.txt_strings() if t.strip().lower().startswith("v=spf1")]
        if not records:
            # There is a TXT record but no SPF record -> not a void lookup,
            # it is a missing policy (permerror for include/redirect).
            entry["resolved"] = "no-spf-at-target"
            return []
        return records

    seen_domains.add(domain.lower())
    walk(record, domain, 0, "root")
    return state

# ---------------------------------------------------------------------------
# DKIM
# ---------------------------------------------------------------------------

_DKIM_TAG_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.*)$", re.DOTALL)


def _der_tlv(buf, off):
    """Read one DER tag-length-value header. Returns (tag, value_start, length)."""
    if off + 2 > len(buf):
        raise ValueError("truncated DER")
    tag = buf[off]
    off += 1
    ln = buf[off]
    off += 1
    if ln & 0x80:
        nbytes = ln & 0x7F
        if nbytes == 0 or off + nbytes > len(buf):
            raise ValueError("bad DER length")
        ln = int.from_bytes(buf[off:off + nbytes], "big")
        off += nbytes
    if off + ln > len(buf):
        raise ValueError("DER length past end of buffer")
    return tag, off, ln


def rsa_modulus_bits(der):
    """Extract the RSA modulus size in bits from a DER SubjectPublicKeyInfo.

    RFC 6376 section 3.6.1: for k=rsa, p= is the base64 of a DER-encoded
    SubjectPublicKeyInfo. Returns None if the structure cannot be parsed.
    """
    try:
        tag, off, ln = _der_tlv(der, 0)
        if tag != 0x30:
            return None
        end = off + ln
        # AlgorithmIdentifier SEQUENCE
        tag, off, ln = _der_tlv(der, off)
        if tag != 0x30:
            return None
        off += ln
        # BIT STRING
        tag, off, ln = _der_tlv(der, off)
        if tag != 0x03:
            return None
        if off >= end:
            return None
        off += 1  # number of unused bits
        # RSAPublicKey SEQUENCE { INTEGER modulus, INTEGER exponent }
        tag, off, ln = _der_tlv(der, off)
        if tag != 0x30:
            return None
        tag, off, ln = _der_tlv(der, off)
        if tag != 0x02:
            return None
        modulus = der[off:off + ln]
        stripped = modulus.lstrip(b"\x00")
        if not stripped:
            return 0
        return len(stripped) * 8
    except (ValueError, IndexError):
        return None


class DKIMParseResult(object):
    def __init__(self):
        self.tags = {}
        self.errors = []
        self.warnings = []
        self.present = False
        self.revoked = False
        self.key_type = None
        self.key_bits = None
        self.key_bytes = None
        self.valid_version = False

    def to_dict(self):
        out = dict(self.tags)
        if self.key_bytes is not None:
            out["_p_decoded_bytes"] = self.key_bytes
        return {
            "present": self.present, "revoked": self.revoked,
            "valid_version": self.valid_version, "key_type": self.key_type,
            "key_bits": self.key_bits, "tags": out,
            "errors": self.errors, "warnings": self.warnings,
        }


def parse_dkim(record):
    """Parse a DKIM public key record (RFC 6376 section 3.6.1)."""
    res = DKIMParseResult()
    if record is None:
        return res
    res.present = True
    text = record.strip()
    if not text:
        res.errors.append("record is empty")
        return res

    for chunk in text.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        m = _DKIM_TAG_RE.match(chunk)
        if not m:
            res.errors.append("cannot parse tag %r" % chunk)
            continue
        name = m.group(1).lower()
        # FWS inside a tag value is not part of the value (RFC 6376 section 3.2),
        # so whitespace is removed entirely - except for the human-readable n=
        # note, where it is only collapsed.
        raw_value = m.group(2)
        value = (" ".join(raw_value.split()) if name == "n"
                 else "".join(raw_value.split()))
        if name in res.tags:
            res.warnings.append("duplicate tag %r; receivers use the first occurrence" % name)
            continue
        res.tags[name] = value

    v = res.tags.get("v")
    if v is None:
        res.warnings.append("no v= tag; RFC 6376 requires v=DKIM1 for records retrieved from DNS")
    elif v != "DKIM1":
        res.errors.append("v=%s is not DKIM1" % v)
    else:
        res.valid_version = True

    res.key_type = (res.tags.get("k") or "rsa").lower()
    if res.key_type not in ("rsa", "ed25519"):
        res.errors.append("k=%s is not a registered key type (rsa or ed25519)" % res.key_type)

    if "p" not in res.tags:
        res.errors.append("no p= tag; the record is not usable")
        return res

    p = res.tags["p"]
    if p == "":
        res.revoked = True
        return res

    try:
        der = base64.b64decode(p, validate=True)
    except (binascii.Error, ValueError) as exc:
        res.errors.append("p= is not valid base64 (%s)" % exc)
        return res

    res.key_bytes = len(der)
    if res.key_type == "rsa":
        res.key_bits = rsa_modulus_bits(der)
        if res.key_bits is None:
            res.warnings.append("could not parse the DER key structure; key size not verified")
    elif res.key_type == "ed25519":
        res.key_bits = len(der) * 8

    if res.tags.get("g"):
        res.warnings.append("g= (granularity) is deprecated and MUST be ignored by verifiers")

    h = res.tags.get("h")
    if h:
        allowed = [x.strip().lower() for x in h.split(":") if x.strip()]
        if "sha1" in allowed:
            res.warnings.append("h= lists sha1, which RFC 8301 removed from DKIM")
        if "sha256" not in allowed:
            res.warnings.append("h=%s does not include sha256; the only hash RFC 8301 allows is sha256" % h)

    if res.tags.get("t"):
        flags = [x.strip() for x in res.tags["t"].split(":") if x.strip()]
        if "y" in flags:
            res.warnings.append("t=y declares this domain as testing; receivers treat failures as passes")
        for flag in flags:
            if flag not in ("y", "s"):
                res.warnings.append("unknown t= flag %r" % flag)

    for tagname in res.tags:
        if tagname not in ("v", "k", "p", "h", "t", "n", "s", "g", "i", "d"):
            res.warnings.append("unknown tag %r" % tagname)
    return res


# ---------------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------------

DMARC_POLICIES = ("none", "quarantine", "reject")
_DMARC_URI_RE = re.compile(r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*):(?P<rest>.+?)(?:!(?P<size>\d+[kmgtKMGT]?))?$")


class DMARCParseResult(object):
    def __init__(self):
        self.tags = {}
        self.errors = []
        self.warnings = []
        self.valid = False
        self.p = None
        self.sp = None
        self.pct = None
        self.adkim = None
        self.aspf = None
        self.rua = []
        self.ruf = []
        self.fo = None
        self.rf = None
        self.ri = None
        self.np = None

    @property
    def enforcing(self):
        return self.p in ("quarantine", "reject")

    def to_dict(self):
        return {
            "valid": self.valid, "p": self.p, "sp": self.sp, "pct": self.pct,
            "adkim": self.adkim, "aspf": self.aspf, "rua": self.rua, "ruf": self.ruf,
            "fo": self.fo, "rf": self.rf, "ri": self.ri, "np": self.np,
            "tags": self.tags, "errors": self.errors, "warnings": self.warnings,
        }


def _split_dmarc_uri(value):
    """Split a DMARC URI from its optional !size limit."""
    value = value.strip()
    m = _DMARC_URI_RE.match(value)
    if not m:
        return value, None, None
    return value, m.group("scheme").lower(), m.group("rest")


def parse_dmarc(record):
    """Parse a DMARC policy record (RFC 7489 section 6.3/6.4)."""
    res = DMARCParseResult()
    if record is None:
        return res

    parts = [p.strip() for p in record.split(";")]
    parts = [p for p in parts if p]

    seen = []
    for chunk in parts:
        if "=" not in chunk:
            res.errors.append("tag without '=': %r" % chunk)
            continue
        name, _, value = chunk.partition("=")
        name = name.strip().lower()
        value = value.strip()
        if name in res.tags:
            res.warnings.append("duplicate tag %r; receivers use the first occurrence" % name)
            continue
        res.tags[name] = value
        seen.append(name)

    if not seen or seen[0] != "v":
        res.errors.append("v= must be the first tag; a receiver discards the whole record")
        return res
    if res.tags.get("v") != "DMARC1":
        res.errors.append("v=%s is not DMARC1; the whole record MUST be ignored" % res.tags.get("v"))
        return res

    if "p" not in res.tags:
        res.errors.append("no p= tag; RFC 7489 requires v and p in that order")
        return res

    p = res.tags["p"].lower()
    if p not in DMARC_POLICIES:
        res.errors.append("p=%s is not one of none/quarantine/reject" % res.tags["p"])
    else:
        res.p = p

    if "sp" in res.tags:
        sp = res.tags["sp"].lower()
        if sp == "":
            res.errors.append("sp= is present but empty; treat it as absent (p applies to subdomains)")
        elif sp not in DMARC_POLICIES:
            res.errors.append("sp=%s is not one of none/quarantine/reject" % res.tags["sp"])
        else:
            res.sp = sp

    if "np" in res.tags:  # RFC 9091
        np = res.tags["np"].lower()
        if np not in DMARC_POLICIES:
            res.errors.append("np=%s is not one of none/quarantine/reject" % res.tags["np"])
        else:
            res.np = np

    if "pct" in res.tags:
        try:
            pct = int(res.tags["pct"])
            if not 0 <= pct <= 100:
                res.errors.append("pct=%s is outside 0-100; the record is invalid" % res.tags["pct"])
            else:
                res.pct = pct
        except ValueError:
            res.errors.append("pct=%s is not an integer; the record is invalid" % res.tags["pct"])

    for tag in ("adkim", "aspf"):
        if tag in res.tags:
            val = res.tags[tag].lower()
            if val not in ("r", "s"):
                res.errors.append("%s=%s must be 'r' (relaxed) or 's' (strict)" % (tag, res.tags[tag]))
            else:
                setattr(res, tag, val)

    for tag, dest in (("rua", res.rua), ("ruf", res.ruf)):
        raw = res.tags.get(tag)
        if raw is None:
            continue
        if raw.strip() == "":
            res.warnings.append("%s= is present but empty, which requests no reports" % tag)
            continue
        for item in raw.split(","):
            item = item.strip()
            if not item:
                continue
            uri, scheme, rest = _split_dmarc_uri(item)
            if scheme is None:
                res.warnings.append("%s=%s is not a URI" % (tag, item))
                continue
            if scheme not in ("mailto", "https"):
                res.warnings.append("%s=%s uses scheme %r; mailto is what receivers support in practice"
                                    % (tag, item, scheme))
            else:
                dest.append({"uri": item, "scheme": scheme, "target": rest})

    if "fo" in res.tags:
        fo = res.tags["fo"]
        allowed = {"0", "1", "d", "s"}
        values = [v.strip() for v in fo.split(":") if v.strip()]
        if not values or not set(values).issubset(allowed):
            res.warnings.append("fo=%s contains values outside 0/1/d/s" % fo)
        else:
            res.fo = fo

    if "rf" in res.tags:
        rf = res.tags["rf"].lower()
        if rf not in ("afrf",):
            res.warnings.append("rf=%s is not a registered report format (only afrf)" % res.tags["rf"])
        else:
            res.rf = rf

    if "ri" in res.tags:
        try:
            ri = int(res.tags["ri"])
            if ri < 0:
                res.warnings.append("ri=%s is negative" % res.tags["ri"])
            else:
                res.ri = ri
        except ValueError:
            res.warnings.append("ri=%s is not an integer" % res.tags["ri"])

    for name in res.tags:
        if name not in ("v", "p", "sp", "np", "pct", "rua", "ruf", "fo", "rf", "ri",
                        "adkim", "aspf"):
            res.warnings.append("unknown tag %r is ignored by receivers" % name)
        if name == "p" and seen.index("p") != 1:
            res.warnings.append("p= should immediately follow v= in the tag order")

    res.valid = res.p is not None
    return res


# ---------------------------------------------------------------------------
# MX
# ---------------------------------------------------------------------------

# MX-host suffix -> the SPF include token a domain is expected to authorise when
# it sends through that provider. This is a HINT derived from observable DNS,
# not proof of how a domain sends mail. See README.md.
MX_PROVIDER_HINTS = [
    ("google.com", "_spf.google.com", "Google Workspace"),
    ("googlemail.com", "_spf.google.com", "Google Workspace"),
    ("outlook.com", "spf.protection.outlook.com", "Microsoft 365"),
    ("protection.outlook.com", "spf.protection.outlook.com", "Microsoft 365"),
    ("pphosted.com", "pphosted.com", "Proofpoint"),
    ("mimecast.com", "mimecast.com", "Mimecast"),
    ("messagelabs.com", "messagelabs.com", "Symantec/Broadcom Email Security"),
    ("iphmx.com", "iphmx.com", "Cisco Email Security"),
    ("barracudanetworks.com", "barracudanetworks.com", "Barracuda"),
    ("hornetsecurity.com", "hornetsecurity.com", "Hornetsecurity"),
    ("zoho.com", "zoho.com", "Zoho Mail"),
    ("secureserver.net", "secureserver.net", "GoDaddy"),
    ("emailsrvr.com", "emailsrvr.com", "Rackspace"),
    ("mailgun.org", "mailgun.org", "Mailgun"),
    ("fastmail.com", "messagingengine.com", "Fastmail"),
    ("messagingengine.com", "messagingengine.com", "Fastmail"),
    ("yandex.net", "spf.yandex.net", "Yandex Mail"),
    ("mail.ru", "mail.ru", "Mail.ru"),
    ("icloud.com", "icloud.com", "iCloud Mail"),
]


def analyse_mx(domain, resolver, verbose_log=None):
    """Return (info dict, list of Finding)."""
    log = verbose_log or (lambda *a, **k: None)
    info = {"records": [], "null_mx": False, "hosts": [], "dangling": [],
            "provider_hints": []}
    findings = []

    resp = resolver.mx(domain)
    info["rcode"] = resp.rcode
    info["error"] = resp.describe_error()
    info["raw"] = [r.to_dict() for r in resp.answers]

    if not resp.ok:
        findings.append(finding(
            "mx.lookup_failed", "INFO", "MX",
            "MX lookup could not be completed",
            "Querying MX for %s failed: %s" % (domain, resp.describe_error()),
            "Without an MX answer this audit cannot tell whether the domain receives mail. "
            "The rest of the report is still valid for SPF, DKIM and DMARC.",
            "Re-run with --resolver or --doh if the failure is local to your network."))
        return info, findings

    mxs = resp.of_type(QTYPE["MX"])
    info["records"] = [[r.value[0], r.value[1]] for r in mxs]

    if not mxs:
        if resp.rcode == "NXDOMAIN":
            info["nxdomain"] = True
            findings.append(finding(
                "mx.nxdomain", "HIGH", "MX",
                "Domain does not exist (NXDOMAIN)",
                "MX lookup for %s returned NXDOMAIN." % domain,
                "A non-existent domain cannot receive mail, and any SPF/DKIM/DMARC record you "
                "publish for it is irrelevant until it resolves.",
                "Check for a typo in the domain name and that the domain is delegated at your "
                "registrar and active in your DNS provider."))
        else:
            findings.append(finding(
                "mx.none", "MEDIUM", "MX",
                "No MX record: the domain does not receive mail",
                "MX query for %s returned %s with no MX records." % (domain, resp.rcode or "NOERROR"),
                "A domain with no MX and no null MX still receives delivery attempts at whatever "
                "its A/AAAA records point to (RFC 7505 section 1). That produces delayed bounces "
                "and backscatter rather than an immediate, clean rejection.",
                "If the domain should not receive mail, publish a null MX:  %s. IN MX 0 .  "
                "(a single MX record, preference 0, exchange '.') and make sure no other MX exists. "
                "If it should receive mail, publish your provider's MX records." % domain))
        return info, findings

    # Null MX: single MX, preference 0, exchange "."
    if len(mxs) == 1 and mxs[0].value[0] == 0 and mxs[0].value[1] in (".", ""):
        info["null_mx"] = True
        findings.append(finding(
            "mx.null", "OK", "MX",
            "Null MX is published: the domain explicitly accepts no mail",
            "Found 'MX 0 .' and no other MX record, which is the RFC 7505 null MX.",
            "This is the correct way to say 'this domain does not receive mail'. It makes senders "
            "fail immediately instead of retrying for days.",
            "No change needed. Keep the record as the only MX for this name."))
        return info, findings

    if any(r.value[1] in (".", "") for r in mxs):
        findings.append(finding(
            "mx.null_mixed", "HIGH", "MX",
            "Null MX is mixed with real MX records",
            "MX set for %s contains both '.' and real exchanges: %s"
            % (domain, ", ".join("%d %s" % (r.value[0], r.value[1]) for r in mxs)),
            "RFC 7505 section 3: a domain that advertises a null MX MUST NOT advertise any other "
            "MX record. Behaviour is then undefined and depends on the receiver.",
            "Remove either the null MX or the real MX records so exactly one intent is published."))

    # Dangling MX hosts: an MX target with no A/AAAA loses mail.
    for rr in mxs:
        host = rr.value[1]
        if host in (".", ""):
            continue
        info["hosts"].append(host)
        a = resolver.query(host, QTYPE["A"])
        aaaa = resolver.query(host, QTYPE["AAAA"])
        has_v4 = a.ok and bool(a.of_type(QTYPE["A"]))
        has_v6 = aaaa.ok and bool(aaaa.of_type(QTYPE["AAAA"]))
        if not has_v4 and not has_v6:
            info["dangling"].append(host)
        for hint_suffix, include_token, provider in MX_PROVIDER_HINTS:
            if host.lower() == hint_suffix or host.lower().endswith("." + hint_suffix):
                info["provider_hints"].append({"host": host, "include": include_token,
                                               "provider": provider})
                break

    if info["dangling"]:
        findings.append(finding(
            "mx.dangling", "HIGH", "MX",
            "MX host has no address record",
            "These MX targets resolve to no A or AAAA record: %s" % ", ".join(info["dangling"]),
            "Senders cannot connect to a host with no address. Mail routed to that MX is delayed "
            "and then bounced, and some senders will retry the other MX records first, which can "
            "look like intermittent failure.",
            "Either correct the MX target in your DNS zone to the hostname your mail provider "
            "documents, or ask the provider for the current MX hostnames."))

    return info, findings

# ---------------------------------------------------------------------------
# SPF audit
# ---------------------------------------------------------------------------

def analyse_spf(domain, resolver, mx_present=False, verbose_log=None):
    log = verbose_log or (lambda *a, **k: None)
    info = {"records": [], "raw": [], "parse": None, "lookups": None,
            "length": {}, "type99": [], "rcode": None, "error": None,
            "mx_present": bool(mx_present)}
    findings = []

    resp = resolver.txt(domain)
    info["rcode"] = resp.rcode
    info["error"] = resp.describe_error()
    info["raw"] = [r.to_dict() for r in resp.answers]

    if not resp.ok:
        findings.append(finding(
            "spf.lookup_failed", "INFO", "SPF",
            "SPF lookup could not be completed",
            "TXT lookup for %s failed: %s" % (domain, resp.describe_error()),
            "No conclusion about SPF can be drawn from a failed lookup. This is a local or "
            "transient network problem, not a finding about the domain.",
            "Re-run the audit. If it keeps failing, try --doh (DNS over HTTPS) or --resolver."))
        return info, findings

    txts, cname, _ = resolver.txt_records(domain)
    if cname:
        info["cname"] = cname
    info["all_txt"] = txts
    spf_records = [t for t in txts if t.strip().lower().startswith("v=spf1")]
    info["records"] = spf_records

    # Legacy SPF RR type (99), obsoleted by RFC 7208 section 3.1 / 14.1.
    t99 = resolver.txt_type99(domain)
    if t99.ok and t99.of_type(QTYPE["SPF"]):
        info["type99"] = t99.txt_strings()
        findings.append(finding(
            "spf.type99", "MEDIUM", "SPF",
            "An obsolete SPF RR (type 99) is published",
            "Found SPF RR type 99 at %s: %s" % (domain, " | ".join(info["type99"])),
            "RFC 7208 section 3.1 moved SPF to the ordinary TXT RR type; the dedicated type 99 "
            "was never widely deployed and is now obsolete. Receivers read TXT only, so this "
            "record does nothing, and it can confuse anyone reading the zone later.",
            "Delete the type 99 SPF record. Keep the policy in a single TXT record at %s "
            "beginning with v=spf1." % domain))

    if not spf_records:
        sev = "HIGH" if mx_present else "MEDIUM"
        findings.append(finding(
            "spf.missing", sev, "SPF",
            "No SPF record is published",
            "No TXT record at %s begins with v=spf1. Other TXT records found: %s"
            % (domain, ", ".join(repr(t[:60]) for t in txts) or "none"),
            "Without SPF, receivers have no list of hosts authorised to send as this domain. "
            "SPF is also one of the two methods DMARC can use to pass, so a missing SPF record "
            "removes half of your alignment options and makes spoofing easier.",
            "Publish one TXT record at %s. If the domain sends no mail at all, publish exactly:\n"
            "    %s.  IN TXT  \"v=spf1 -all\"\n"
            "If it does send mail, authorise only the providers you actually send through "
            "(see templates/ for ready-made records) and end with -all." % (domain, domain)))
        return info, findings

    if len(spf_records) > 1:
        findings.append(finding(
            "spf.multiple", "CRITICAL", "SPF",
            "Multiple SPF records: every check fails with permerror",
            "Found %d TXT records starting with v=spf1 at %s:\n%s"
            % (len(spf_records), domain, "\n".join("    " + r for r in spf_records)),
            "RFC 7208 section 3.2 allows exactly one SPF record per name. When a receiver finds "
            "more than one it returns permerror, and a permerror result is not a pass for SPF. "
            "Some receivers treat permerror as a hard fail. This is one of the most common silent "
            "breaks in SPF, and it usually happens when a second provider is added without "
            "merging into the existing record.",
            "Merge everything into ONE TXT record at %s. Keep a single v=spf1, keep one terminal "
            "all, and put every provider's include in that same record:\n"
            "    %s.  IN TXT  \"v=spf1 include:_spf.google.com include:sendgrid.net -all\"\n"
            "Then delete the other v=spf1 TXT record at the same name." % (domain, domain)))

    # ---- length, in octets, as published
    lengths = []
    for rec in spf_records:
        lengths.append(len(rec.encode("utf-8")))
    strings = []
    for r in resp.answers:
        if r.rtype == 16 and "".join(r.value).strip().lower().startswith("v=spf1"):
            strings = [len(s.encode("utf-8")) for s in r.value]
            break
    info["length"] = {"total_octets": max(lengths) if lengths else 0,
                      "character_strings": strings}
    total = info["length"]["total_octets"]

    if total > 255 and len(strings) <= 1:
        findings.append(finding(
            "spf.length.unsplit", "HIGH", "SPF",
            "SPF record is longer than one DNS character-string can hold",
            "The record is %d octets and is published as a single character-string." % total,
            "A DNS TXT character-string is limited to 255 octets (RFC 1035 section 3.3.14). A "
            "record longer than that must be split across several character-strings in the same "
            "TXT record. Some DNS user interfaces and zone-file generators do this for you and "
            "some do not; if it is not split, the record is invalid in the zone.",
            "Split the record into two or more quoted strings in the same TXT record, for example:\n"
            "    %s.  IN TXT ( \"v=spf1 include:_spf.google.com\"\n"
            "                     \" include:sendgrid.net -all\" )\n"
            "Receivers concatenate the strings, so the policy is unchanged." % domain))
    elif total > 450:
        findings.append(finding(
            "spf.length.long", "MEDIUM", "SPF",
            "SPF record is long enough to risk truncation in transit",
            "The record is %d octets, split into character-strings of %s octets."
            % (total, ", ".join(str(s) for s in strings) or "unknown"),
            "Long TXT answers do not fit in a classic 512-octet UDP DNS response. The reply is "
            "then flagged truncated and the receiver has to retry over TCP. Most receivers do "
            "this correctly, but a resolver that mishandles truncation will see no SPF record at "
            "all, which silently removes SPF from your authentication.",
            "Trim the record: remove providers you no longer send through, replace long include "
            "chains with flatter ones, and drop unused mechanisms. If you cannot shorten it, "
            "verify with the audit tool that the full record is returned (this tool retries over "
            "TCP automatically and reports the octet count above)."))

    parsed = parse_spf(spf_records[0])
    info["parse"] = parsed

    if parsed.errors:
        findings.append(finding(
            "spf.syntax", "CRITICAL", "SPF",
            "SPF record contains syntax errors, so receivers return permerror",
            "Problems found:\n" + "\n".join("    - " + e for e in parsed.errors),
            "RFC 7208 section 4.6.4 and section 6 treat an unparseable record as permerror. Some "
            "receivers map permerror to a hard fail, which means legitimate mail from this domain "
            "can be rejected.",
            "Fix the terms listed above. Present the record as a single line of space-separated "
            "terms beginning with v=spf1 and ending with a terminal all mechanism."))

    # ---- DNS lookup counting
    lookups = count_spf_lookups(spf_records[0], domain, resolver, verbose_log=log)
    info["lookups"] = lookups

    if lookups.over_limit:
        findings.append(finding(
            "spf.lookups.over", "CRITICAL", "SPF",
            "SPF exceeds the 10-DNS-lookup limit: permerror",
            "Counting every lookup-causing term reachable from the record (include, a, mx, ptr, "
            "exists and redirect, recursing into nested includes) gives %d terms:\n%s"
            % (lookups.count, _format_lookup_terms(lookups)),
            "RFC 7208 section 4.6.4: implementations MUST limit these terms to 10 and MUST return "
            "permerror beyond that. Receivers that treat permerror as a fail will reject or "
            "quarantine legitimate mail. This is the most common silent SPF breakage: it appears "
            "whenever another provider is added to an already-deep include chain.",
            "Get the count to 10 or fewer. In order of effort:\n"
            "  1. Remove includes for providers you no longer send through.\n"
            "  2. Replace a chain of nested includes with the provider's flatter include where "
            "one exists.\n"
            "  3. Use ip4:/ip6: for your own fixed sending IPs instead of a: or mx: lookups.\n"
            "  4. Ask the providers you keep for a single consolidated include.\n"
            "Re-run the audit after each change; the count is printed above term by term."))
    elif lookups.near_limit:
        findings.append(finding(
            "spf.lookups.near", "MEDIUM", "SPF",
            "SPF is at or near the 10-DNS-lookup limit",
            "Counted %d lookup-causing terms:\n%s" % (lookups.count, _format_lookup_terms(lookups)),
            "RFC 7208 section 4.6.4 caps these terms at 10. At 8 or more, adding one more "
            "provider or one more nested include pushes the record into permerror, and the "
            "failure appears in production rather than in testing.",
            "Plan the consolidation before your next provider change. Note the count in your "
            "runbook and re-run this audit after every SPF edit."))

    if lookups.depth_exceeded:
        findings.append(finding(
            "spf.lookups.depth", "HIGH", "SPF",
            "Include chain is deeper than the recursion cap",
            "The counter stopped at a nesting depth of %d. The real number of lookup-causing "
            "terms is at least %d." % (SPF_MAX_INCLUDE_DEPTH, lookups.count),
            "A chain this deep already cannot satisfy the 10-term limit. The count reported here "
            "is a lower bound, so the true total is unknown and almost certainly over the limit.",
            "Flatten the include chain. Find which provider is pulling in long sub-chains by "
            "walking the includes shown in the breakdown above."))

    if lookups.cycles:
        findings.append(finding(
            "spf.lookups.cycle", "HIGH", "SPF",
            "Include chain contains a loop",
            "These domains are referenced more than once in the chain and were not re-entered: %s"
            % ", ".join(sorted(set(lookups.cycles))),
            "A cycle means SPF records include each other. Receivers stop recursing and the "
            "authorisation outcome depends on where they stop, so results differ between "
            "receivers.",
            "Break the loop: remove the include that points back into the chain. A domain should "
            "never need to include itself, directly or indirectly."))

    if lookups.void_lookups > SPF_VOID_LOOKUP_LIMIT:
        findings.append(finding(
            "spf.lookups.void", "MEDIUM", "SPF",
            "More than two void lookups",
            "Counted %d void lookups (NXDOMAIN, or NOERROR with no records):\n%s"
            % (lookups.void_lookups,
               "\n".join("    - " + n for n in lookups.notes if "void lookup" in n)),
            "RFC 7208 section 4.6.4: implementations SHOULD limit void lookups to two, and "
            "exceeding that produces permerror. Void lookups usually mean an include points at a "
            "name that no longer exists, for example a provider that renamed its SPF host.",
            "Fix or remove the terms above. Check each include target still resolves and still "
            "publishes an SPF record; providers do rename these hosts, and the old name lingers "
            "in records for years."))
    elif lookups.void_lookups:
        findings.append(finding(
            "spf.lookups.void_low", "LOW", "SPF",
            "Void lookups present (%d of a suggested maximum of 2)" % lookups.void_lookups,
            "\n".join("    - " + n for n in lookups.notes if "void lookup" in n),
            "RFC 7208 section 4.6.4 suggests limiting void lookups to two. One or two is normal "
            "and harmless; it is worth knowing which they are so you notice if the count grows.",
            "No urgent action. Investigate if the count rises above two."))

    for err in lookups.errors:
        findings.append(finding(
            "spf.include.broken", "HIGH", "SPF",
            "An include or redirect target does not publish SPF",
            err,
            "RFC 7208 section 5.2: if the target of include: has no SPF record, the result MUST be "
            "permerror. A broken include does not merely fail to match; it can break the whole "
            "evaluation, and it is easy to miss because the rest of the record looks fine.",
            "Either remove the include or point it at a name that does publish an SPF record. "
            "Check the provider's current documentation: these hosts are renamed more often than "
            "most other DNS records."))

    if lookups.dns_errors:
        findings.append(finding(
            "spf.lookup.dns_error", "INFO", "SPF",
            "Some SPF lookups could not be completed while counting",
            "\n".join("    - " + e for e in lookups.dns_errors),
            "These are network or resolver failures during this audit, not necessarily findings "
            "about the zone. They do mean the count above may be incomplete.",
            "Re-run the audit. If the same names keep failing, test them with --verbose to see "
            "which resolver answered."))

    # ---- the terminal all mechanism
    info["all"] = None
    all_term = parsed.all_term
    redirect = parsed.get_modifier("redirect")
    if all_term is None and redirect is None:
        findings.append(finding(
            "spf.all.missing", "MEDIUM", "SPF",
            "No terminal 'all' mechanism and no redirect",
            "The record has no all mechanism: %s" % spf_records[0],
            "RFC 7208 section 4.7: with no matching mechanism, no all and no redirect, "
            "check_host() returns neutral, which is the same as publishing ?all. A neutral result "
            "is not a pass for SPF and gives receivers no instruction, so unauthorised senders "
            "are neither authorised nor rejected.",
            "End the record with -all once you have confirmed every legitimate sender is "
            "authorised through this domain:\n"
            "    ... -all\n"
            "Use ~all only as a temporary step while you collect evidence."))
    elif all_term is not None:
        qual = all_term.qualifier or "+"
        info["all"] = qual
        if qual == "+":
            findings.append(finding(
                "spf.all.plus", "CRITICAL", "SPF",
                "'+all' authorises the entire internet to send as this domain",
                "The record ends in +all: %s" % spf_records[0],
                "+all matches every sending IP, so SPF returns pass for anyone. Any spammer can "
                "send as this domain and SPF will vouch for them. Combined with a DMARC policy of "
                "p=none this gives almost no protection, and with p=reject the SPF pass will hide "
                "the spoofing from enforcement.",
                "Replace +all with -all once you have listed every legitimate sender. If you are "
                "still discovering senders, use ~all temporarily, never +all."))
        elif qual == "?":
            findings.append(finding(
                "spf.all.neutral", "MEDIUM", "SPF",
                "'?all' declares no policy for unauthorised senders",
                "The record ends in ?all: %s" % spf_records[0],
                "?all means neutral: receivers are told nothing about mail from unlisted hosts. "
                "Unauthorised senders get no signal, and SPF contributes nothing to DMARC unless "
                "it returns pass.",
                "Change the final mechanism to -all once the sender list is complete."))
        elif qual == "~":
            findings.append(finding(
                "spf.all.softfail", "LOW", "SPF",
                "'~all' softfails unauthorised senders rather than rejecting them",
                "The record ends in ~all: %s" % spf_records[0],
                "~all marks unlisted senders as softfail. Many receivers treat softfail as "
                "harmless, so spoofed mail often still reaches the inbox. It is the conventional "
                "setting while you are still finding senders, not the end state.",
                "Once the DMARC reports show every legitimate sender passing, change ~all to -all. "
                "See docs/MIGRATION-TO-ENFORCEMENT.md for the order to make that change in."))
        else:
            findings.append(finding(
                "spf.all.hardfail", "OK", "SPF",
                "'-all' hardfails unauthorised senders",
                "The record ends in -all: %s" % spf_records[0],
                "This is the recommended terminal mechanism: senders not listed are explicitly "
                "not authorised.",
                "No change needed. Make sure every legitimate sender is listed before you rely "
                "on it, because a missing sender now fails SPF outright."))

    # ---- discouraged mechanisms
    for term in parsed.mechanisms:
        if term.name == "ptr":
            findings.append(finding(
                "spf.ptr", "MEDIUM", "SPF",
                "'ptr' mechanism is deprecated and should not be published",
                "Term found: %s" % term.raw,
                "RFC 7208 section 5.5 is titled 'ptr (do not use)' and says the mechanism SHOULD "
                "NOT be published. It depends on reverse DNS you do not control, it is slow, and "
                "receivers are free to skip it entirely, so it produces different results at "
                "different receivers.",
                "Remove the ptr term and authorise the sending hosts by ip4:/ip6: or by the "
                "provider's include: instead."))
        elif term.name == "exists":
            findings.append(finding(
                "spf.exists", "LOW", "SPF",
                "'exists' mechanism is valid but expensive and easy to misuse",
                "Term found: %s" % term.raw,
                "exists is not deprecated: RFC 7208 section 5.7 defines it and it counts as one "
                "of the 10 lookup-causing terms. It is discouraged in practice because it turns an "
                "SPF record into an arbitrary DNS query, it is often used to build dynamic "
                "allow-lists that nobody can audit, and each one consumes budget you may need for "
                "include:.",
                "Confirm you still need it. If it was added for a specific provider, check whether "
                "that provider now offers a plain include: instead."))

    if parsed.get_modifier("exp") is not None:
        findings.append(finding(
            "spf.exp", "INFO", "SPF",
            "'exp=' explanation string is published",
            "Term found: exp=%s" % parsed.get_modifier("exp").arg,
            "exp= is only fetched when a receiver produces a fail result, and few receivers "
            "display it. It does not count against the 10-lookup limit because it is not queried "
            "during evaluation.",
            "No action required. Keep it working only if you want the explanation text shown."))

    for warn in parsed.warnings:
        if "unknown modifier" in warn:
            findings.append(finding(
                "spf.modifier.unknown", "LOW", "SPF",
                "Unrecognised SPF modifier",
                warn,
                "RFC 7208 section 6 says unknown modifiers MUST be ignored. The term has no "
                "effect; the risk is that it was meant to do something.",
                "Remove it, or check whether you meant a mechanism instead of a modifier."))

    if lookups.terms and parsed.errors == [] and not lookups.over_limit and not lookups.near_limit:
        findings.append(finding(
            "spf.ok", "OK", "SPF",
            "SPF record is present, parses, and is within the lookup limit",
            "One SPF record with %d lookup-causing terms (limit 10). Terminal mechanism: %s"
            % (lookups.count, ("'%s'" % all_term.raw) if all_term else "none"),
            "SPF is syntactically valid and receivers can evaluate it without hitting the "
            "10-term permerror.",
            "No structural change needed. Re-check whenever you add or remove a sending provider."))

    return info, findings


def _format_lookup_terms(lookups):
    lines = []
    for t in lookups.terms:
        lines.append("    %2d. %-30s depth %d  from %s%s"
                     % (t["index"], t["term"], t["depth"], t["source_record"],
                        "" if t.get("resolved") in (None, "resolved", "recursed") else
                        "  [%s]" % t["resolved"]))
    return "\n".join(lines) if lines else "    (none)"


# ---------------------------------------------------------------------------
# DKIM audit
# ---------------------------------------------------------------------------

# Selector names that appear commonly in the wild. A hit here is a verified DNS
# fact. A miss proves NOTHING: DKIM selectors are arbitrary strings chosen by the
# sender and there is no registry and no way to enumerate them.
COMMON_SELECTOR_GUESSES = [
    "google", "selector1", "selector2", "s1", "s2", "k1", "k2", "dkim", "default",
    "mail", "smtp", "mandrill", "mta", "pm", "pm1", "pm2", "resend", "sendgrid",
    "smtpapi", "cm", "protonmail", "zoho", "mx", "email", "exim", "postfix",
]

DKIM_CNAME_WARNING = ("The DKIM record name is a CNAME. That works at receivers which follow "
                      "CNAMEs for TXT lookups, but RFC 6376 section 3.6.1 expects the key "
                      "record to exist at the _domainkey name itself, and some verifiers do "
                      "not chase aliases. It is safest to publish the TXT record directly.")


def analyse_dkim(domain, selectors, resolver, guess=False, verbose_log=None):
    log = verbose_log or (lambda *a, **k: None)
    info = {"selectors": [], "guessed": {}, "selector_supplied": bool(selectors)}
    findings = []

    order = []
    for s in (selectors or []):
        if s not in order:
            order.append(s)
    guesses_used = []
    if guess:
        for cand in COMMON_SELECTOR_GUESSES:
            if cand in order:
                continue
            guesses_used.append(cand)
            order.append(cand)

    if not order:
        info["note"] = ("No DKIM selector was supplied, so DKIM was not checked. Selectors are "
                        "arbitrary names chosen by the sender; they cannot be enumerated from "
                        "DNS. Pass --dkim-selector (repeatable) to check specific ones.")
        findings.append(finding(
            "dkim.not_checked", "INFO", "DKIM",
            "DKIM not checked: no selector supplied",
            info["note"],
            "A DKIM public key lives at <selector>._domainkey.<domain>. The selector is a free "
            "choice made by whoever set up signing, so there is no DNS method to discover it: "
            "selectors cannot be enumerated, and the only names you can query are ones you "
            "already know. Many tools claim to find your DKIM records automatically; what they "
            "are actually doing is trying a list of common names and reporting the hits, which "
            "means a miss tells you nothing.",
            "Find your selector where the key was created. It is shown in the DKIM page of your "
            "provider's console and it is the part before ._domainkey in the CNAME or TXT record "
            "they gave you. Then run:\n"
            "    python3 audit.py --domain %s --dkim-selector YOUR_SELECTOR\n"
            "You can pass the flag more than once. If you do not know it, add --guess-selectors "
            "to try a list of names seen in the wild; a hit is proof, a miss proves nothing."
            % domain))
        if guesses_used:
            pass
        return info, findings

    for sel in order:
        guessed = sel in guesses_used
        name = "%s._domainkey.%s" % (sel, domain)
        entry = {"selector": sel, "name": name, "guessed": guessed}
        resp = resolver.txt(name)
        entry["rcode"] = resp.rcode
        entry["error"] = resp.describe_error()
        entry["raw"] = [r.to_dict() for r in resp.answers]

        records, cname, _ = resolver.txt_records(name)
        if cname:
            entry["cname"] = cname
        entry["records"] = records
        entry["record"] = records[0] if records else None

        if not resp.ok:
            entry["status"] = "lookup-failed"
            info["selectors"].append(entry)
            if not guessed:
                findings.append(finding(
                    "dkim.lookup_failed", "INFO", "DKIM",
                    "DKIM lookup for selector %r could not be completed" % sel,
                    "TXT lookup for %s failed: %s" % (name, resp.describe_error()),
                    "A failed lookup says nothing about whether the key exists.",
                    "Re-run the audit, or use --doh to query over HTTPS."))
            continue

        if not records:
            entry["status"] = "absent"
            info["selectors"].append(entry)
            if guessed:
                info["guessed"][sel] = "absent"
                continue
            if resp.rcode == "NXDOMAIN":
                state_line = ("TXT lookup for %s returned NXDOMAIN: the name does not exist in "
                              "DNS at all, so this selector has no key record." % name)
            elif resp.nodata:
                state_line = ("TXT lookup for %s returned NOERROR with an empty answer (NODATA): "
                              "the name exists but publishes no TXT record." % name)
                if cname:
                    state_line += (" It is a CNAME to %s, and that target published no TXT "
                                   "record either." % cname)
            else:
                state_line = ("TXT lookup for %s returned %s with no usable TXT record."
                              % (name, resp.rcode or "NOERROR"))
            findings.append(finding(
                "dkim.missing", "HIGH", "DKIM",
                "No DKIM key record at selector %r" % sel,
                state_line + "\n"
                "This is a MISSING record, not a revoked key: a revoked key is a record that "
                "exists and carries an empty p= tag (v=DKIM1; p=), which is a different finding.",
                "Either the selector name is wrong or the key was never published. A selector "
                "name that does not exist looks exactly like DKIM that was never configured, and "
                "both mean receivers cannot verify your signature for this selector. Mail signed "
                "with an unpublished key fails DKIM, which also removes one of DMARC's two ways "
                "to pass.",
                "Check the selector in your provider's DKIM console and compare it character by "
                "character with the one you passed. Then confirm the record exists at\n"
                "    %s   IN TXT  \"v=DKIM1; k=rsa; p=...\"\n"
                "Copy the record from the provider console: the public key is unique to your "
                "account and cannot be guessed or reused from documentation." % name))
            continue

        parsed = parse_dkim(records[0])
        entry["parsed"] = parsed
        entry["status"] = "revoked" if parsed.revoked else "present"
        info["selectors"].append(entry)

        if guessed:
            info["guessed"][sel] = entry["status"]
            findings.append(finding(
                "dkim.guessed_hit", "INFO", "DKIM",
                "Selector %r exists (found by --guess-selectors)" % sel,
                "%s returned a DKIM record: %s" % (name, _redact_dkim(records[0])),
                "This is a real DNS fact: the name exists and publishes a key record. It does "
                "not by itself prove that your mail is signed with this selector.",
                "Confirm in your provider's console that this is the selector currently used for "
                "signing, then pin it: run the audit again with --dkim-selector %s so it is "
                "always checked." % sel))
            continue

        if parsed.revoked:
            findings.append(finding(
                "dkim.revoked", "HIGH", "DKIM",
                "DKIM key at selector %r is revoked" % sel,
                "%s exists but its p= tag is empty: %s" % (name, _redact_dkim(records[0])),
                "RFC 6376 section 3.6.1: an empty p= tag means the public key has been revoked. "
                "Receivers that see this treat every signature made with the matching private key "
                "as unverifiable, so DKIM fails for that selector. A revoked key is deliberate: "
                "someone rotated or disabled it. The danger is that the sender is still signing "
                "with it, which is silent because nothing reports an error.",
                "If you rotated keys, make sure new mail is signed with the new selector and that "
                "the new selector's record is published. If you are not sending with this selector "
                "any more, deleting the empty record is cleaner than leaving it, because an empty "
                "p= is a public statement that the key is dead. Re-run with --dkim-selector to "
                "confirm the selector you actually sign with."))
        elif parsed.errors:
            findings.append(finding(
                "dkim.invalid", "HIGH", "DKIM",
                "DKIM record at selector %r is present but not usable" % sel,
                "%s: %s\nProblems: %s" % (name, _redact_dkim(records[0]),
                                          "; ".join(parsed.errors)),
                "A record that cannot be parsed cannot verify a signature. Receivers will treat "
                "signatures made with this key as failing.",
                "Re-copy the record from your provider's console. It must begin with v=DKIM1 and "
                "contain p= followed by the base64 public key with no line breaks or stray "
                "characters."))
        else:
            findings.append(finding(
                "dkim.ok", "OK", "DKIM",
                "DKIM key present and parseable at selector %r" % sel,
                "%s: k=%s, key size %s bits, tags: %s"
                % (name, parsed.key_type, parsed.key_bits if parsed.key_bits else "unknown",
                   ", ".join(sorted(parsed.tags))),
                "The public key is published and well formed, so signatures made with the "
                "matching private key can be verified by receivers.",
                "No change needed. Re-run this audit after any key rotation."))

        if parsed.key_type == "rsa" and parsed.key_bits:
            if parsed.key_bits < 1024:
                findings.append(finding(
                    "dkim.weak", "HIGH", "DKIM",
                    "DKIM RSA key is shorter than 1024 bits",
                    "Selector %r publishes a %d-bit RSA key." % (sel, parsed.key_bits),
                    "RFC 8301 section 3.2: signers MUST use RSA keys of at least 1024 bits and "
                    "verifiers MUST NOT consider signatures with keys under 1024 bits valid. So "
                    "this key cannot produce a passing DKIM result anywhere.",
                    "Generate a new key pair with at least 2048 bits, publish the new selector "
                    "first, switch signing over, and only then remove the old record. See "
                    "templates/ for the staged rotation pattern."))
            elif parsed.key_bits < 2048:
                findings.append(finding(
                    "dkim.1024", "MEDIUM", "DKIM",
                    "DKIM RSA key is 1024 bits",
                    "Selector %r publishes a %d-bit RSA key." % (sel, parsed.key_bits),
                    "RFC 8301 section 3.2 says signers MUST use at least 1024 bits, which this "
                    "meets, and SHOULD use at least 2048. Some receivers use key length as one "
                    "signal when judging a signature, and 1024-bit RSA is no longer a comfortable "
                    "margin.",
                    "Rotate to 2048 bits at your next convenient window. Publish the new selector "
                    "alongside the old one, switch signing over, watch DMARC reports for a day or "
                    "two, then remove the old selector."))

        if parsed.key_type == "ed25519" and parsed.key_bytes != 32:
            findings.append(finding(
                "dkim.ed25519_size", "MEDIUM", "DKIM",
                "ed25519 public key is not 32 bytes",
                "Selector %r decoded to %s bytes, expected 32." % (sel, parsed.key_bytes),
                "RFC 8463 defines ed25519 DKIM keys as the 32-octet raw public key. A different "
                "length means the record is malformed or the k= tag does not match the key.",
                "Re-copy the record from the provider console, or correct the k= tag."))

        for warn in parsed.warnings:
            if "testing" in warn:
                findings.append(finding(
                    "dkim.testing", "MEDIUM", "DKIM",
                    "Selector %r declares testing mode" % sel,
                    warn,
                    "RFC 6376 section 3.6.1: with t=y, receivers should not treat a failed "
                    "signature as a failure. Testing mode is a debugging setting, and leaving it "
                    "on means a broken signature will not be reported to you through DMARC "
                    "failure data.",
                    "Remove t=y from the record once signing is verified. Re-check the tag list "
                    "shown above after the change."))
            elif "deprecated" in warn:
                findings.append(finding(
                    "dkim.g", "LOW", "DKIM",
                    "Selector %r uses the deprecated g= tag" % sel,
                    warn,
                    "g= (granularity) is deprecated in RFC 6376 section 3.6.1 and verifiers must "
                    "ignore it, so it changes no behaviour while making the record harder to read.",
                    "Remove g= from the record."))
            else:
                findings.append(finding(
                    "dkim.tag_warning", "LOW", "DKIM",
                    "DKIM record at selector %r has a non-blocking problem" % sel,
                    warn,
                    "This does not stop the key from working, but it is either obsolete or "
                    "unexpected and worth cleaning up while you are in the zone file.",
                    "Compare against the record your provider documents and remove the "
                    "unnecessary tags."))

        if cname:
            findings.append(finding(
                "dkim.cname", "MEDIUM", "DKIM",
                "Selector %r resolves through a CNAME" % sel,
                "%s is a CNAME to %s." % (name, cname),
                DKIM_CNAME_WARNING,
                "Replace the CNAME with the TXT record it points at, taken from your provider's "
                "console. If the provider rotates the key at the target and expects the CNAME, "
                "leave it and simply note the limitation."))

    return info, findings


def _redact_dkim(record):
    """Show a DKIM record without dumping a full public key into the report."""
    out = []
    for chunk in record.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        if chunk.lower().startswith("p=") and len(chunk) > 24:
            out.append("p=<%d base64 characters omitted>" % (len(chunk) - 2))
        else:
            out.append(chunk)
    return "; ".join(out)

# ---------------------------------------------------------------------------
# DMARC audit
# ---------------------------------------------------------------------------

def analyse_dmarc(domain, resolver, spf_info, dkim_info, verbose_log=None):
    log = verbose_log or (lambda *a, **k: None)
    info = {"records": [], "raw": [], "parents": {}, "external_auth": [],
            "rcode": None, "error": None}
    findings = []

    name = "_dmarc.%s" % domain
    resp = resolver.txt(name)
    info["rcode"] = resp.rcode
    info["error"] = resp.describe_error()
    info["raw"] = [r.to_dict() for r in resp.answers]
    if not resp.ok:
        findings.append(finding(
            "dmarc.lookup_failed", "INFO", "DMARC",
            "DMARC lookup could not be completed",
            "TXT lookup for %s failed: %s" % (name, resp.describe_error()),
            "No conclusion about DMARC can be drawn from a failed lookup.",
            "Re-run the audit, or use --doh to query over HTTPS."))
        return info, findings

    records, cname, _ = resolver.txt_records(name)
    if cname:
        info["cname"] = cname
    info["all_txt"] = records
    dmarc_records = [t for t in records if t.strip().lower().startswith("v=dmarc1")]
    other_txt = [t for t in records if t not in dmarc_records]
    info["records"] = dmarc_records
    info["other_txt"] = other_txt

    # Inheritance: walk up to see what a parent publishes.
    for parent in parent_domains(domain):
        presp = resolver.txt("_dmarc.%s" % parent)
        if presp.ok and presp.rcode == "NOERROR":
            precs = [t for t in presp.txt_strings() if t.strip().lower().startswith("v=dmarc1")]
            info["parents"][parent] = precs
    if not dmarc_records:
        inherited = [(p, r) for p, r in info["parents"].items() if r]
        if inherited:
            p, r = inherited[0]
            findings.append(finding(
                "dmarc.inherited", "MEDIUM", "DMARC",
                "No DMARC record here; a parent domain's policy applies",
                "%s publishes no v=DMARC1 record, but _dmarc.%s does: %s" % (domain, p, r[0]),
                "RFC 7489 section 6.6.3: when a domain has no DMARC record, receivers look up the "
                "Organizational Domain and use that policy if one exists. So this name is covered "
                "by a policy someone else set, which is convenient but easy to forget: the "
                "subdomain policy of that record decides what happens to mail from this name.",
                "Decide deliberately. If the parent policy is what you want, publish it here too "
                "so it is visible on this domain, and check whether the parent's sp= tag covers "
                "you. If you want different handling, publish an explicit record at\n"
                "    %s   IN TXT  \"v=DMARC1; p=none; rua=mailto:dmarc-reports@%s\"\n"
                "and see docs/MIGRATION-TO-ENFORCEMENT.md for the enforcement path." % (name, domain)))
        else:
            findings.append(finding(
                "dmarc.missing", "HIGH", "DMARC",
                "No DMARC record is published",
                "No TXT record at %s begins with v=DMARC1, and no parent domain publishes one "
                "either." % name,
                "Without DMARC, nothing ties your SPF and DKIM results to the domain in the From "
                "header, so a spoofed message that passes neither check is still delivered "
                "normally. You also receive no reports, which means you have no data about who is "
                "sending as your domain. Mailbox providers have also made DMARC part of their "
                "documented bulk-sender requirements, so its absence is an active deliverability "
                "risk rather than just a missing hardening step.",
                "Start with reporting, not enforcement. Publish:\n"
                "    %s   IN TXT  \"v=DMARC1; p=none; rua=mailto:dmarc-reports@%s; fo=1\"\n"
                "Use an address you control. Then follow docs/MIGRATION-TO-ENFORCEMENT.md: read "
                "the aggregate reports for at least two weeks, list every legitimate sender, and "
                "only then move to quarantine and reject." % (name, domain)))
        return info, findings

    if len(dmarc_records) > 1:
        findings.append(finding(
            "dmarc.multiple", "HIGH", "DMARC",
            "Multiple DMARC records: the policy is not applied at all",
            "Found %d TXT records starting with v=DMARC1 at %s:\n%s"
            % (len(dmarc_records), name, "\n".join("    " + r for r in dmarc_records)),
            "RFC 7489 section 6.6.3 step 5: if the set of usable records contains more than one, "
            "policy discovery terminates and DMARC processing is not applied. This is a silent "
            "failure: publishing two records does not give you the stricter of the two, it gives "
            "you none of them.",
            "Keep exactly one v=DMARC1 TXT record at %s and delete the other. If two teams or two "
            "providers each added one, agree on a single merged record." % name))

    parsed = parse_dmarc(dmarc_records[0])
    info["parse"] = parsed

    if parsed.errors:
        findings.append(finding(
            "dmarc.syntax", "HIGH", "DMARC",
            "DMARC record has a validity problem",
            "Record: %s\nProblems:\n%s" % (dmarc_records[0],
                                           "\n".join("    - " + e for e in parsed.errors)),
            "RFC 7489 section 6.6.3 step 6: if the record has no valid p tag, or an invalid sp "
            "tag, then a receiver acts as if p=none when a valid rua is present, and applies no "
            "DMARC at all when one is not. So a malformed record can quietly reduce your policy to "
            "nothing, or switch DMARC off entirely.",
            "Rewrite the record with exactly one v=DMARC1 first, then p= with one of "
            "none/quarantine/reject:\n"
            "    %s   IN TXT  \"v=DMARC1; p=none; rua=mailto:dmarc-reports@%s\"\n"
            "Keep the tag order v then p; other tags can follow in any order." % (name, domain)))

    if other_txt:
        findings.append(finding(
            "dmarc.extra_txt", "INFO", "DMARC",
            "Non-DMARC TXT records exist at the _dmarc name",
            "\n".join("    " + t for t in other_txt),
            "These records are ignored by analysis because they do not start with v=DMARC1. They "
            "are usually leftovers or verification tokens published at the wrong name.",
            "Check whether they belong somewhere else. Only one record at this name matters."))

    p = parsed.p
    rua_ok = [d for d in parsed.rua if d["scheme"] in ("mailto", "https")]

    if p == "none":
        if not rua_ok:
            findings.append(finding(
                "dmarc.none.no_rua", "HIGH", "DMARC",
                "p=none with no usable reporting address: monitoring that reports nowhere",
                "Record: %s\nNo rua= address was accepted from this record." % dmarc_records[0],
                "p=none asks receivers to deliver everything and to tell you what they saw. With "
                "no rua= there is nobody to tell, so the record provides none of DMARC's benefits: "
                "no spoofing protection and no visibility. It is the most common way a domain "
                "stays on p=none for years without ever progressing to enforcement, because the "
                "reports that would justify the next step never arrive.",
                "Add an aggregate reporting address you control:\n"
                "    %s   IN TXT  \"v=DMARC1; p=none; rua=mailto:dmarc-reports@%s; fo=1\"\n"
                "Then read the reports as described in docs/MIGRATION-TO-ENFORCEMENT.md and use "
                "them to move to p=quarantine and p=reject." % (name, domain)))
        else:
            findings.append(finding(
                "dmarc.none", "MEDIUM", "DMARC",
                "p=none: reporting only, no enforcement",
                "Record: %s\nReporting addresses: %s"
                % (dmarc_records[0], ", ".join(d["uri"] for d in rua_ok)),
                "p=none tells receivers to deliver mail that fails DMARC and to send you reports. "
                "It is the correct starting point, and it is not a protection: spoofed mail is "
                "still delivered. Domains that stay here permanently get the reporting without "
                "the benefit.",
                "Work through docs/MIGRATION-TO-ENFORCEMENT.md: collect at least two weeks of "
                "reports, list every legitimate sender with its source IP and result, then move to "
                "p=quarantine; pct=25 and finally p=reject."))

    elif p in ("quarantine", "reject"):
        # "SPF could not be checked" is NOT "SPF is broken". Keep them separate:
        # a failed lookup must not be reported as an enforcing policy sitting on
        # top of broken authentication, because the reader would act on it.
        spf_unknown = bool(spf_info.get("error"))
        spf_ok = (not spf_unknown) and bool(spf_info.get("records")) and not (
            spf_info.get("parse") and spf_info["parse"].errors)
        lookups = spf_info.get("lookups")
        if lookups and lookups.over_limit:
            spf_ok = False
        verified_dkim = [e for e in dkim_info.get("selectors", [])
                         if e.get("status") == "present" and e.get("parsed")
                         and not e["parsed"].errors]
        dkim_checked = bool(dkim_info.get("selector_supplied"))

        if spf_unknown and not verified_dkim:
            findings.append(finding(
                "dmarc.enforcing.unverified", "INFO", "DMARC",
                "p=%s is enforcing, but SPF could not be checked in this run" % p,
                "The DMARC policy is p=%s. %s%s"
                % (p, _spf_problem_summary(spf_info),
                   "" if dkim_checked else
                   " No DKIM selector was supplied, so DKIM was not checked either."),
                "This finding says nothing about the domain. It says the audit could not see the "
                "SPF record, so it cannot tell you whether SPF is usable. If it is not, and DKIM "
                "is not covering the domain either, an enforcing policy will affect legitimate "
                "mail that fails alignment.",
                "Re-run the audit so the SPF lookup succeeds, and supply a DKIM selector if you "
                "know one. --doh and --resolver can work around a blocked or broken resolver on "
                "your side."))
        elif not spf_ok and not verified_dkim:
            if not dkim_checked:
                findings.append(finding(
                    "dmarc.enforcing.risky", "CRITICAL", "DMARC",
                    "p=%s is enforcing but the one method we could check is not working" % p,
                    "The DMARC policy is p=%s. SPF is not usable: %s No DKIM selector was supplied, "
                    "so DKIM could not be checked at all."
                    % (p, _spf_problem_summary(spf_info)),
                    "A DMARC check passes when SPF or DKIM passes AND aligns with the From domain. "
                    "SPF cannot pass here. Whether DKIM covers you is unknown, because selectors "
                    "cannot be discovered from DNS. If DKIM is also not signing this domain, every "
                    "message that fails alignment is %s, and legitimate mail is affected too."
                    % ("quarantined" if p == "quarantine" else "rejected"),
                    "Establish the DKIM position before you trust this policy:\n"
                    "  1. Find the selector in your provider's DKIM console.\n"
                    "  2. Re-run: python3 audit.py --domain %s --dkim-selector SELECTOR\n"
                    "  3. If SPF or DKIM is broken, drop to p=none temporarily to keep mail "
                    "flowing, fix the sender, then step back up using pct=. See "
                    "docs/COMMON-BREAKAGES.md." % domain))
            else:
                findings.append(finding(
                    "dmarc.enforcing.broken", "CRITICAL", "DMARC",
                    "p=%s is enforcing while both SPF and DKIM look broken" % p,
                    "DMARC policy is p=%s. SPF is not usable: %s DKIM was checked and no supplied "
                    "selector produced a working key."
                    % (p, _spf_problem_summary(spf_info)),
                    "DMARC passes only when SPF or DKIM passes and aligns. Neither does here, so "
                    "every message that fails alignment is %s. That includes your own legitimate "
                    "mail if it is sent through a path you have not authorised."
                    % ("quarantined" if p == "quarantine" else "rejected"),
                    "This is urgent: legitimate mail is likely being dropped or filed as spam now. "
                    "Fix it in this order:\n"
                    "  1. Publish p=none with rua= immediately to stop the damage while you "
                    "investigate.\n"
                    "  2. Repair SPF (see the SPF findings above) and publish the correct DKIM "
                    "selector.\n"
                    "  3. Confirm with reports that legitimate senders pass, then step back up "
                    "with pct=25, 50, 100. docs/MIGRATION-TO-ENFORCEMENT.md has the sequence."))
        elif spf_unknown:
            findings.append(finding(
                "dmarc.enforcing.unverified", "INFO", "DMARC",
                "p=%s is enforcing, but SPF could not be checked in this run" % p,
                "The DMARC policy is p=%s. %s DKIM: %s"
                % (p, _spf_problem_summary(spf_info),
                   ", ".join("selector %s ok" % e["selector"] for e in verified_dkim)),
                "This finding says nothing about the domain. The SPF record could not be read, so "
                "this audit cannot tell you whether SPF is usable. DKIM verifies at least one "
                "selector, which is a real result, but you cannot assume every sender signs with a "
                "selector you have verified.",
                "Re-run the audit so the SPF lookup succeeds. --doh and --resolver can work around "
                "a blocked or broken resolver on your side."))
        elif not spf_ok:
            findings.append(finding(
                "dmarc.enforcing.spf", "MEDIUM", "DMARC",
                "p=%s is enforcing with SPF not usable; DKIM must carry the alignment" % p,
                "SPF problem: %s DKIM: %s"
                % (_spf_problem_summary(spf_info),
                   ", ".join("selector %s ok" % e["selector"] for e in verified_dkim)),
                "With p=%s, any message where neither SPF nor DKIM passes and aligns is %s. DKIM "
                "verifies at least one selector, so mail signed with that selector is protected "
                "even though SPF is not usable. But you cannot assume every sender signs with a "
                "selector you have verified, and SPF failures will still show up in reports."
                % (p, "quarantined" if p == "quarantine" else "rejected"),
                "Fix SPF anyway: it costs nothing and removes a single point of failure. Then "
                "confirm from the aggregate reports that no legitimate sender appears as both SPF "
                "fail and DKIM fail."))
        else:
            findings.append(finding(
                "dmarc.enforcing.ok", "OK", "DMARC",
                "p=%s is enforcing and SPF is usable" % p,
                "DMARC: %s\nSPF is present, parses, and is within the lookup limit."
                % dmarc_records[0],
                "An enforcing policy with working authentication is the target state: spoofed "
                "mail that fails alignment is %s."
                % ("quarantined" if p == "quarantine" else "rejected"),
                "Keep monitoring the aggregate reports. Watch for new senders appearing as "
                "failing, which is what a broken sender looks like from the outside."))

    if parsed.pct is not None:
        if parsed.pct == 0:
            findings.append(finding(
                "dmarc.pct0", "HIGH", "DMARC",
                "pct=0 disables enforcement entirely",
                "Record: %s" % dmarc_records[0],
                "pct=0 means the policy is applied to no messages. The record looks enforcing but "
                "behaves like p=none for delivery purposes.",
                "Either remove pct= (which means 100) or raise it as the reports justify."))
        elif parsed.pct < 100 and p in ("quarantine", "reject"):
            findings.append(finding(
                "dmarc.pct", "INFO", "DMARC",
                "pct=%d: the policy is applied to only part of your mail" % parsed.pct,
                "Record: %s" % dmarc_records[0],
                "RFC 7489 section 6.6.4: a receiver MUST NOT apply the policy to more than pct "
                "percent of affected messages, and with p=reject the remainder get quarantine "
                "treatment instead. pct= is the right tool for stepping up gradually, and a "
                "liability if it is left in place: a percentage of spoofed mail is still "
                "delivered, and different receivers sample differently.",
                "Once the reports are clean, raise pct= in steps (for example 25, 50, 100) and "
                "finish at pct=100, or omit pct= entirely, which means 100. Do not leave a "
                "staged value in production permanently."))
        elif p == "none":
            findings.append(finding(
                "dmarc.pct.none", "LOW", "DMARC",
                "pct= has no effect while p=none",
                "Record: %s" % dmarc_records[0],
                "pct= limits how much of the enforcement policy is applied. With p=none there is "
                "nothing to limit, so the tag is inert and only adds noise.",
                "Remove pct= until you move to quarantine or reject."))

    if parsed.sp is None and p in ("quarantine", "reject"):
        findings.append(finding(
            "dmarc.sp.missing", "INFO", "DMARC",
            "No sp= tag: subdomains inherit p=%s" % p,
            "Record: %s" % dmarc_records[0],
            "RFC 7489 section 6.3: when sp= is absent, the p= policy applies to subdomains of "
            "this domain as well. That is usually what you want, but it means any subdomain that "
            "sends mail through a path you have not authorised will be %s along with the "
            "spoofers." % ("quarantined" if p == "quarantine" else "rejected"),
            "Check which subdomains send mail, for example transactional mail from a subdomain "
            "delegated to a provider. Either authorise each one (SPF include and a DKIM selector) "
            "or publish an explicit sp= policy that matches your intent, such as sp=quarantine "
            "while you finish the rollout on subdomains."))
    elif parsed.sp is not None:
        findings.append(finding(
            "dmarc.sp", "INFO", "DMARC",
            "sp=%s sets the subdomain policy" % parsed.sp,
            "Record: %s" % dmarc_records[0],
            "sp= overrides p= for subdomains of this domain. It is the tag to use when "
            "subdomains are at a different stage of readiness from the main domain.",
            "No action needed unless the subdomain situation changes. See the subdomain section "
            "of docs/GLOSSARY-AND-FAQ.md for how inheritance works across label levels."))

    for tag, mode in (("adkim", parsed.adkim), ("aspf", parsed.aspf)):
        if mode == "s":
            findings.append(finding(
                "dmarc.%s.strict" % tag, "INFO", "DMARC",
                "%s=s uses strict alignment" % tag,
                "Record: %s" % dmarc_records[0],
                "Strict alignment requires an exact domain match between the From domain and the "
                "%s domain. Relaxed alignment (the default, r) accepts the Organizational Domain "
                "as well. Strict is stronger but breaks setups where a provider signs or sends as "
                "a subdomain, for example From: you@mail.example.com signed with d=example.com."
                % ("DKIM d=" if tag == "adkim" else "SPF envelope"),
                "Leave it strict only if every sender uses the same exact domain in both places. "
                "Otherwise change it to %s=r, or fix the sender to align exactly." % tag))
        elif mode == "r":
            pass

    if parsed.np is not None:
        findings.append(finding(
            "dmarc.np", "INFO", "DMARC",
            "np=%s sets the policy for non-existent subdomains" % parsed.np,
            "Record: %s" % dmarc_records[0],
            "RFC 9091 adds np= for subdomains that do not exist. It protects against mail "
            "forged from a random subdomain of your domain, which is a common spamming pattern.",
            "No action needed. np=reject is a sensible setting on domains you fully control."))

    # ---- external report destinations need authorisation (RFC 7489 section 7.1)
    for kind, items in (("rua", parsed.rua), ("ruf", parsed.ruf)):
        for item in items:
            target = item.get("target") or ""
            host = target.split("@")[-1].split("/")[0].strip()
            if not host:
                continue
            if registrable_like(host) == registrable_like(domain):
                continue
            auth_name = "%s._report._dmarc.%s" % (domain, host)
            aresp = resolver.txt(auth_name)
            found = []
            if aresp.ok and aresp.rcode == "NOERROR":
                found = [t for t in aresp.txt_strings() if t.strip().lower().startswith("v=dmarc1")]
            entry = {"tag": kind, "uri": item["uri"], "destination": host,
                     "auth_record": auth_name, "authorised": bool(found),
                     "found": found, "rcode": aresp.rcode}
            info["external_auth"].append(entry)
            if not found:
                findings.append(finding(
                    "dmarc.external.%s" % kind, "HIGH", "DMARC",
                    "External %s destination is not authorised: reports will not be sent" % kind,
                    "%s points at %s, which is outside this domain. The authorisation record at "
                    "%s returned %s with no v=DMARC1 record."
                    % (kind, item["uri"], auth_name, aresp.rcode or "no answer"),
                    "RFC 7489 section 7.1 requires a third-party report destination to prove it "
                    "consents, by publishing a DMARC record at "
                    "<your-domain>._report._dmarc.<destination-domain>. Without it, receivers MUST "
                    "NOT send reports to that address. This is a very common and completely silent "
                    "failure: the destination looks correct, the DMARC record looks correct, and "
                    "no reports ever arrive.",
                    "Either switch %s to an address at a domain you control, or ask the third "
                    "party (the DMARC report service) to publish:\n"
                    "    %s   IN TXT  \"v=DMARC1\"\n"
                    "Reputable report services document this step; if they provide the record, "
                    "add it at the destination's DNS, not yours." % (kind, auth_name)))

    return info, findings


def _spf_problem_summary(spf_info):
    """Describe what is wrong with SPF, or say that it could not be determined.

    A lookup that never completed is NOT a broken record, and must never be
    summarised as one: "we could not check" and "it is wrong" lead the reader to
    opposite actions.
    """
    if spf_info.get("error"):
        return ("SPF could not be checked at all (%s), so nothing can be concluded about it"
                % spf_info["error"])
    problems = []
    if not spf_info.get("records"):
        problems.append("no SPF record is published")
    else:
        parsed = spf_info.get("parse")
        if parsed and parsed.errors:
            problems.append("the SPF record has syntax errors (%s)" % parsed.errors[0])
        lookups = spf_info.get("lookups")
        if lookups and lookups.over_limit:
            problems.append("SPF exceeds the 10-lookup limit (%d terms)" % lookups.count)
    return "; ".join(problems) if problems else "no specific problem identified"


# ---------------------------------------------------------------------------
# Extras: MTA-STS, TLS-RPT, BIMI
# ---------------------------------------------------------------------------

def analyse_extras(domain, resolver, dmarc_info, fetch_policy=False, verbose_log=None):
    log = verbose_log or (lambda *a, **k: None)
    info = {"mta_sts": {}, "tls_rpt": {}, "bimi": {}, "policy_fetch": None}
    findings = []

    # ---- MTA-STS (RFC 8461)
    sts_name = "_mta-sts.%s" % domain
    sresp = resolver.txt(sts_name)
    info["mta_sts"]["name"] = sts_name
    info["mta_sts"]["rcode"] = sresp.rcode
    info["mta_sts"]["raw"] = [r.to_dict() for r in sresp.answers]
    sts_records = [t for t in sresp.txt_strings() if t.strip().lower().startswith("v=stsv1")]
    info["mta_sts"]["records"] = sts_records
    if sts_records:
        rec = sts_records[0]
        tags = _parse_simple_tags(rec)
        info["mta_sts"]["tags"] = tags
        sts_id = tags.get("id", "")
        if not sts_id:
            findings.append(finding(
                "mta_sts.no_id", "MEDIUM", "MTA-STS",
                "MTA-STS record has no id= field",
                "%s: %s" % (sts_name, rec),
                "RFC 8461 section 3.1 requires both v= and id=. The id is how a sender knows "
                "whether its cached policy is still current, so a record without one is invalid.",
                "Add an id= value of 1 to 32 letters and digits, and change it every time you "
                "update the policy file:\n"
                "    %s   IN TXT  \"v=STSv1; id=20240101000000\"\n"
                "Bump the id whenever the policy file at https://mta-sts.%s/.well-known/"
                "mta-sts.txt changes, or senders will keep using the cached copy."
                % (sts_name, domain)))
        elif not re.fullmatch(r"[A-Za-z0-9]{1,32}", sts_id):
            findings.append(finding(
                "mta_sts.bad_id", "MEDIUM", "MTA-STS",
                "MTA-STS id= value does not match the required form",
                "%s: %s" % (sts_name, rec),
                "RFC 8461 section 3.1 defines id= as 1 to 32 ALPHA or DIGIT characters. A value "
                "outside that is invalid and a strict sender may ignore the record.",
                "Use an alphanumeric timestamp of at most 32 characters, for example id=%s."
                % re.sub(r"[^A-Za-z0-9]", "", sts_id)[:32]))
        else:
            findings.append(finding(
                "mta_sts.present", "OK", "MTA-STS",
                "MTA-STS record present and well formed",
                "%s: %s" % (sts_name, rec),
                "Senders can discover that you require TLS for inbound mail, which protects "
                "messages in transit from being stripped down to plaintext.",
                "Remember the DNS record is only half of it: the policy must also be served over "
                "HTTPS at https://mta-sts.%s/.well-known/mta-sts.txt with a valid certificate for "
                "mta-sts.%s. A record without a working policy file causes failures once senders "
                "start enforcing." % (domain, domain)))
            if fetch_policy:
                info["policy_fetch"] = _fetch_mta_sts_policy(domain, log)
                pf = info["policy_fetch"]
                if pf.get("error"):
                    findings.append(finding(
                        "mta_sts.policy_fetch", "HIGH", "MTA-STS",
                        "MTA-STS policy file could not be fetched",
                        "GET https://mta-sts.%s/.well-known/mta-sts.txt failed: %s"
                        % (domain, pf["error"]),
                        "Senders that enforce MTA-STS fetch this file. If it is missing, "
                        "unreachable, or served with the wrong certificate, senders that have "
                        "cached your record will refuse to deliver over unencrypted connections.",
                        "Publish the policy file at that exact URL. It must contain "
                        "'version: STSv1', a 'mode:' line of enforce, testing or none, and 'mx:' "
                        "lines listing every hostname in your MX records. It must be served over "
                        "HTTPS with a certificate valid for mta-sts.%s." % domain))
                else:
                    parsed_policy = _parse_mta_sts_policy(pf.get("body", ""))
                    info["policy_fetch"]["parsed"] = parsed_policy
                    if parsed_policy.get("problems"):
                        findings.append(finding(
                            "mta_sts.policy_content", "HIGH", "MTA-STS",
                            "MTA-STS policy file has problems",
                            "\n".join("    - " + p for p in parsed_policy["problems"]),
                            "A policy file that does not match your MX records or that omits a "
                            "required field will cause delivery failures once senders enforce it.",
                            "Correct the policy file. Every mx: entry must match a hostname in your "
                            "MX records exactly, and the mode must be one of enforce, testing or none."))
                    elif parsed_policy.get("mode") == "testing":
                        findings.append(finding(
                            "mta_sts.testing", "INFO", "MTA-STS",
                            "MTA-STS policy is in testing mode",
                            "mode: testing",
                            "Testing mode asks senders to report failures without changing "
                            "delivery, which is the right way to start but not the end state.",
                            "Move to mode: enforce once TLS-RPT reports show no failures."))
    else:
        dmarc_p = (dmarc_info.get("parse").p if dmarc_info.get("parse") else None)
        sev = "LOW"
        findings.append(finding(
            "mta_sts.missing", sev, "MTA-STS",
            "No MTA-STS record",
            "No TXT record at %s begins with v=STSv1." % sts_name,
            "Without MTA-STS, a sender has no way to know that you require TLS, and an attacker "
            "who can intercept the connection can strip TLS by failing the STARTTLS command. "
            "This does not affect whether mail lands in spam, which is why it is optional and "
            "worth doing only after SPF, DKIM and DMARC are settled. It is reported at LOW for "
            "that reason%s."
            % ("; this domain already enforces DMARC, so the authentication groundwork is done"
               if dmarc_p in ("quarantine", "reject") else ""),
            "Optional but recommended once DMARC is enforcing. See templates/ for the record and "
            "docs/GLOSSARY-AND-FAQ.md for what the policy file must contain."))

    # ---- TLS-RPT (RFC 8460)
    rpt_name = "_smtp._tls.%s" % domain
    rresp = resolver.txt(rpt_name)
    info["tls_rpt"]["name"] = rpt_name
    info["tls_rpt"]["rcode"] = rresp.rcode
    info["tls_rpt"]["raw"] = [r.to_dict() for r in rresp.answers]
    rpt_records = [t for t in rresp.txt_strings() if t.strip().lower().startswith("v=tlsrptv1")]
    info["tls_rpt"]["records"] = rpt_records
    if rpt_records:
        rec = rpt_records[0]
        tags = _parse_simple_tags(rec)
        info["tls_rpt"]["tags"] = tags
        if not tags.get("rua"):
            findings.append(finding(
                "tls_rpt.no_rua", "MEDIUM", "TLS-RPT",
                "TLS-RPT record has no rua= reporting address",
                "%s: %s" % (rpt_name, rec),
                "RFC 8460 section 3: rua is the whole point of the record. Without it there is "
                "nowhere to send the reports.",
                "Add a reporting address:\n"
                "    %s   IN TXT  \"v=TLSRPTv1; rua=mailto:tls-reports@%s\"" % (rpt_name, domain)))
        else:
            findings.append(finding(
                "tls_rpt.present", "OK", "TLS-RPT",
                "TLS-RPT record present",
                "%s: %s" % (rpt_name, rec),
                "You will receive daily JSON reports about TLS negotiation failures with your "
                "domain, which is how you find out that a sender cannot establish the TLS you "
                "require.",
                "No change needed. Check the reports before you move MTA-STS to enforce."))
    elif info["mta_sts"].get("records"):
        findings.append(finding(
            "tls_rpt.missing", "MEDIUM", "TLS-RPT",
            "MTA-STS is published but TLS-RPT is not",
            "No TXT record at %s begins with v=TLSRPTv1, while MTA-STS is configured." % rpt_name,
            "MTA-STS without TLS-RPT means you have asked senders to use TLS and to refuse "
            "delivery when they cannot, but you receive no reports about failures. You would find "
            "out about a broken MX hostname from a recipient complaint instead of from data.",
            "Publish:\n"
            "    %s   IN TXT  \"v=TLSRPTv1; rua=mailto:tls-reports@%s\"\n"
            "and read the reports for a week before setting MTA-STS mode to enforce."
            % (rpt_name, domain)))

    # ---- BIMI
    bimi_name = "default._bimi.%s" % domain
    bresp = resolver.txt(bimi_name)
    info["bimi"]["name"] = bimi_name
    info["bimi"]["rcode"] = bresp.rcode
    info["bimi"]["raw"] = [r.to_dict() for r in bresp.answers]
    bimi_records = [t for t in bresp.txt_strings() if t.strip().lower().startswith("v=bimi1")]
    info["bimi"]["records"] = bimi_records
    dmarc_parsed = dmarc_info.get("parse")
    dmarc_enforcing = bool(dmarc_parsed and dmarc_parsed.enforcing
                           and (dmarc_parsed.pct in (None, 100)))
    if bimi_records:
        rec = bimi_records[0]
        tags = _parse_simple_tags(rec)
        info["bimi"]["tags"] = tags
        if not dmarc_enforcing:
            findings.append(finding(
                "bimi.no_dmarc", "MEDIUM", "BIMI",
                "BIMI is published but DMARC is not enforcing",
                "%s: %s\nDMARC policy in use: %s"
                % (bimi_name, rec,
                   (dmarc_parsed.p or "no usable policy") if dmarc_parsed else "no usable policy"),
                "BIMI requires an enforcing DMARC policy before a mailbox provider will display a "
                "logo. With p=none, or with pct below 100, receivers ignore the BIMI record, so "
                "the logo will not appear no matter how correct the record is. This is a common "
                "source of confusion because the BIMI record itself looks perfect.",
                "Get DMARC to p=quarantine or p=reject with pct=100 first, then verify the BIMI "
                "record again. See docs/MIGRATION-TO-ENFORCEMENT.md for the order."))
        else:
            problems = []
            l = tags.get("l", "")
            if "l" not in tags:
                problems.append("no l= tag (the logo URL)")
            else:
                if l and not l.lower().startswith("https://"):
                    problems.append("l=%s is not an https:// URL" % l)
                if l and not l.lower().split("?")[0].endswith(".svg"):
                    problems.append("l=%s does not end in .svg; BIMI logos must be "
                                    "SVG Tiny 1.2" % l)
            if "a" in tags:
                a = tags["a"]
                if a and not a.lower().startswith("https://"):
                    problems.append("a=%s is not an https:// URL" % a)
            if problems:
                findings.append(finding(
                    "bimi.tags", "MEDIUM", "BIMI",
                    "BIMI record has problems",
                    "%s: %s\n%s" % (bimi_name, rec, "\n".join("    - " + p for p in problems)),
                    "A malformed BIMI record is ignored by receivers. Nothing warns you: the logo "
                    "simply never appears.",
                    "Check the record against your BIMI provider's instructions. l= must be an "
                    "https URL to an SVG Tiny 1.2 logo, and a= is the URL of the Verified Mark "
                    "Certificate, which most providers now require for a logo to be shown."))
            else:
                findings.append(finding(
                    "bimi.present", "OK", "BIMI",
                    "BIMI record present with an enforcing DMARC policy",
                    "%s: %s" % (bimi_name, rec),
                    "The record is well formed and DMARC is enforcing, which are the two things "
                    "that can be checked from DNS.",
                    "This audit cannot verify the logo file, the certificate, or whether any "
                    "mailbox provider has accepted the record. Those depend on the VMC and on each "
                    "provider's own process."))

    return info, findings


def _parse_simple_tags(record):
    tags = {}
    for chunk in record.split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        k, _, v = chunk.partition("=")
        tags.setdefault(k.strip().lower(), v.strip())
    return tags


def _fetch_mta_sts_policy(domain, log):
    """GET the MTA-STS policy file. Read-only. Never raises."""
    url = "https://mta-sts.%s/.well-known/mta-sts.txt" % domain
    out = {"url": url, "body": None, "error": None, "status": None}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "email-auth-dns-audit/1.0"})
        with urllib.request.urlopen(req, timeout=15) as fh:
            out["status"] = getattr(fh, "status", None)
            out["body"] = fh.read(65536).decode("utf-8", "replace")
            log("  fetched %s (%s bytes)" % (url, len(out["body"])))
    except urllib.error.HTTPError as exc:
        out["error"] = "HTTP %s" % exc.code
    except urllib.error.URLError as exc:
        out["error"] = str(getattr(exc, "reason", exc))
    except Exception as exc:
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    return out


def _parse_mta_sts_policy(body):
    result = {"version": None, "mode": None, "mx": [], "max_age": None, "problems": []}
    for line in (body or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "version":
            result["version"] = value
        elif key == "mode":
            result["mode"] = value.lower()
        elif key == "mx":
            result["mx"].append(value.lower().rstrip("."))
        elif key == "max_age":
            result["max_age"] = value
    if result["version"] != "STSv1":
        result["problems"].append("version is %r, expected STSv1" % result["version"])
    if result["mode"] not in ("enforce", "testing", "none"):
        result["problems"].append("mode is %r, expected enforce, testing or none" % result["mode"])
    if not result["mx"]:
        result["problems"].append("no mx: lines; the policy must list your MX hostnames")
    if result["max_age"] is not None:
        try:
            if int(result["max_age"]) > 31557600:
                result["problems"].append("max_age above one year is not allowed")
        except ValueError:
            result["problems"].append("max_age is not an integer")
    return result

# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

class DomainReport(object):
    def __init__(self, domain):
        self.domain = domain
        self.spf = {}
        self.dkim = {}
        self.dmarc = {}
        self.mx = {}
        self.extras = {}
        self.findings = []
        self.duration = 0.0
        self.query_count = 0

    def worst(self):
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if any(f.severity == sev for f in self.findings):
                return sev
        return "OK"

    def counts(self):
        out = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def sorted_findings(self):
        return sorted(self.findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.area, f.fid))

    def to_dict(self):
        return {
            "domain": self.domain,
            "worst_severity": self.worst(),
            "severity_counts": self.counts(),
            "query_count": self.query_count,
            "duration_seconds": round(self.duration, 2),
            "spf": _serialisable(self.spf),
            "dkim": _serialisable(self.dkim),
            "dmarc": _serialisable(self.dmarc),
            "mx": _serialisable(self.mx),
            "extras": _serialisable(self.extras),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }


def _serialisable(obj):
    if isinstance(obj, dict):
        return {k: _serialisable(v) for k, v in obj.items() if not k.startswith("_")}
    if isinstance(obj, (list, tuple)):
        return [_serialisable(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode("ascii")
    if hasattr(obj, "to_dict"):
        return _serialisable(obj.to_dict())
    return repr(obj)


def audit_domain(domain, resolver, selectors=None, guess_selectors=False,
                 fetch_mta_sts_policy=False, verbose_log=None):
    """Run every check for one domain. Returns a DomainReport.

    Each stage is isolated: if one check fails unexpectedly the others still
    run and the failure is reported as a finding, so the buyer never gets a
    traceback and never loses the rest of the report.
    """
    log = verbose_log or (lambda *a, **k: None)
    domain = domain.strip().strip(".").lower()
    report = DomainReport(domain)
    start = time.time()
    log("auditing %s" % domain)

    def stage(label, func, default):
        try:
            return func()
        except Exception as exc:
            log("  %s failed: %s: %s" % (label, type(exc).__name__, exc))
            report.findings.append(finding(
                "internal.error.%s" % label.lower().replace(" ", "_").replace("/", ""),
                "INFO", "MX" if label == "MX" else label,
                "The %s check failed unexpectedly" % label,
                "%s: %s" % (type(exc).__name__, exc),
                "This is a bug in the audit tool, not necessarily a problem with the domain. The "
                "other checks in this report are unaffected and are still valid.",
                "Re-run the audit with --verbose for a traceback and include that output in any "
                "bug report. You can also skip this check and verify it by hand with a DNS lookup."))
            return default

    log("  -- MX")
    report.mx, mx_findings = stage("MX", lambda: analyse_mx(domain, resolver, verbose_log=log),
                                   ({}, []))
    report.findings.extend(mx_findings)

    log("  -- SPF")
    report.spf, spf_findings = stage(
        "SPF",
        lambda: analyse_spf(domain, resolver, mx_present=bool(report.mx.get("records")),
                            verbose_log=log),
        ({}, []))
    report.findings.extend(spf_findings)

    # Cross-check: MX points at a provider whose SPF include is missing.
    try:
        _cross_check_mx_and_spf(report)
    except Exception as exc:
        log("  MX/SPF cross-check failed: %s" % exc)

    log("  -- DKIM")
    report.dkim, dkim_findings = stage(
        "DKIM",
        lambda: analyse_dkim(domain, selectors, resolver, guess=guess_selectors, verbose_log=log),
        ({}, []))
    report.findings.extend(dkim_findings)

    log("  -- DMARC")
    report.dmarc, dmarc_findings = stage(
        "DMARC",
        lambda: analyse_dmarc(domain, resolver, report.spf, report.dkim, verbose_log=log),
        ({}, []))
    report.findings.extend(dmarc_findings)

    log("  -- MTA-STS / TLS-RPT / BIMI")
    report.extras, extra_findings = stage(
        "MTA-STS",
        lambda: analyse_extras(domain, resolver, report.dmarc,
                               fetch_policy=fetch_mta_sts_policy, verbose_log=log),
        ({}, []))
    report.findings.extend(extra_findings)

    # If the name itself does not resolve, every "record is missing" finding above
    # is a consequence of that, not a separate problem. Say so loudly at the top,
    # otherwise the reader starts publishing records for a domain that is not
    # delegated or is simply misspelled.
    if report.mx.get("nxdomain"):
        report.findings.append(finding(
            "domain.nxdomain", "CRITICAL", "MX",
            "The domain name itself does not exist, so this whole report is unreadable as-is",
            "%s returns NXDOMAIN, which means the name is not present in DNS at all. Every "
            "'no SPF record', 'no DMARC record' and 'no MTA-STS record' finding in this report "
            "is a consequence of that, not an independent configuration problem." % domain,
            "A name that does not exist can neither send nor receive mail, and any record you "
            "publish for a name that is not in DNS will not be found by anyone.",
            "Fix the name first: check for a typo, check that the domain is registered and "
            "delegated at the registrar, and check that the zone is actually served by your "
            "nameservers. Re-run the audit once the name resolves. If you meant to audit a "
            "subdomain, note that a subdomain which does not exist cannot inherit anything."))

    report.duration = time.time() - start
    report.query_count = resolver.query_count
    return report


def _cross_check_mx_and_spf(report):
    hints = report.mx.get("provider_hints") or []
    if not hints:
        return
    spf_records = report.spf.get("records") or []
    if not spf_records:
        return
    blob = " ".join(spf_records).lower()

    # Group by provider so a provider with several MX hosts (mx1/mx2/...) produces
    # one finding listing every host, not one near-identical finding per host.
    grouped = []
    index = {}
    for hint in hints:
        key = hint["provider"]
        if key not in index:
            index[key] = len(grouped)
            grouped.append({"provider": key, "include": hint["include"], "hosts": []})
        grouped[index[key]]["hosts"].append(hint["host"])

    for hint in grouped:
        token = hint["include"].lower()
        if token and token not in blob:
            hosts = hint["hosts"]
            host_text = ("The MX record %s belongs to %s" % (hosts[0], hint["provider"])
                         if len(hosts) == 1 else
                         "The MX records %s belong to %s"
                         % (", ".join(hosts[:-1]) + " and " + hosts[-1], hint["provider"]))
            report.findings.append(finding(
                "spf.provider.not_authorised", "LOW", "SPF",
                "Hint: MX provider %s is not named in the SPF record" % hint["provider"],
                "%s, while the SPF record is:\n    %s\n"
                "The expected token %r does not appear anywhere in that record."
                % (host_text, spf_records[0], hint["include"]),
                "READ THIS AS A HINT, NOT A VERDICT. MX records say where a domain RECEIVES mail; "
                "they say nothing about where it SENDS. A domain can receive at one provider and "
                "send through a completely different one, and large domains often do exactly that. "
                "So this finding alone does not prove anything is broken. It is worth checking "
                "because the opposite case is very common and very damaging: when the domain does "
                "send through its mailbox provider and that provider's include is missing from "
                "SPF, mail sent through it fails SPF, and that is one of the most frequent reasons "
                "transactional mail from an otherwise correct setup lands in spam.",
                "Decide from evidence, not from this hint. Your DMARC aggregate reports name every "
                "IP that sends as your domain, and it is the sending provider's own documentation "
                "that tells you which include it needs. If %s is one of your senders, add its "
                "include to the single SPF record:\n"
                "    %s.  IN TXT  \"v=spf1 include:%s ... -all\"\n"
                "If it is not, ignore this finding and move on."
                % (hint["provider"], report.domain, hint["include"])))


# ---------------------------------------------------------------------------
# Text report rendering
# ---------------------------------------------------------------------------

SEVERITY_LABEL = {
    "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
    "LOW": "LOW", "INFO": "INFO", "OK": "OK",
}

AREA_TITLES = {
    "SPF": "SPF", "DKIM": "DKIM", "DMARC": "DMARC", "MX": "MX / mail routing",
    "MTA-STS": "MTA-STS", "TLS-RPT": "TLS-RPT", "BIMI": "BIMI",
}


def _wrap(text, width=76, indent="    "):
    out = []
    for para in str(text).split("\n"):
        if para.strip() == "":
            out.append("")
            continue
        if para.startswith("    ") or para.startswith("\t"):
            out.append(para)
            continue
        line = ""
        for word in para.split(" "):
            if not line:
                line = word
            elif len(line) + 1 + len(word) <= width:
                line += " " + word
            else:
                out.append(indent + line)
                line = word
        out.append(indent + line)
    return "\n".join(out)


def render_text(report, verbose=False, show_ok=True):
    lines = []
    bar = "=" * 78
    domain = report.domain
    lines.append(bar)
    lines.append(" Email authentication audit: %s" % domain)
    lines.append(" audit.py 1.0.0  |  %d DNS queries  |  %.2fs"
                 % (report.query_count, report.duration))
    lines.append(bar)
    lines.append("")

    # ---- summary
    counts = report.counts()
    worst = report.worst()
    lines.append("SUMMARY")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "OK"):
        if sev in counts:
            lines.append("    %-9s %d" % (sev, counts[sev]))
    lines.append("    %-9s %s" % ("WORST", worst))
    lines.append("")

    # ---- one-line state per area
    lines.append("POSTURE")
    spf_records = report.spf.get("records") or []
    lookups = report.spf.get("lookups")
    if spf_records:
        lines.append("    SPF     %d record(s), %s lookup-causing term(s), terminal %s"
                     % (len(spf_records), lookups.count if lookups else "?",
                        ("'%s'" % report.spf.get("all")) if report.spf.get("all") else "none"))
    elif report.spf.get("error"):
        # Never print "none published" for a lookup that never completed.
        lines.append("    SPF     could not be checked (%s)" % report.spf["error"])
    else:
        lines.append("    SPF     none published")
    sels = report.dkim.get("selectors") or []
    if sels:
        lines.append("    DKIM    %s" % ", ".join(
            "%s=%s" % (e["selector"], e.get("status", "?")) for e in sels))
    else:
        lines.append("    DKIM    not checked (no selector supplied; selectors cannot be "
                     "enumerated from DNS)")
    dparsed = report.dmarc.get("parse")
    dmarc_records = report.dmarc.get("records") or []
    if dmarc_records:
        lines.append("    DMARC   p=%s%s%s  rua=%s"
                     % (dparsed.p if dparsed and dparsed.p else "invalid",
                        (" sp=%s" % dparsed.sp) if dparsed and dparsed.sp else "",
                        (" pct=%s" % dparsed.pct) if dparsed and dparsed.pct is not None else "",
                        ", ".join(d["uri"] for d in dparsed.rua) if dparsed and dparsed.rua
                        else "none"))
    else:
        if report.dmarc.get("error"):
            lines.append("    DMARC   could not be checked (%s)" % report.dmarc["error"])
        else:
            lines.append("    DMARC   none published")
    mxs = report.mx.get("records") or []
    if report.mx.get("null_mx"):
        lines.append("    MX      null MX (accepts no mail)")
    elif mxs:
        lines.append("    MX      %s" % ", ".join("%d %s" % (p, h) for p, h in mxs[:6]))
    else:
        lines.append("    MX      none" if not report.mx.get("error")
                     else "    MX      could not be checked (%s)" % report.mx["error"])
    lines.append("")

    # ---- findings, grouped by area, worst first
    by_area = {}
    for f in report.sorted_findings():
        by_area.setdefault(f.area, []).append(f)

    lines.append("FINDINGS")
    lines.append("")
    for area in ("SPF", "DKIM", "DMARC", "MX", "MTA-STS", "TLS-RPT", "BIMI"):
        items = by_area.get(area)
        if not items:
            continue
        shown = [f for f in items if show_ok or f.severity != "OK"]
        if not shown:
            continue
        lines.append("-" * 78)
        lines.append(" %s" % AREA_TITLES.get(area, area))
        lines.append("-" * 78)
        for f in shown:
            lines.append("")
            lines.append("  [%s] %s" % (SEVERITY_LABEL[f.severity], f.title))
            lines.append("  id: %s" % f.fid)
            if f.observed:
                lines.append("  Observed:")
                lines.append(_wrap(f.observed, indent="      "))
            if f.why:
                lines.append("  Why it matters:")
                lines.append(_wrap(f.why, indent="      "))
            if f.fix:
                lines.append("  Fix:")
                lines.append(_wrap(f.fix, indent="      "))
            lines.append("")
    lines.append("")

    # ---- next actions
    actionable = [f for f in report.sorted_findings()
                  if f.severity in ("CRITICAL", "HIGH", "MEDIUM")]
    lines.append("NEXT ACTIONS, IN ORDER")
    if not actionable:
        lines.append("    Nothing critical, high or medium was found in DNS.")
        lines.append("    This does not measure inbox placement or sender reputation; see")
        lines.append("    README.md for what this audit can and cannot see.")
    else:
        for i, f in enumerate(actionable, 1):
            lines.append("    %d. [%s] %s" % (i, f.severity, f.title))
            first = (f.fix or "").strip().split("\n")[0]
            # A fix whose first line is "Do this:" reads as a dangling clause here,
            # because the numbered steps that follow are not printed in this summary.
            if first.endswith(":"):
                first = first[:-1]
            lines.append(_wrap(first, indent="       ", width=70))
    lines.append("")

    if verbose:
        lines.append(bar)
        lines.append(" RAW DNS ANSWERS")
        lines.append(bar)
        for label, section in (("SPF", report.spf), ("DKIM", report.dkim),
                               ("DMARC", report.dmarc), ("MX", report.mx),
                               ("MTA-STS", (report.extras or {}).get("mta_sts", {})),
                               ("TLS-RPT", (report.extras or {}).get("tls_rpt", {})),
                               ("BIMI", (report.extras or {}).get("bimi", {}))):
            lines.append("")
            lines.append("[%s]" % label)
            if label == "DKIM":
                for e in section.get("selectors", []) or []:
                    lines.append("  %s (rcode=%s%s)" % (e["name"], e.get("rcode"),
                                                        ", cname -> %s" % e["cname"] if e.get("cname") else ""))
                    for r in e.get("raw", []):
                        lines.append("    %s %d IN %s %s" % (r["name"], r["ttl"], r["type"], r["text"]))
                    if not e.get("raw"):
                        lines.append("    (no records)")
                if section.get("note"):
                    lines.append("  note: %s" % section["note"])
            else:
                target = section
                for r in target.get("raw", []) or []:
                    lines.append("  %s %d IN %s %s" % (r["name"], r["ttl"], r["type"], r["text"]))
                if not target.get("raw"):
                    lines.append("  (no records, rcode=%s)" % target.get("rcode"))
        lines.append("")
        if report.spf.get("lookups"):
            lines.append("SPF lookup count breakdown (worst case, includes followed):")
            lines.append(_format_lookup_terms(report.spf["lookups"]))
            for n in report.spf["lookups"].notes:
                lines.append("    note: %s" % n)
            lines.append("")

    lines.append(bar)
    lines.append(" This audit reports only what is visible in DNS. It does not measure sender")
    lines.append(" reputation or inbox placement, and it never modifies any record.")
    lines.append(bar)
    return "\n".join(lines)


def render_spf_test(domain, record, resolver, verbose=False):
    """Count lookups for a proposed SPF record that has not been published."""
    lines = []
    bar = "=" * 78
    lines.append(bar)
    lines.append(" Proposed SPF record check (nothing was published)")
    lines.append(" audit.py 1.0.0  |  context domain: %s" % domain)
    lines.append(bar)
    lines.append("")
    lines.append("Record:")
    lines.append(_wrap(record, indent="    ", width=74))
    lines.append("")

    parsed = parse_spf(record)
    if not parsed.valid_version:
        lines.append("This is not an SPF record: %s" % "; ".join(parsed.errors))
        lines.append("")
        return "\n".join(lines), None

    if parsed.errors:
        lines.append("Syntax errors (each of these is a permerror at a receiver):")
        for e in parsed.errors:
            lines.append("    - %s" % e)
        lines.append("")

    lookups = count_spf_lookups(record, domain, resolver, verbose_log=_verbose_logger(verbose))

    lines.append("Lookup count breakdown (worst case, every reachable term):")
    lines.append(_format_lookup_terms(lookups))
    lines.append("")
    lines.append("    Lookup-causing terms : %d  (RFC 7208 limit: 10)" % lookups.count)
    lines.append("    Void lookups         : %d  (RFC 7208 suggested maximum: %d)"
                 % (lookups.void_lookups, SPF_VOID_LOOKUP_LIMIT))
    lines.append("    Deepest include chain: %d" % lookups.max_depth_seen)
    lines.append("")

    if lookups.over_limit:
        lines.append("  [CRITICAL] Over the limit: this record would produce permerror.")
        lines.append("             A sender that does not match one of the first 10 lookup-causing")
        lines.append("             terms will get permerror instead of the result of any later term,")
        lines.append("             so terms %d onwards cannot be relied on." % 11)
        lines.append("             Remove includes until the count is 10 or fewer.")
    elif lookups.near_limit:
        lines.append("  [MEDIUM] At or near the limit (%d of 10). Adding one more provider "
                     "breaks it." % lookups.count)
    else:
        lines.append("  [OK] Within the lookup limit (%d of 10)." % lookups.count)

    if lookups.depth_exceeded:
        lines.append("  [HIGH] The count stopped at the recursion cap, so the real total is "
                     "higher than %d." % lookups.count)
    if lookups.cycles:
        lines.append("  [HIGH] Include loop detected: %s" % ", ".join(sorted(set(lookups.cycles))))
    if lookups.over_void_limit:
        lines.append("  [MEDIUM] More than %d void lookups." % SPF_VOID_LOOKUP_LIMIT)
    if lookups.errors:
        lines.append("")
        lines.append("  Problems that would cause permerror:")
        for e in lookups.errors:
            lines.append("    - %s" % e)
    if lookups.notes:
        lines.append("")
        for n in lookups.notes:
            lines.append("    note: %s" % n)
    lines.append("")
    lines.append("This check resolves every include: against live DNS but did not read the")
    lines.append("published record, so it reflects exactly the record printed above.")
    lines.append(bar)
    return "\n".join(lines), lookups


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="audit.py",
        description="Audit a domain's email authentication DNS records (SPF, DKIM, DMARC, MX, "
                    "MTA-STS, TLS-RPT, BIMI) and print findings with severities and fixes. "
                    "Read-only: this tool only queries DNS and never changes anything.",
        epilog="Examples:\n"
               "  python3 audit.py --domain example.com\n"
               "  python3 audit.py --domain example.com --dkim-selector google --dkim-selector s1\n"
               "  python3 audit.py --domain example.com --json > report.json\n"
               "  python3 audit.py --domain example.com --guess-selectors --verbose\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--domain", "-d", action="append", default=[], metavar="DOMAIN",
                   help="domain to audit. Repeat the flag to audit several domains. Not required "
                        "when --test-spf is used.")
    p.add_argument("--dkim-selector", action="append", default=[], metavar="SELECTOR",
                   help="DKIM selector to check, repeatable. Selectors cannot be discovered "
                        "from DNS, so you must supply the ones you use. Checked as "
                        "<SELECTOR>._domainkey.<domain>.")
    p.add_argument("--guess-selectors", action="store_true",
                   help="also try a list of selector names commonly seen in the wild. A hit is "
                        "a verified DNS fact; a miss proves nothing.")
    p.add_argument("--json", action="store_true",
                   help="emit machine-readable JSON instead of the text report.")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="include raw DNS answers and the SPF lookup-count breakdown.")
    p.add_argument("--resolver", action="append", default=[], metavar="IP",
                   help="nameserver to query, repeatable. Defaults to /etc/resolv.conf.")
    p.add_argument("--doh", metavar="URL", nargs="?", const="https://dns.google/dns-query",
                   default=None,
                   help="use DNS over HTTPS instead of UDP/TCP (default endpoint "
                        "https://dns.google/dns-query).")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, metavar="SECONDS",
                   help="per-query timeout, default %.1f." % DEFAULT_TIMEOUT)
    p.add_argument("--retries", type=int, default=DEFAULT_RETRIES, metavar="N",
                   help="extra attempts per query after the first, default %d." % DEFAULT_RETRIES)
    p.add_argument("--tcp", action="store_true", help="use TCP for DNS queries instead of UDP.")
    p.add_argument("--fetch-mta-sts-policy", action="store_true",
                   help="also fetch https://mta-sts.<domain>/.well-known/mta-sts.txt over HTTPS "
                        "and check it against your MX records. Off by default: it is the only "
                        "check that makes an outbound HTTP request.")
    p.add_argument("--hide-ok", action="store_true", help="omit OK findings from the text report.")
    p.add_argument("--test-spf", action="append", default=[], metavar="RECORD",
                   help="count the DNS lookups a PROPOSED SPF record would need, without "
                        "publishing anything. Include chains are resolved against live DNS with "
                        "--domain as the context for relative targets. Repeatable. Useful before "
                        "you add a provider to a record that is near the limit.")
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "never"],
                   default="never",
                   help="exit with status 1 if any finding at or above this severity exists. "
                        "Default never, so a CI job collecting reports does not fail on findings.")
    p.add_argument("--version", action="version", version="audit.py 1.0.0")
    return p


def _verbose_logger(enabled):
    if not enabled:
        return lambda *a, **k: None

    def log(*parts):
        sys.stderr.write(" ".join(str(p) for p in parts) + "\n")
        sys.stderr.flush()
    return log


def _run(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    domains = []
    for d in args.domain:
        d = (d or "").strip().strip(".").lower()
        if not d:
            continue
        # A name with no dot cannot carry SPF/DMARC/DKIM records, so auditing it
        # produces a full report of "none published" findings for a domain that
        # cannot exist. Reject it up front rather than reporting noise as if it
        # were a real posture. The same applies to an IP literal.
        import re as _re
        _label = _re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
        _ipv4 = _re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        _bad = None
        if " " in d or "/" in d:
            _bad = "contains a space or slash"
        elif "." not in d:
            _bad = "has no dot, so it cannot have DNS records"
        elif _ipv4.match(d):
            _bad = "looks like an IP address, not a domain name"
        elif any(not _label.match(part) for part in d.split(".")):
            _bad = "contains a label that is not a valid DNS label"
        if _bad:
            sys.stderr.write("error: %r does not look like a domain name (%s)\n" % (d, _bad))
            return 2
        if d not in domains:
            domains.append(d)
    if not domains:
        if not args.test_spf:
            sys.stderr.write("error: --domain is required (or use --test-spf to check a "
                             "proposed record)\n")
            return 2
        # --test-spf alone: use a neutral context domain for relative SPF targets.
        context_domain = "example.com"
        sys.stderr.write("note: no --domain given, using %s as the context domain for relative "
                         "SPF targets\n" % context_domain)
    else:
        context_domain = domains[0]

    log = _verbose_logger(args.verbose)

    try:
        resolver = Resolver(
            servers=args.resolver or None,
            timeout=args.timeout,
            retries=args.retries,
            doh_endpoint=args.doh,
            tcp_only=args.tcp,
            verbose=args.verbose,
            logger=log,
        )
    except Exception as exc:
        sys.stderr.write("error: could not initialise the resolver: %s\n" % exc)
        return 3

    if args.verbose:
        if resolver.doh_endpoint:
            log("resolver: DNS over HTTPS via %s" % resolver.doh_endpoint)
        else:
            log("resolver: %s (timeout %.1fs, retries %d)"
                % (", ".join(resolver.servers), resolver.timeout, resolver.retries))
        if resolver.used_fallback_resolvers:
            log("note: /etc/resolv.conf had no nameserver entries; using %s"
                % ", ".join(FALLBACK_RESOLVERS))

    reports = []
    for domain in domains:
        try:
            reports.append(audit_domain(
                domain, resolver,
                selectors=args.dkim_selector,
                guess_selectors=args.guess_selectors,
                fetch_mta_sts_policy=args.fetch_mta_sts_policy,
                verbose_log=log))
        except KeyboardInterrupt:
            sys.stderr.write("interrupted\n")
            return 130
        except Exception as exc:
            # A bug in one check must not produce a traceback for the buyer.
            sys.stderr.write("error: auditing %s failed: %s: %s\n"
                             % (domain, type(exc).__name__, exc))
            if args.verbose:
                import traceback
                traceback.print_exc(file=sys.stderr)
            r = DomainReport(domain)
            r.findings.append(finding(
                "internal.error", "INFO", "MX", "Internal error while auditing this domain",
                "%s: %s" % (type(exc).__name__, exc),
                "An unexpected error occurred. Re-run with --verbose for a traceback.",
                "Please report this with the --verbose output."))
            reports.append(r)

    # Every domain failed to resolve at all -> almost certainly no DNS access.
    total_queries = sum(r.query_count for r in reports)
    if resolver.network_failures and resolver.network_failures >= max(3, total_queries):
        # Do NOT print a report here. With no answers at all, every "record is
        # missing" finding would be an artefact of the broken connection, and
        # telling a buyer their domain publishes no SPF/DKIM/DMARC when the real
        # problem is local DNS access is the worst possible failure mode.
        sys.stderr.write(
            "error: no DNS server answered any query, so no report was produced.\n"
            "  tried: %s\n"
            "  Check outbound DNS access (port 53 UDP/TCP), or use --doh to query over HTTPS.\n"
            % ", ".join(resolver.servers))
        return 3

    # ---- proposed SPF record check (--test-spf)
    spf_test_results = []
    for proposed in args.test_spf:
        try:
            _text, lookups = render_spf_test(context_domain, proposed, resolver,
                                             verbose=args.verbose)
            spf_test_results.append({
                "context_domain": context_domain,
                "record": proposed,
                "lookup_count": lookups.count if lookups else None,
                "over_limit": lookups.over_limit if lookups else None,
                "void_lookups": lookups.void_lookups if lookups else None,
                "parsed_ok": bool(lookups),
                "breakdown": lookups.to_dict() if lookups else None,
            })
        except Exception as exc:
            sys.stderr.write("error: checking the proposed SPF record failed: %s: %s\n"
                             % (type(exc).__name__, exc))
            spf_test_results.append({"record": proposed, "error": str(exc)})

    if args.json:
        payload = {
            "tool": "audit.py", "version": __version__,
            "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "resolver": (resolver.doh_endpoint or ", ".join(resolver.servers)),
            "domains": [r.to_dict() for r in reports],
        }
        if args.test_spf:
            payload["spf_tests"] = spf_test_results
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=False) + "\n")
    else:
        for i, r in enumerate(reports):
            if i:
                sys.stdout.write("\n")
            sys.stdout.write(render_text(r, verbose=args.verbose, show_ok=not args.hide_ok) + "\n")
        for proposed in args.test_spf:
            _text, _lookups = render_spf_test(context_domain, proposed, resolver,
                                              verbose=args.verbose)
            sys.stdout.write("\n" + _text + "\n")

    if args.fail_on != "never":
        threshold = SEVERITY_ORDER[args.fail_on.upper()]
        worst = max((SEVERITY_ORDER[r.worst()] for r in reports), default=0)
        for t in spf_test_results:
            if t.get("over_limit"):
                worst = max(worst, SEVERITY_ORDER["CRITICAL"])
        if worst >= threshold:
            return 1
    return 0


def main(argv=None):
    """Console-script entry point.

    Wraps the implementation in `_run` so that any failure still produces a
    readable one-line message and a non-zero exit status instead of a traceback
    - the same guarantee the repo-root `python3 audit.py` wrapper has always
    given. Without this, the installed `spf-dkim-dmarc-audit` script would let
    an unexpected exception escape as an unhandled traceback.
    """
    try:
        return _run(argv)
    except KeyboardInterrupt:
        sys.stderr.write("interrupted\n")
        return 130
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0
    except Exception as exc:
        # Absolute last resort: a readable message, never a traceback.
        sys.stderr.write("error: %s: %s\n" % (type(exc).__name__, exc))
        return 3


if __name__ == "__main__":
    sys.exit(main())
