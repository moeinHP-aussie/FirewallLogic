"""
parser.py — Phase 3
====================
Reads a raw firewall config file (iptables-save format or nftables)
and converts every rule into a validated Rule object that the bridge
layer can assert into the Prolog engine as rule/8 facts.

The parser deliberately knows NOTHING about anomaly detection — it only
answers "given this line of config text, what does it say?". All
reasoning about whether two rules conflict stays inside firewall_engine.pl.

Supported input formats
-----------------------
1. iptables-save  — the output of `iptables-save` or `ip6tables-save`,
   e.g. lines like:
       -A FORWARD -s 172.16.0.0/16 -d 10.0.0.5 -p tcp --dport 80 -j ACCEPT
   This is the most common format on university Linux firewalls and is
   what `iptables-restore` / `firewalld` / `ufw` all export.

2. nftables       — the output of `nft list ruleset`, e.g.:
       ip filter FORWARD accept ip saddr 172.16.0.0/16 daddr 10.0.0.5 tcp dport 80
   Detected automatically by looking for the `table` / `chain` / `type`
   keywords that nftables always emits.

Output
------
A list of Rule namedtuples:
    Rule(id, priority, action, protocol, src_ip, dst_ip, src_port, dst_port)

    id        : int  — line-order sequence number (1-based)
    priority  : int  — same as id (iptables order IS evaluation order)
    action    : str  — "allow" | "deny"
    protocol  : str  — "tcp" | "udp" | "icmp" | "any"
    src_ip    : str  — Prolog term string, e.g. "ip4(10,0,0,0,24)"
    dst_ip    : str  — Prolog term string
    src_port  : str  — Prolog term string, e.g. "port(80)" | "any"
    dst_port  : str  — Prolog term string

IP addresses are stored as Prolog term strings (not Python objects)
because the bridge will embed them verbatim into Prolog facts — no
second conversion step is needed.
"""

import re
import ipaddress
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# 1. Data model
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    id:        int
    priority:  int
    action:    str   # "allow" | "deny"
    protocol:  str   # "tcp" | "udp" | "icmp" | "any"
    src_ip:    str   # Prolog ip4/ip6 term string
    dst_ip:    str   # Prolog ip4/ip6 term string
    src_port:  str   # Prolog port term string
    dst_port:  str   # Prolog port term string
    chain:     str = "FORWARD"  # Rules are comparable only within one chain.

    def to_prolog_fact(self) -> str:
        """Returns a ready-to-assert Prolog fact string, e.g.:
        rule(1, 10, allow, tcp, ip4(10,0,0,0,24), ip4(10,0,0,5,32), any, port(80)).
        """
        return (
            f"rule({self.id}, {self.priority}, {self.action}, {self.protocol}, "
            f"{self.src_ip}, {self.dst_ip}, {self.src_port}, {self.dst_port})."
        )

    def validate(self) -> Optional[str]:
        """Returns None if this Rule is safe to assert as a rule/8 fact,
        or a human-readable reason string if it is not.

        This is a Python-side re-implementation of ip_subnet.pl's
        valid_ip_term/1, applied to src_ip/dst_ip, PLUS the port-range
        checks port_to_prolog() already enforces at construction time
        (see that function's docstring). It exists because
        ip_subnet.pl's own comment on valid_ip_term/1 says the predicate
        "exists so that Phase 3's parser can call it on every fact it's
        about to assert ... instead of an uncaught type_error crashing
        the whole ingestion run partway through" -- but nothing in
        Phase 3 ever actually called it. Rather than have the Python
        parser shell out to Prolog just to validate a term (which would
        make parser.py depend on bridge.py / a live Prolog engine,
        breaking the layering described in this file's own module
        docstring: "the parser knows NOTHING about ... reasoning ...
        stays inside firewall_engine.pl"), this re-implements the same
        octet/hextet/prefix-length range checks in pure Python against
        the ip4(...)/ip6(...) term string this Rule already built.

        IMPORTANT: this must be kept in sync with valid_ip_term/1 in
        ip_subnet.pl by hand -- there is no shared source of truth
        between the two languages. If ip_subnet.pl's valid range for
        A/B/C/D, a hextet, or PrefixLen ever changes, this function
        needs the same edit. bridge.py's pyswip backend additionally
        wraps every engine call in try/except specifically so a term
        that slips past this check (or a future field this function
        doesn't yet know to validate) still surfaces as a caught error
        rather than a silent wrong answer -- see run_engine()'s
        docstring in bridge.py.
        """
        for label, term in (("src_ip", self.src_ip), ("dst_ip", self.dst_ip)):
            reason = _validate_ip_term_string(term)
            if reason is not None:
                return f"{label} {term!r}: {reason}"
        return None


@dataclass
class ParseError:
    """Returned alongside the rule list for lines the parser couldn't
    interpret, so the caller can log them without crashing the run."""
    line_number: int
    raw_line:    str
    reason:      str


# ---------------------------------------------------------------------------
# 1b. Term-string validation (Python-side mirror of ip_subnet.pl's
#     valid_ip_term/1 -- see Rule.validate()'s docstring above for why
#     this exists as a duplicate implementation rather than a call into
#     Prolog)
# ---------------------------------------------------------------------------

_IP4_TERM_RE = re.compile(
    r"^ip4\((-?\d+),(-?\d+),(-?\d+),(-?\d+),(-?\d+)\)$"
)
_IP6_TERM_RE = re.compile(
    r"^ip6\((-?\d+),(-?\d+),(-?\d+),(-?\d+),(-?\d+),(-?\d+),(-?\d+),(-?\d+),(-?\d+)\)$"
)


def _validate_ip_term_string(term: str) -> Optional[str]:
    """Returns None if `term` (a Prolog ip4(...)/ip6(...) term string,
    as produced by ip_to_prolog() above) satisfies the same range
    constraints as ip_subnet.pl's valid_ip_term/1, or a reason string
    if not.

    valid_ip_term/1's rules, mirrored here exactly:
      ip4(A,B,C,D,PrefixLen): A,B,C,D in 0..255, PrefixLen in 0..32
      ip6(H1..H8,PrefixLen):  H1..H8 in 0..0xFFFF, PrefixLen in 0..128

    In practice ip_to_prolog() only ever builds terms from Python's
    ipaddress module, which already guarantees octets/hextets/prefix
    lengths are in range -- so this should never actually fire for
    output produced by this file's own parsers. It exists as a defense
    -- e.g. if a future contributor (or Phase 4's remediation code,
    per the project roadmap) starts building ip4(...)/ip6(...) strings
    some other way, this still catches a malformed term before it
    reaches assertz(), exactly as ip_subnet.pl's own comment describes.
    """
    m4 = _IP4_TERM_RE.match(term)
    if m4:
        a, b, c, d, prefix = (int(x) for x in m4.groups())
        if not all(0 <= v <= 255 for v in (a, b, c, d)):
            return "IPv4 octet out of range 0-255"
        if not (0 <= prefix <= 32):
            return "IPv4 prefix length out of range 0-32"
        return None

    m6 = _IP6_TERM_RE.match(term)
    if m6:
        *hextets, prefix = (int(x) for x in m6.groups())
        if not all(0 <= h <= 0xFFFF for h in hextets):
            return "IPv6 hextet out of range 0-0xFFFF"
        if not (0 <= prefix <= 128):
            return "IPv6 prefix length out of range 0-128"
        return None

    return f"not a well-formed ip4(...)/ip6(...) term"


# ---------------------------------------------------------------------------
# 2. IP / port conversion helpers
# ---------------------------------------------------------------------------

def ip_to_prolog(cidr: str) -> str:
    """Converts a CIDR string to a Prolog ip4/ip6 term string.

    "172.16.0.0/16"  → "ip4(172,16,0,0,16)"
    "10.0.0.5"       → "ip4(10,0,0,5,32)"      (host = /32)
    "0.0.0.0/0"      → "ip4(0,0,0,0,0)"         ("any" in iptables)
    "2001:db8::/32"  → "ip6(8193,3512,0,0,0,0,0,0,32)"
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        # Not a network; try as plain address (host)
        try:
            addr = ipaddress.ip_address(cidr)
            net = ipaddress.ip_network(f"{cidr}/{addr.max_prefixlen}", strict=False)
        except ValueError:
            raise ValueError(f"Cannot parse IP/CIDR: {cidr!r}")

    prefix = net.prefixlen
    if isinstance(net, ipaddress.IPv4Network):
        a, b, c, d = net.network_address.packed
        return f"ip4({a},{b},{c},{d},{prefix})"
    else:
        packed = net.network_address.packed
        hextets = [int.from_bytes(packed[i:i+2], 'big') for i in range(0, 16, 2)]
        return f"ip6({','.join(str(h) for h in hextets)},{prefix})"


ANY_IP4 = "ip4(0,0,0,0,0)"
ANY_IP6 = "ip6(0,0,0,0,0,0,0,0,0)"


def port_to_prolog(port_str: Optional[str]) -> str:
    """Converts an iptables/nftables port spec to a Prolog term string.

    None / "" / "any"     → "any"
    "80"                  → "port(80)"
    "1024:2048"           → "port_range(1024,2048)"
    "1024:65535"          → "port_range(1024,65535)"

    Raises ValueError for a syntactically-numeric but out-of-range port
    (e.g. "99999", "-1") or an inverted range (Lo > Hi). Previously this
    function accepted any integer-looking string outright, so a config
    line like "--dport 99999" silently produced the Prolog term
    port(99999) -- not rejected here, not rejected by ip_subnet.pl
    either (is_subset_port/2 and port_bounds/3 in firewall_engine.pl
    assume every port(N) is already in 0-65535 and never re-check it),
    so an out-of-range port would have quietly skewed port_overlaps/2's
    interval math instead of being caught at ingestion. Now it is
    caught here, at the same point a malformed IP already raises
    ValueError, and reported as a ParseError like any other bad line.
    """
    if not port_str or port_str.lower() in ("", "any", "0:65535"):
        return "any"
    if ":" in port_str:
        lo, hi = port_str.split(":", 1)
        lo_i, hi_i = int(lo), int(hi)
        if not (0 <= lo_i <= 65535) or not (0 <= hi_i <= 65535):
            raise ValueError(f"port out of range 0-65535: {port_str!r}")
        if lo_i > hi_i:
            raise ValueError(f"inverted port range (Lo > Hi): {port_str!r}")
        return f"port_range({lo_i},{hi_i})"
    port_i = int(port_str)
    if not (0 <= port_i <= 65535):
        raise ValueError(f"port out of range 0-65535: {port_str!r}")
    return f"port({port_i})"


def action_to_prolog(raw: str) -> str:
    """Maps supported terminal targets to the engine's allow|deny vocabulary.

    A target such as LOG, RETURN, MARK, or a user-defined chain is not a
    terminal allow/deny decision. Treating one as ``deny`` would produce a
    convincing but false security finding, so unsupported targets must be
    rejected by the parser instead.
    """
    mapping = {
        "accept": "allow", "allow": "allow", "pass": "allow",
        "drop": "deny",  "deny": "deny",  "reject": "deny",
    }
    try:
        return mapping[raw.lower()]
    except KeyError:
        raise ValueError(
            f"unsupported target {raw!r}; only ACCEPT, DROP, REJECT, "
            "ALLOW, DENY, and PASS are currently modeled"
        ) from None


def protocol_to_prolog(raw: Optional[str]) -> str:
    mapping = {"tcp": "tcp", "udp": "udp", "icmp": "icmp", "icmpv6": "icmp", "all": "any"}
    if not raw:
        return "any"
    return mapping.get(raw.lower(), "any")


# ---------------------------------------------------------------------------
# 3. iptables-save parser
# ---------------------------------------------------------------------------
# iptables-save produces lines like:
#   -A CHAIN [-s SRC] [-d DST] [-p PROTO [--sport SPORT] [--dport DPORT]] -j TARGET
# Rules are analyzed independently per chain.  A rule in INPUT must never be
# compared with a rule in FORWARD, even if their traffic selectors are equal.

_IPTABLES_OPT = re.compile(
    r"""
    (?:-s\s+(?P<src>\S+))|           # source IP/CIDR
    (?:-d\s+(?P<dst>\S+))|           # destination IP/CIDR
    (?:-p\s+(?P<proto>\S+))|         # protocol
    (?:--sport\s+(?P<sport>\S+))|    # source port / range
    (?:--dport\s+(?P<dport>\S+))|    # destination port / range
    (?:-j\s+(?P<action>\S+))         # jump target (action)
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _parse_iptables_line(line: str, rule_id: int) -> Rule:
    """Parses a single -A line from iptables-save output."""
    parts = line.split(maxsplit=2)
    if len(parts) < 2:
        raise ValueError("missing chain after -A")
    chain = parts[1]
    m_all = {k: v for m in _IPTABLES_OPT.finditer(line)
             for k, v in m.groupdict().items() if v is not None}

    if "action" not in m_all:
        raise ValueError("missing terminal target (-j)")

    action   = action_to_prolog(m_all["action"])
    protocol = protocol_to_prolog(m_all.get("proto"))
    src_ip   = ip_to_prolog(m_all["src"]) if "src" in m_all else ANY_IP4
    dst_ip   = ip_to_prolog(m_all["dst"]) if "dst" in m_all else ANY_IP4
    src_port = port_to_prolog(m_all.get("sport"))
    dst_port = port_to_prolog(m_all.get("dport"))

    return Rule(
        id=rule_id, priority=rule_id * 10,
        action=action, protocol=protocol,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        chain=chain,
    )


def parse_iptables(text: str) -> tuple[list[Rule], list[ParseError]]:
    """Parses an iptables-save format config string.
    Returns (rules, errors).
    """
    rules, errors = [], []
    rule_id = 0

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("*") or line.startswith(":"):
            continue
        if not line.startswith("-A "):
            continue  # COMMIT or other directives — skip

        rule_id += 1
        try:
            rule = _parse_iptables_line(line, rule_id)
        except Exception as e:
            errors.append(ParseError(lineno, raw, str(e)))
            continue

        invalid_reason = rule.validate()
        if invalid_reason is not None:
            errors.append(ParseError(lineno, raw, invalid_reason))
            continue

        rules.append(rule)

    return rules, errors


# ---------------------------------------------------------------------------
# 4. nftables parser
# ---------------------------------------------------------------------------
# nft list ruleset produces blocks like:
#   table ip filter {
#       chain FORWARD {
#           type filter hook forward priority 0; policy drop;
#           ip saddr 172.16.0.0/16 ip daddr 10.0.0.5 tcp dport 80 accept
#           ...
#       }
#   }
# We parse the actual rule lines inside chain blocks.
# nftables is more free-form than iptables-save, so this parser handles
# the common field order; exotic expressions (sets, maps, concatenations)
# fall through to ParseError.
#
# NOTE on design (fixes a real bug from an earlier version of this file):
# an earlier version of this pattern chained all fields as a single fixed
# sequence of OPTIONAL groups separated by non-greedy '.*?' gaps, e.g.
#   (?:ip6?\s+saddr\s+(?P<src>\S+))?  .*?  (?:ip6?\s+daddr\s+(?P<dst>\S+))?  .*?  ...
# That looks reasonable but is broken: because every group in the chain is
# optional, Python's regex engine is free to satisfy the WHOLE pattern by
# matching 'src' and then immediately skipping the (also optional) 'daddr'
# group entirely -- dumping the real daddr text into the following '.*?'
# instead of capturing it. This isn't a rare edge case: it happens for
# ANY line where 'saddr' appears before 'daddr' (the standard, common
# field order), silently turning every rule's real destination into
# "any" instead of raising an error -- which then feeds a wrong DstIP
# straight into Phase 2's shadowing/redundancy checks.
#
# Fix: mirror the iptables parser's approach (_IPTABLES_OPT above) --
# find each field independently, anywhere in the line, via finditer +
# alternation, instead of expecting one fixed left-to-right sequence.
# Order and presence of fields no longer matters, and there is no gap
# for the regex engine to "cheat" through.

_NFT_FIELD = re.compile(
    r"""
    (?:\bip6?\s+saddr\s+(?P<src>\S+))|      # source IP/CIDR (ip or ip6 prefix)
    (?:\bip6?\s+daddr\s+(?P<dst>\S+))|      # destination IP/CIDR
    (?:\b(?P<proto>tcp|udp|icmp(?:v6)?)\b)| # protocol
    (?:\bsport\s+(?P<sport>\S+))|           # source port / range
    (?:\bdport\s+(?P<dport>\S+))            # destination port / range
    """,
    re.VERBOSE | re.IGNORECASE,
)

# The action is always the final verdict keyword on the rule line (accept/
# drop/reject/pass), optionally followed by nftables trailers like a
# counter or comment that we don't otherwise care about. Matched
# separately from the fields above since it anchors to the END of the
# line rather than floating anywhere in it.
_NFT_ACTION = re.compile(
    r"\b(?P<action>accept|drop|reject|pass)\b\s*(?:counter\b.*)?(?:comment\b.*)?$",
    re.IGNORECASE,
)


def _is_ipv6_context(chain_block: str) -> bool:
    return "ip6" in chain_block.split("chain")[0][:200].lower()


def parse_nftables(text: str) -> tuple[list[Rule], list[ParseError]]:
    """Parses nft list ruleset output.
    Returns (rules, errors).
    """
    rules, errors = [], []
    rule_id = 0
    in_chain = False
    current_chain: Optional[str] = None

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("chain "):
            in_chain = True
            current_chain = line.split(maxsplit=2)[1]
            continue
        if line == "}":
            in_chain = False
            current_chain = None
            continue
        if line.startswith("type ") or line.startswith("table "):
            continue
        if not in_chain:
            continue

        # Action anchors the end of a genuine rule line. If it's absent,
        # this line isn't a rule (could be a policy/counter-only line or
        # an unsupported expression) -- skip it the same way the old
        # code did, rather than misreporting it as a broken rule.
        m_action = _NFT_ACTION.search(line)
        if not m_action:
            if "policy" not in line and "counter" not in line:
                errors.append(ParseError(lineno, raw, "no recognized rule pattern"))
            continue

        # Collect every field independently -- order and presence no
        # longer matter, and (unlike the old chained-optional-groups
        # pattern) there's no gap for the regex engine to skip a real
        # field through. Last match wins for any field named twice,
        # which matches nftables' own "last statement wins" semantics
        # for a given line.
        g = {}
        for fm in _NFT_FIELD.finditer(line):
            for key, val in fm.groupdict().items():
                if val is not None:
                    g[key] = val

        rule_id += 1
        # Decide IP family from presence of "ip6" in saddr/daddr tokens
        is_v6 = "ip6" in line.lower() and ("ip6 saddr" in line.lower() or "ip6 daddr" in line.lower())
        any_ip = ANY_IP6 if is_v6 else ANY_IP4

        # All four field conversions (both IPs, both ports) are now
        # inside ONE try/except. Previously only the two ip_to_prolog()
        # calls were guarded -- port_to_prolog() was called directly
        # inside the Rule(...) constructor below, unguarded. That was
        # never a problem while port_to_prolog() could not raise (any
        # integer-looking string was accepted), but now that it
        # rejects out-of-range ports/inverted ranges (see that
        # function's docstring), an unguarded call would let one bad
        # port crash parse_nftables() for the WHOLE file instead of
        # being reported as a ParseError for that one line -- exactly
        # the "uncaught error aborts the whole ingestion run" failure
        # mode this project's validation exists to avoid (see
        # ip_subnet.pl's valid_ip_term/1 comment, and Rule.validate()).
        try:
            src_ip = ip_to_prolog(g["src"]) if g.get("src") else any_ip
            dst_ip = ip_to_prolog(g["dst"]) if g.get("dst") else any_ip
            src_port = port_to_prolog(g.get("sport"))
            dst_port = port_to_prolog(g.get("dport"))
        except ValueError as e:
            errors.append(ParseError(lineno, raw, str(e)))
            continue

        rule = Rule(
            id=rule_id, priority=rule_id * 10,
            action=action_to_prolog(m_action["action"]),
            protocol=protocol_to_prolog(g.get("proto")),
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            chain=current_chain or "<unknown>",
        )

        invalid_reason = rule.validate()
        if invalid_reason is not None:
            errors.append(ParseError(lineno, raw, invalid_reason))
            continue

        rules.append(rule)

    return rules, errors


# ---------------------------------------------------------------------------
# 5. Auto-detect format and dispatch
# ---------------------------------------------------------------------------

def parse(text: str) -> tuple[list[Rule], list[ParseError]]:
    """Auto-detects format (iptables-save vs nftables) and parses.

    Detection heuristic: nftables output always contains 'table' and
    'chain' keywords as line-starters; iptables-save uses '*', ':', '-A'.
    If both patterns are absent the text is returned as empty with an error.
    """
    lines = text.splitlines()
    has_iptables = any(l.strip().startswith(("-A ", "*", ":FORWARD", ":INPUT")) for l in lines)
    has_nftables = any(l.strip().startswith(("table ", "chain ")) for l in lines)

    if has_iptables and not has_nftables:
        fmt = "iptables-save"
        rules, errors = parse_iptables(text)
    elif has_nftables:
        fmt = "nftables"
        rules, errors = parse_nftables(text)
    else:
        return [], [ParseError(0, "", "unrecognized config format — expected iptables-save or nftables")]

    print(f"[parser] detected format: {fmt} — {len(rules)} rules parsed, {len(errors)} lines skipped",
          file=__import__('sys').stderr)
    return rules, errors


# ---------------------------------------------------------------------------
# 6. Standalone test (run as: python3 parser.py)
# ---------------------------------------------------------------------------

SAMPLE_IPTABLES = """
# Generated by iptables-save
*filter
:INPUT   DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT  ACCEPT [0:0]
# Allow web traffic from internal LAN
-A FORWARD -s 172.16.0.0/16 -d 10.0.0.5 -p tcp --dport 80 -j ACCEPT
# Deny this specific host (shadowed by the rule above -- anomaly expected)
-A FORWARD -s 172.16.1.10 -d 10.0.0.5 -p tcp --dport 80 -j DROP
# Allow DNS
-A FORWARD -p udp --dport 53 -j ACCEPT
# Block everything else
-A FORWARD -j DROP
COMMIT
"""

SAMPLE_NFTABLES = """
table ip filter {
    chain FORWARD {
        type filter hook forward priority 0; policy drop;
        ip saddr 192.168.1.0/24 ip daddr 10.0.0.0/8 tcp dport 443 accept
        ip saddr 192.168.1.50 ip daddr 10.0.0.5 tcp dport 443 drop
        ip daddr 10.0.0.0/8 udp dport 53 accept
        drop
    }
}
"""

if __name__ == "__main__":
    print("=== iptables-save test ===")
    rules, errors = parse(SAMPLE_IPTABLES)
    for r in rules:
        print(" ", r.to_prolog_fact())
    for e in errors:
        print(f"  SKIP line {e.line_number}: {e.reason} — {e.raw_line!r}")

    print("\n=== nftables test ===")
    rules, errors = parse(SAMPLE_NFTABLES)
    for r in rules:
        print(" ", r.to_prolog_fact())
    for e in errors:
        print(f"  SKIP line {e.line_number}: {e.reason} — {e.raw_line!r}")
