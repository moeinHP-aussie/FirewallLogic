% ============================================================================
% ip_subnet.pl
%
% Project 1, Phase 1 -- IP / Subnet / Port core logic
% ----------------------------------------------------------------------------
% This file contains NO firewall rules and NO parsing. It is the pure
% mathematical foundation everything else in the project stands on:
%
%   - representing an IPv4 or IPv6 address / CIDR block
%   - converting that representation to an integer network range
%   - converting Cisco-style wildcard masks to CIDR prefixes
%   - deciding whether one IP/subnet is a SUBSET of another
%   - deciding whether one port specifier is a SUBSET of another
%
% Every anomaly detector in Phase 2 (shadowing, redundancy, correlation,
% generalization) is built entirely out of is_subset_ip/2 and
% is_subset_port/2. If the containment logic here is wrong, every
% anomaly report downstream is wrong too -- so this file is tested
% exhaustively in isolation before Phase 2 begins.
% ============================================================================

:- module(ip_subnet, [
    ip_to_int/2,
    ip_range/3,
    is_subset_ip/2,
    is_subset_port/2,
    ip_overlaps/2,
    wildcard_to_prefix/2,
    valid_ip_term/1
]).

% ----------------------------------------------------------------------------
% 1. Representation
% ----------------------------------------------------------------------------
% An IP/subnet is one Prolog term. We support both address families
% explicitly rather than trying to guess -- a config parser will know
% which family it's reading, so it should say so:
%
%   ip4(A,B,C,D, PrefixLen)     -- IPv4, PrefixLen 0-32
%   ip6(H1,H2,H3,H4,H5,H6,H7,H8, PrefixLen)  -- IPv6, PrefixLen 0-128
%                                   (H1..H8 are the eight 16-bit hextets)
%
% Examples:
%   ip4(192,168,1,0,24)                              -- 192.168.1.0/24
%   ip4(10,0,0,5,32)                                  -- single host
%   ip6(0x2001,0xdb8,0,0,0,0,0,1, 128)                -- 2001:db8::1/128
%   ip6(0xfe80,0,0,0,0,0,0,0, 10)                     -- fe80::/10 (link-local)
%
% We deliberately do NOT unify IPv4 and IPv6 into one "generic address"
% representation (e.g. via IPv4-mapped IPv6 addresses). A firewall rule
% written for one family should never be silently compared against the
% other family -- that would be a correctness bug hiding as a feature.
% is_subset_ip/2 below enforces this: comparing an ip4/5 term against an
% ip6/9 term simply fails, it does not raise a confusing type error and
% it does not "helpfully" try to convert one to the other.

% ----------------------------------------------------------------------------
% 2. valid_ip_term(+Term)
% ----------------------------------------------------------------------------
% Checks that a term is a well-formed ip4/5 or ip6/9 term, with octets/
% hextets and prefix length in valid range. This exists so that Phase 3's
% parser can call it on every fact it's about to assert and get a clean
% true/false answer -- instead of an uncaught type_error crashing the
% whole ingestion run partway through a 2000-line config file.
% ----------------------------------------------------------------------------

valid_ip_term(ip4(A,B,C,D,PrefixLen)) :-
    integer(A), between(0,255,A),
    integer(B), between(0,255,B),
    integer(C), between(0,255,C),
    integer(D), between(0,255,D),
    integer(PrefixLen), between(0,32,PrefixLen).

valid_ip_term(ip6(H1,H2,H3,H4,H5,H6,H7,H8,PrefixLen)) :-
    maplist([H]>>(integer(H), between(0,0xFFFF,H)),
            [H1,H2,H3,H4,H5,H6,H7,H8]),
    integer(PrefixLen), between(0,128,PrefixLen).

% ----------------------------------------------------------------------------
% 3. ip_to_int(+IPTerm, -Int)
% ----------------------------------------------------------------------------
% Converts an address into a single unsigned integer:
%   - IPv4: 32-bit integer, A most significant (standard network order)
%   - IPv6: 128-bit integer, H1 most significant hextet
% Using plain integers (Prolog has unbounded-precision integers built in,
% so 128-bit values need no special handling) lets both families reuse
% exactly the same range/subset/overlap arithmetic below.
% ----------------------------------------------------------------------------

ip_to_int(IPTerm, Int) :-
    must_be(nonvar, IPTerm),
    ( valid_ip_term(IPTerm) -> true
    ; domain_error(valid_ip_term, IPTerm)
    ),
    ip_to_int_(IPTerm, Int).

ip_to_int_(ip4(A,B,C,D,_), Int) :-
    Int is (A << 24) + (B << 16) + (C << 8) + D.

ip_to_int_(ip6(H1,H2,H3,H4,H5,H6,H7,H8,_), Int) :-
    Int is (H1 << 112) + (H2 << 96) + (H3 << 80) + (H4 << 64) +
           (H5 << 48) + (H6 << 32) + (H7 << 16) + H8.

% Bit-width of the address family a term belongs to -- used to build
% the correct-length mask in ip_range/3 below.
address_bits(ip4(_,_,_,_,_), 32).
address_bits(ip6(_,_,_,_,_,_,_,_,_), 128).

prefix_len(ip4(_,_,_,_,P), P).
prefix_len(ip6(_,_,_,_,_,_,_,_,P), P).

% ----------------------------------------------------------------------------
% 4. ip_range(+IPTerm, -Start, -End)
% ----------------------------------------------------------------------------
% Computes the inclusive integer range [Start,End] an address/block covers.
% Works uniformly for IPv4 and IPv6 because both reduce to "TotalBits,
% PrefixLen, BaseInt" and the mask arithmetic is identical either way.
%
%   HostBits = TotalBits - PrefixLen
%   Mask     = TotalBits high bits set to 1, HostBits low bits set to 0
%   Start    = BaseInt /\ Mask                (network address)
%   End      = Start \/ (bitwise-not Mask)    (broadcast / last address)
%
% A /32 (IPv4) or /128 (IPv6) has zero host bits, so Mask is all-1s and
% Start = End = BaseInt exactly, as expected for a single host.
% ----------------------------------------------------------------------------

ip_range(IPTerm, Start, End) :-
    ip_to_int(IPTerm, BaseInt),
    address_bits(IPTerm, TotalBits),
    prefix_len(IPTerm, PrefixLen),
    HostBits is TotalBits - PrefixLen,
    FullMask is (1 << TotalBits) - 1,           % TotalBits worth of 1s
    Mask is (FullMask << HostBits) /\ FullMask,  % keep only TotalBits bits
    Start is BaseInt /\ Mask,
    Wildcard is Mask xor FullMask,               % bitwise-not Mask, TotalBits wide
    End is Start \/ Wildcard.

% ----------------------------------------------------------------------------
% 5. is_subset_ip(+Inner, +Outer)
% ----------------------------------------------------------------------------
% True when every address covered by Inner is also covered by Outer.
% This answers "is this narrow/specific rule completely covered by that
% broader rule?" -- exactly what Shadowing and Generalization need in
% Phase 2.
%
% Mixed-family comparison (ip4 vs ip6) always fails, on purpose: an
% IPv4 rule and an IPv6 rule can never shadow or be redundant with each
% other, no matter what their numeric values happen to be.
%
% Reflexive by design: is_subset_ip(X, X) holds (a block is a subset of
% itself). Redundancy detection in Phase 2 relies on this.
% ----------------------------------------------------------------------------

is_subset_ip(Inner, Outer) :-
    same_family(Inner, Outer),
    ip_range(Inner, InnerStart, InnerEnd),
    ip_range(Outer, OuterStart, OuterEnd),
    OuterStart =< InnerStart,
    InnerEnd =< OuterEnd.

same_family(ip4(_,_,_,_,_), ip4(_,_,_,_,_)) :- !.
same_family(ip6(_,_,_,_,_,_,_,_,_), ip6(_,_,_,_,_,_,_,_,_)) .
% Any other combination (including ip4 vs ip6) simply fails to unify
% with either clause above, so same_family/2 fails -- no clause needed.

% ----------------------------------------------------------------------------
% 6. ip_overlaps(+A, +B)
% ----------------------------------------------------------------------------
% True when A and B's ranges share at least one address in either
% direction, without either necessarily containing the other. This is
% what Correlation/Conflict detection in Phase 2 needs: two rules can
% partially overlap and still have conflicting actions on the addresses
% they share, even though neither rule fully shadows the other.
%
% Two closed intervals [S1,E1] and [S2,E2] overlap iff S1 =< E2 and S2 =< E1.
% Like is_subset_ip/2, this refuses to compare across address families.
% ----------------------------------------------------------------------------

ip_overlaps(A, B) :-
    same_family(A, B),
    ip_range(A, S1, E1),
    ip_range(B, S2, E2),
    S1 =< E2,
    S2 =< E1.

% ----------------------------------------------------------------------------
% 7. wildcard_to_prefix(?Wildcard, ?PrefixLen)
% ----------------------------------------------------------------------------
% Classic Cisco IOS ACLs specify a WILDCARD MASK instead of a CIDR
% prefix length -- e.g. "access-list 1 permit 192.168.1.0 0.0.0.255"
% means the same thing as 192.168.1.0/24. A wildcard mask is simply the
% bitwise complement of a normal subnet mask: 0-bits mean "must match",
% 1-bits mean "don't care".
%
% Wildcard is given as a wc(A,B,C,D) term (four octets, IPv4 only --
% wildcard masks are a Cisco IPv4 ACL convention and do not exist in
% IPv6 ACL syntax, which is prefix-length-only).
%
% This predicate works in both directions:
%   wildcard_to_prefix(wc(0,0,0,255), P)   ->  P = 24
%   wildcard_to_prefix(W, 24)              ->  W = wc(0,0,0,255)
%
% Only CONTIGUOUS wildcard masks (the ones that correspond to an actual
% CIDR prefix) are accepted. Cisco technically allows discontiguous
% wildcard masks (e.g. 0.0.0.85, used for advanced ACL tricks) -- those
% cannot be expressed as a prefix length at all, and are intentionally
% out of scope: this project's whole approach depends on every rule
% being expressible as a contiguous IP range, so a discontiguous
% wildcard should be flagged as unsupported input, not silently
% mishandled.
% ----------------------------------------------------------------------------

wildcard_to_prefix(wc(A,B,C,D), PrefixLen) :-
    ( var(PrefixLen) ->
        must_be(between(0,255), A), must_be(between(0,255), B),
        must_be(between(0,255), C), must_be(between(0,255), D),
        WildcardInt is (A << 24) + (B << 16) + (C << 8) + D,
        MaskInt is WildcardInt xor 0xFFFFFFFF,
        contiguous_mask_prefix_len(MaskInt, 32, PrefixLen)
    ;
        must_be(between(0,32), PrefixLen),
        HostBits is 32 - PrefixLen,
        FullMask is 0xFFFFFFFF,
        Mask is (FullMask << HostBits) /\ FullMask,
        WildcardInt is Mask xor FullMask,
        A is (WildcardInt >> 24) /\ 0xFF,
        B is (WildcardInt >> 16) /\ 0xFF,
        C is (WildcardInt >> 8) /\ 0xFF,
        D is WildcardInt /\ 0xFF
    ).

% Checks that MaskInt's binary form is N high 1-bits followed by all
% 0-bits (a legal subnet mask), and if so returns the prefix length.
% Fails (does not raise an error) for discontiguous masks, so callers
% can catch that with a simple \+ or ->/2 and report "unsupported ACL
% syntax" cleanly rather than crashing.
contiguous_mask_prefix_len(MaskInt, TotalBits, PrefixLen) :-
    between(0, TotalBits, PrefixLen),
    HostBits is TotalBits - PrefixLen,
    FullMask is (1 << TotalBits) - 1,
    ExpectedMask is (FullMask << HostBits) /\ FullMask,
    MaskInt =:= ExpectedMask,
    !.

% ----------------------------------------------------------------------------
% 8. Ports
% ----------------------------------------------------------------------------
% A port specifier is one of:
%   any                  -- matches every port
%   port(N)              -- a single port, e.g. port(80)
%   port_range(Lo,Hi)     -- an inclusive range, e.g. port_range(1024,2048)
%
% is_subset_port(Inner, Outer): true when every port matched by Inner
% is also matched by Outer. Mirrors is_subset_ip/2 exactly in spirit.
% ----------------------------------------------------------------------------

is_subset_port(_, any) :- !.

is_subset_port(port(P), port_range(Lo,Hi)) :-
    !,
    number(P),
    Lo =< P, P =< Hi.

is_subset_port(port(P), port(P)) :- !.

is_subset_port(port_range(Lo1,Hi1), port_range(Lo2,Hi2)) :-
    !,
    Lo2 =< Lo1, Hi1 =< Hi2.

% A range is a subset of a single port only if it degenerates to that
% exact point (Lo1 == Hi1 == P). We do not treat a range as "equal" to
% a point unless it truly is one -- getting this wrong would let
% Redundancy/Shadowing wrongly fire on a rule that only partially matches.
is_subset_port(port_range(P,P), port(P)) :- !.
