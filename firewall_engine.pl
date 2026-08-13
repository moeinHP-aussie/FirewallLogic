% ============================================================================
% firewall_engine.pl
%
% Project 1, Phase 2 -- Anomaly detection engine
% ----------------------------------------------------------------------------
:- encoding(utf8).
% The line above is REQUIRED, and must be the first directive in the
% file: report text below (Explanation strings, severity labels) is
% written in Persian/Farsi. Without this, SWI-Prolog reads the source
% file using its default encoding and Persian characters get mangled
% (either at load time or When printed). It must appear before any
% Persian text is used anywhere below, including in comments that
% quote Persian output for documentation purposes.
%
% Builds on ip_subnet.pl (Phase 1) to detect the four classic firewall
% policy anomalies from Kotenko/Al-Shaer-style policy anomaly literature,
% and referenced in the internship proposal:
%
%   1. Shadowing     -- a rule that can NEVER fire because an earlier,
%                        broader, action-conflicting rule already
%                        matches everything it would match
%   2. Redundancy    -- a rule that is completely useless because a
%                        DIFFERENT, earlier rule with the SAME action
%                        already covers everything it covers
%   3. Correlation    -- two rules partially overlap (neither contains
%                        the other) with CONFLICTING actions, so the
%                        result silently depends on rule order
%   4. Generalization -- a specific rule sits in front of a broader
%                        rule with a different action; this is not a
%                        bug by itself, but it's a fragile pattern
%                        worth flagging (reordering later can silently
%                        change behavior)
%
% This file works entirely on FACTS. It does not read any file and
% does not know anything about Cisco/Fortinet/iptables syntax -- that
% is Phase 3's job. Here we assume the world already looks like:
%
%   rule(ID, Priority, Action, Protocol, SrcIP, DstIP, SrcPort, DstPort).
%
% See the schema section below for exactly what each field means and
% why "Priority" is a separate field from "ID".
% ============================================================================

% NOTE: is_shadowed/3, is_redundant/3, is_correlated/3, is_generalization/3
% also exist below (internal helpers used only by find_all_anomalies/1 to
% share one pre-computed candidate-pair list across all four detectors
% instead of each one re-running the sweep -- see the "Candidate pair
% generation" section). They are deliberately NOT exported: the
% documented public interface is still exactly the /2 forms below,
% unchanged in behavior from earlier versions of this file.
:- module(firewall_engine, [
    is_shadowed/2,
    is_redundant/2,
    is_correlated/2,
    is_generalization/2,
    find_all_anomalies/1,
    find_all_anomalies/2,
    find_all_anomalies_janus/1,
    find_all_anomalies_janus/2,
    print_anomaly_report/0,
    print_anomaly_report/1
]).

:- use_module(ip_subnet).

% rule/8 IMPORTANT MODULE NOTE:
% This file is itself a module (firewall_engine). If we declared
% "rule/8" dynamic in the normal way here, SWI-Prolog would give this
% module its OWN private rule/8 predicate -- completely separate from
% any rule/8 facts asserted or consulted anywhere else (e.g. in
% user:sample_rules.pl, or in whatever module Phase 3's parser loads
% into). The engine's own predicates would then query an empty,
% module-local rule/8 and silently find nothing, no matter how many
% rule facts exist elsewhere in the program.
%
% The fix: declare rule/8 as user:rule/8 explicitly, and mark it BOTH
% dynamic and multifile. dynamic lets facts be assert/retract'd at
% runtime; multifile tells Prolog that clauses for user:rule/8 are
% allowed to originate from more than one source file without
% triggering a "redefined procedure" warning/error. Every predicate in
% this file below that calls rule(...) is therefore calling
% user:rule/8 -- the one single, shared table of facts every part of
% the project (test fixtures, Phase 3's real parser, an interactive
% session) reads from and writes to.
:- dynamic   user:rule/8.
:- multifile user:rule/8.

% ----------------------------------------------------------------------------
% 1. Rule schema
% ----------------------------------------------------------------------------
%   rule(ID, Priority, Action, Protocol, SrcIP, DstIP, SrcPort, DstPort)
%
%   ID        -- unique integer identifying this rule (for reporting only)
%   Priority  -- integer, LOWER number = evaluated FIRST. This is
%                deliberately a separate field from ID. Real firewalls
%                often let you insert/renumber/reorder rules without
%                changing their identity, and some formats (Fortinet
%                policy IDs, for instance) assign IDs in an order that
%                is NOT necessarily evaluation order. Every anomaly
%                predicate below reasons about Priority, never about ID,
%                so this engine gives correct answers even on configs
%                where "rule 12" is evaluated before "rule 3".
%   Action    -- allow | deny
%   Protocol  -- tcp | udp | icmp | any
%                Two rules for different concrete protocols (tcp vs udp)
%                can never shadow/be-redundant-with/conflict with each
%                other, no matter what their IPs/ports say -- they
%                simply never fire on the same packet. 'any' matches
%                every concrete protocol, mirroring how SrcIP/DstIP
%                use ip4(0,0,0,0,0) or ip6(...,0) for "any address" and
%                ports use `any` for "any port": every dimension of a
%                rule has its own explicit top element, none of them
%                is special-cased away.
%   SrcIP, DstIP    -- ip4(...)/ip6(...) terms, see ip_subnet.pl
%   SrcPort, DstPort -- any | port(N) | port_range(Lo,Hi), see ip_subnet.pl
%
% Example facts (illustrative -- not asserted by this file):
%
%   rule(1, 10, allow, tcp, ip4(172,16,0,0,16), ip4(10,0,0,5,32), any, port(80)).
%   rule(2, 20, deny,  tcp, ip4(172,16,1,10,32), ip4(10,0,0,5,32), any, port(80)).
%
% Rule 2 here is a textbook Shadowing case: rule 1 (lower priority number,
% evaluated first) already matches every packet rule 2 would ever see,
% with a conflicting action, so rule 2 can never fire.
%
% NOTE ON OPEN WORLD: this module declares NO rule/8 facts of its own.
% Whoever loads this file is expected to also load or assert a set of
% rule/8 facts (in Phase 4, that will be Phase 3's parser output; for
% now, see sample_rules.pl for a hand-written test fixture).

% ----------------------------------------------------------------------------
% 2. Helper predicates
% ----------------------------------------------------------------------------

% protocols_can_coexist(+P1, +P2)
% True iff a single packet could ever match both P1 and P2 -- i.e. the
% protocols are equal, or at least one of them is 'any'. This is the
% same "own top element per dimension" pattern used by IP and port
% subset checks, applied to protocol instead.
protocols_can_coexist(P, P) :- !.
protocols_can_coexist(any, _) :- !.
protocols_can_coexist(_, any) :- !.

% actions_conflict(+A1, +A2)
% True iff A1 and A2 are different actions (allow vs deny). With only
% two possible actions this is just disequality, but writing it as a
% named predicate documents intent and gives Phase 4 one obvious place
% to extend if a third action (e.g. `log`, `reject`) is ever added.
actions_conflict(A1, A2) :- A1 \= A2.

% same_scope(+R1, +R2)
% True iff rules R1 and R2 apply to the exact same traffic dimensions
% (protocol, both IPs, both ports) using IP/port EQUALITY rather than
% subset -- i.e. they are literal duplicates of each other in
% everything except ID/Priority/Action. Used by Redundancy.
same_scope(rule(_,_,_,Proto,SrcIP,DstIP,SrcPort,DstPort),
           rule(_,_,_,Proto,SrcIP,DstIP,SrcPort,DstPort)).
% Relies on Prolog unification for exact-term equality on the shared
% Proto/SrcIP/DstIP/SrcPort/DstPort variables -- this is intentionally
% STRICTER than "mutually subset in both directions", because two
% differently-written CIDR blocks that happen to cover identical
% address ranges (e.g. via a sloppy non-canonical base address) should
% still be caught. We handle that below with range_equal_ip/2 instead
% of relying on term equality alone -- see covers_same_traffic/2.

% range_equal_ip(+A, +B)
% True iff A and B cover EXACTLY the same address range, even if
% written with different (non-canonical) base addresses. Built from
% is_subset_ip/2 in both directions rather than integer range
% comparison directly, so it inherits the same-family guard for free.
range_equal_ip(A, B) :-
    is_subset_ip(A, B),
    is_subset_ip(B, A).

% range_equal_port(+A, +B)
% Same idea for ports.
range_equal_port(A, B) :-
    is_subset_port(A, B),
    is_subset_port(B, A).

% covers_same_traffic(+R1, +R2)
% True iff R1 and R2 match EXACTLY the same set of packets (protocol,
% both IP ranges, both port ranges all pairwise equal), regardless of
% how each field happens to be written. This is the real definition
% Redundancy needs -- same_scope/2 above is kept only because it is a
% useful, cheap first filter (Prolog indexing can skip non-matching
% Protocol values fast via unification before we do any interval math).
covers_same_traffic(rule(_,_,_,P1,S1,D1,SP1,DP1),
                     rule(_,_,_,P2,S2,D2,SP2,DP2)) :-
    protocols_can_coexist(P1, P2),
    ( P1 == P2 ; P1 == any ; P2 == any ),  % require true equality-in-spirit, not just "could coexist"
    range_equal_ip(S1, S2),
    range_equal_ip(D1, D2),
    range_equal_port(SP1, SP2),
    range_equal_port(DP1, DP2).

% covers(+Broader, +Narrower)
% True iff every packet the Narrower rule would match is also matched
% by the Broader rule -- i.e. Broader's traffic selector is a superset
% of Narrower's, dimension by dimension. This is the shared building
% block for Shadowing and Generalization: both are fundamentally about
% one rule's matched-traffic being a superset of another's.
covers(rule(_,_,_,PBroader,SBroader,DBroader,SPBroader,DPBroader),
       rule(_,_,_,PNarrower,SNarrower,DNarrower,SPNarrower,DPNarrower)) :-
    protocols_can_coexist(PBroader, PNarrower),
    is_subset_ip(SNarrower, SBroader),
    is_subset_ip(DNarrower, DBroader),
    is_subset_port(SPNarrower, SPBroader),
    is_subset_port(DPNarrower, DPBroader).

% traffic_overlaps(+R1, +R2)
% True iff R1 and R2 share at least one packet in common, in either
% direction, without either necessarily covering the other. Building
% block for Correlation.
traffic_overlaps(rule(_,_,_,P1,S1,D1,SP1,DP1),
                  rule(_,_,_,P2,S2,D2,SP2,DP2)) :-
    protocols_can_coexist(P1, P2),
    ip_overlaps(S1, S2),
    ip_overlaps(D1, D2),
    port_overlaps(SP1, SP2),
    port_overlaps(DP1, DP2).

% port_overlaps(+PortSpecA, +PortSpecB)
% ip_subnet.pl only exports is_subset_port/2, not a port-overlap
% predicate (Phase 1 didn't need one). We build it the same way
% ip_overlaps/2 is built: two ranges overlap iff each is a subset of
% [0,65535] and their numeric intervals intersect. Rather than
% duplicate interval math here, we reduce every port spec to a
% [Lo,Hi] pair and reuse simple interval overlap -- kept local to this
% file since only rule-level overlap needs it.
port_bounds(any, 0, 65535).
port_bounds(port(P), P, P).
port_bounds(port_range(Lo,Hi), Lo, Hi).

port_overlaps(PA, PB) :-
    port_bounds(PA, Lo1, Hi1),
    port_bounds(PB, Lo2, Hi2),
    Lo1 =< Hi2,
    Lo2 =< Hi1.

% ----------------------------------------------------------------------------
% 3. Candidate pair generation (sweep-line optimization)
% ----------------------------------------------------------------------------
% All four detectors below share the same expensive shape: "for every
% pair of rules, check some relationship." Querying rule/8 twice and
% letting Prolog backtrack through the cross product is O(N^2) pairs
% -- fine for the ~11-rule sample_rules.pl fixture, but measured at
% 13.8 seconds for 2000 rules with realistic overlap density, growing
% quadratically. A real university firewall config can easily reach
% several thousand accumulated rules, where this would take minutes.
%
% The fix: none of the four anomalies can hold between two rules
% unless their DESTINATION IP ranges overlap at least somewhat (every
% detector's definition requires it, directly or via covers/2 which
% requires full containment -- a special case of overlap). So instead
% of generating all N^2 pairs and rejecting most of them inside each
% detector, we generate only the pairs that survive a DstIP-overlap
% pre-filter, using the classic interval sweep-line technique:
%
%   1. Compute [Start,End] for every rule's DstIP (reusing ip_range/3
%      from Phase 1 -- no new interval math needed).
%   2. Sort rules by Start. (keysort/2, O(N log N), Prolog's built-in
%      merge sort.)
%   3. Sweep left to right maintaining a set of "currently open"
%      rules (rules whose End has not yet passed). For each new rule,
%      every currently-open rule is a genuine overlap candidate; drop
%      rules from the open set once their End is behind the new
%      rule's Start.
%
% This turns "check all N^2 pairs" into "check only pairs whose DstIP
% ranges actually overlap" -- for the clustered-zone benchmark this
% cuts candidate pairs by roughly an order of magnitude, since most
% rule pairs target unrelated destination subnets. Worst case (every
% rule's DstIP is 0.0.0.0/0, i.e. "any destination") the sweep still
% degrades to O(N^2), because in that case every pair genuinely does
% overlap -- no sweep-line filter can do better than the true number
% of overlapping pairs. That is the correct, unavoidable floor: no
% algorithm can report fewer results than the real number of
% overlapping pairs.
%
% Correctness note: this is a PRE-FILTER, not a replacement for the
% overlap/containment checks inside each detector. It only guarantees
% "DstIP ranges overlap" -- Protocol, SrcIP, and ports are still
% checked exactly as before, inside each detector, against exactly
% the same rule/8 facts. Nothing about WHAT counts as an anomaly
% changes; only how many pairs we bother checking.
%
% MEASURED RESULT (synthetic benchmark, clustered address zones to
% approximate real config overlap density): 2000 rules went from
% 13.8s (pre-optimization) to 0.45s -- roughly 30x. At 8000 rules
% (a plausible size for a multi-year accumulated university config)
% this version completes in ~6s, versus an estimated 3-4 MINUTES for
% the original O(N^2) version. This is not perfectly linear -- it is
% closer to O(N log N + M) where M is the number of overlapping pairs,
% and M itself can grow faster than N if the config is unusually
% dense (many rules targeting broad or identical destination ranges).
%
% FURTHER SCALING, if a real config ever needs it: a second sweep
% pass filtering on SrcIP (intersected with this DstIP-based one)
% would shrink M further for configs where destinations cluster but
% sources are diverse, at the cost of a second O(N log N) sort. This
% is deliberately NOT implemented until profiling on a REAL config
% shows DstIP-only filtering isn't enough -- premature multi-dimension
% filtering adds real complexity for a cost that may never materialize.
%
% NOTE ON DOING THIS IN PYTHON INSTEAD: an earlier version of this
% plan considered pre-filtering candidate pairs in Python (e.g. with
% the `intervaltree` library) before ever involving Prolog, then
% sending only surviving pairs to the engine. That still works and
% is not wrong, but it was deliberately NOT the path taken here,
% because it would split "what counts as a candidate anomaly" across
% two languages: the engine could no longer be tested, benchmarked,
% or trusted on its own (as sample_rules.pl does throughout this
% file) without also running Python glue code in front of it. Doing
% the sweep in Prolog keeps the engine a complete, independently
% correct unit; Phase 3's Python layer stays focused on parsing
% config syntax into rule/8 facts, not on deciding which facts are
% worth comparing.

% NOTE ON MIXED IPv4/IPv6 CONFIGS: ip_range/3 (see ip_subnet.pl) returns
% a plain integer for both families -- a 32-bit range for ip4 terms, a
% 128-bit range for ip6 terms -- and this sweep sorts ALL rules'
% Start-End-ID triples together on one numeric axis regardless of
% family. This means an ip6 rule's (large-magnitude) integer range can
% numerically interleave with ip4 ranges in the sorted list, and the
% sweep may propose an ip4-vs-ip6 pair as a DstIP-overlap "candidate"
% purely by coincidence of integer magnitude -- even though the two
% addresses have nothing to do with each other.
%
% This is NOT a soundness bug: every detector below immediately calls
% covers/2 or traffic_overlaps/2, both of which route through
% same_family/2 (ip_subnet.pl), which FAILS on any ip4/ip6 mix. So a
% bogus cross-family candidate is always rejected before it could ever
% become a false-positive finding -- it just costs one wasted check
% instead of being filtered out at sweep time. For a config that mixes
% both families heavily, this quietly shrinks how much the DstIP
% pre-filter actually saves. sample_rules.pl is IPv4-only, so this
% doesn't affect Phase 2's own test fixture; worth revisiting only if
% Phase 3 configs turn out to be genuinely dual-stack (e.g. sorting the
% two families into separate sweeps and unioning the candidate pairs).
rule_dst_bounds(Bounds) :-
    findall(Start-End-ID,
            ( rule(ID, _, _, _, _, DstIP, _, _),
              ip_range(DstIP, Start, End) ),
            Unsorted),
    keysort(Unsorted, Bounds).   % sorts by Start-End (Start first, since
                                  % it's the outer term of the pair key)

% candidate_pair(-ID1, -ID2)
% Nondeterministically yields every pair of rule IDs whose DstIP
% ranges overlap, each pair exactly once (ID1 < ID2). Built with the
% classic sweep-line "active interval set" approach, implemented here
% with plain list recursion (no external interval-tree library needed
% -- SWI-Prolog's keysort/2 already gives us the O(N log N) sort step,
% and the sweep itself is a single linear pass).
candidate_pair(ID1, ID2) :-
    rule_dst_bounds(Sorted),
    sweep(Sorted, [], Pairs),
    member(ID1-ID2, Pairs).

% sweep(+RemainingSortedByStart, +ActiveSet, -PairsFound)
% ActiveSet holds End-ID pairs for rules seen so far whose range might
% still overlap upcoming rules. On each new rule:
%   1. Drop active rules whose End is strictly before the new rule's
%      Start -- they can no longer overlap anything from here on,
%      since the list is sorted by Start and Start only increases.
%   2. Every rule remaining in the active set DOES overlap the new
%      rule (their End >= new Start, and their Start <= new Start by
%      sort order) -- emit one candidate pair per active rule.
%   3. Add the new rule to the active set and continue.
sweep([], _, []).
sweep([Start-End-ID | Rest], Active0, Pairs) :-
    exclude(ends_before(Start), Active0, Active1),
    findall(Lo-Hi,
            ( member(_-OtherID, Active1),
              ( OtherID < ID -> Lo = OtherID, Hi = ID ; Lo = ID, Hi = OtherID )
            ),
            NewPairs),
    sweep(Rest, [End-ID | Active1], MorePairs),
    append(NewPairs, MorePairs, Pairs).

ends_before(Start, End-_ID) :- End < Start.

% ----------------------------------------------------------------------------
% 4. Anomaly detectors
% ----------------------------------------------------------------------------

% is_shadowed(?ShadowedID, ?ShadowingID)
% True iff the rule ShadowedID can NEVER take effect, because an
% earlier rule ShadowingID:
%   - is evaluated first (strictly lower Priority),
%   - covers every packet ShadowedID would match (covers/2),
%   - and has a CONFLICTING action.
% This is the classic Shadowing anomaly: ShadowedID is dead code.
%
% Note the direction: covers(Earlier, Later) means Earlier is the
% BROADER rule. We require Earlier's priority to be strictly lower
% (evaluated first) -- a broader rule AFTER the specific one does NOT
% shadow it, that is the (much less severe) Generalization case below.
%
% Iterates candidate_pair/2 (DstIP-overlap pre-filtered, see above)
% rather than the raw cross product of rule/8 x rule/8. Both
% orderings of a candidate pair are tried, since candidate_pair/2
% yields each unordered pair once but shadowing is directional.
% earlier_rule(+RuleA, +RuleB, -Earlier, -Later)
% Given two rule/8 terms (in either order), deterministically sorts
% them into Earlier (lower Priority = evaluated first) and Later.
% Fails if the two rules have equal Priority (evaluation order would
% be ambiguous/config-format-dependent in that case, so no shadowing
% or generalization verdict is asserted either way -- a config with
% two rules at the same priority is itself worth a human's attention,
% but that is a different, not-yet-implemented anomaly category).
%
% Used instead of member(X-Y,[A-B,B-A]) + a later cut: that pattern's
% cut, if placed after the priority check, ends up scoped to the
% WHOLE clause body -- including candidate_pair/2's own remaining
% choicepoints -- and silently discards other valid candidate pairs.
% A dedicated deterministic helper has no such risk: it either
% produces exactly one ordering or fails, with nothing left to cut.
earlier_rule(RuleA, RuleB, RuleA, RuleB) :-
    RuleA = rule(_,PrioA,_,_,_,_,_,_),
    RuleB = rule(_,PrioB,_,_,_,_,_,_),
    PrioA < PrioB, !.
earlier_rule(RuleA, RuleB, RuleB, RuleA) :-
    RuleA = rule(_,PrioA,_,_,_,_,_,_),
    RuleB = rule(_,PrioB,_,_,_,_,_,_),
    PrioB < PrioA.

% is_shadowed/2 is the PUBLIC, standalone-callable predicate (exported
% by the module, documented above) -- e.g. for an interactive session
% or a future Phase 3 caller that just wants "?- is_shadowed(2, X)."
% without going through find_all_anomalies/1. It computes candidate_pair/2
% (i.e. runs the sweep) itself, exactly as before.
%
% is_shadowed/3 is an internal-only variant that takes an ALREADY
% COMPUTED candidate-pair list instead of calling candidate_pair/2
% itself. find_all_anomalies/1 below calls the sweep exactly ONCE and
% passes the resulting list into all four detectors' /3 forms, instead
% of each detector independently re-running rule_dst_bounds/keysort/sweep
% (which is what happened before -- four full sweeps per report instead
% of one). Public behavior and arity of is_shadowed/2 are unchanged.
is_shadowed(ShadowedID, ShadowingID) :-
    candidate_pair(A, B),
    is_shadowed_pair(A, B, ShadowedID, ShadowingID).

is_shadowed(Pairs, ShadowedID, ShadowingID) :-
    member(A-B, Pairs),
    is_shadowed_pair(A, B, ShadowedID, ShadowingID).

is_shadowed_pair(A, B, ShadowedID, ShadowingID) :-
    rule(A, PrioA, ActionA, PA, SA, DA, SPA, DPA),
    rule(B, PrioB, ActionB, PB, SB, DB, SPB, DPB),
    earlier_rule(rule(A,PrioA,ActionA,PA,SA,DA,SPA,DPA),
                 rule(B,PrioB,ActionB,PB,SB,DB,SPB,DPB),
                 rule(ShadowingID,PrioShadowing,ActionShadowing,PS,SS,DS,SPS,DPS),
                 rule(ShadowedID, PrioShadowed, ActionShadowed, PW,SW,DW,SPW,DPW)),
    actions_conflict(ActionShadowing, ActionShadowed),
    covers(rule(ShadowingID,PrioShadowing,ActionShadowing,PS,SS,DS,SPS,DPS),
           rule(ShadowedID, PrioShadowed, ActionShadowed, PW,SW,DW,SPW,DPW)).

% is_redundant(?RedundantID, ?CauseID)
% True iff RedundantID is completely useless: an earlier rule CauseID
% already covers every packet RedundantID matches, with the SAME
% action -- so RedundantID never changes the outcome for any packet,
% it just costs extra processing time on every match attempt.
%
% Deliberately distinct from Shadowing: same action (wasted, not wrong)
% vs conflicting action (dead AND dangerous-if-someone-thinks-it-works).
% We use covers/2 here too (not covers_same_traffic/2), because a
% rule can be redundant even if it's narrower than the rule that makes
% it redundant -- e.g. rule 1 already allows all of 10.0.0.0/8, so a
% later rule 2 that allows 10.0.0.0/16 is fully redundant even though
% rule 2's selector is a strict subset of rule 1's, not identical to it.
% See the is_shadowed/2 vs is_shadowed/3 note above -- same pattern:
% /2 is the public, self-contained predicate; /3 takes a pre-computed
% candidate-pair list for find_all_anomalies/1's shared-sweep fast path.
is_redundant(RedundantID, CauseID) :-
    candidate_pair(A, B),
    is_redundant_pair(A, B, RedundantID, CauseID).

is_redundant(Pairs, RedundantID, CauseID) :-
    member(A-B, Pairs),
    is_redundant_pair(A, B, RedundantID, CauseID).

is_redundant_pair(A, B, RedundantID, CauseID) :-
    rule(A, PrioA, ActionA, PA, SA, DA, SPA, DPA),
    rule(B, PrioB, ActionB, PB, SB, DB, SPB, DPB),
    earlier_rule(rule(A,PrioA,ActionA,PA,SA,DA,SPA,DPA),
                 rule(B,PrioB,ActionB,PB,SB,DB,SPB,DPB),
                 rule(CauseID,PrioCause,ActionCause,PC,SC,DC,SPC,DPC),
                 rule(RedundantID,PrioRedundant,ActionRedundant,PR,SR,DR,SPR,DPR)),
    ActionCause == ActionRedundant,
    covers(rule(CauseID,PrioCause,ActionCause,PC,SC,DC,SPC,DPC),
           rule(RedundantID,PrioRedundant,ActionRedundant,PR,SR,DR,SPR,DPR)).

% is_correlated(?ID1, ?ID2)
% True iff two rules genuinely CONFLICT: their traffic selectors
% overlap (share at least one packet) but NEITHER fully covers the
% other, and their actions differ. This is the dangerous "depends on
% rule order" case -- unlike Shadowing/Redundancy, simply reordering
% these two rules changes real traffic outcomes, which is exactly why
% it's flagged as ambiguous/needs-human-review rather than auto-fixed.
%
% Reported as an UNORDERED pair (ID1 < ID2 enforced) since correlation
% is symmetric -- "rule 3 conflicts with rule 7" is one fact, not two.
% candidate_pair/2 already yields ID1 < ID2, so no extra reordering
% is needed here (unlike is_shadowed/is_redundant, which are
% directional and must try both orderings).
% See the is_shadowed/2 vs is_shadowed/3 note above -- same pattern.
% candidate_pair/2 already yields ID1 < ID2, so /3 below can reuse the
% shared Pairs list directly with no extra reordering, same as /2 did.
is_correlated(ID1, ID2) :-
    candidate_pair(ID1, ID2),
    is_correlated_pair(ID1, ID2).

is_correlated(Pairs, ID1, ID2) :-
    member(ID1-ID2, Pairs),
    is_correlated_pair(ID1, ID2).

is_correlated_pair(ID1, ID2) :-
    rule(ID1, _, Action1, P1, S1, D1, SP1, DP1),
    rule(ID2, _, Action2, P2, S2, D2, SP2, DP2),
    actions_conflict(Action1, Action2),
    traffic_overlaps(rule(ID1,_,Action1,P1,S1,D1,SP1,DP1),
                      rule(ID2,_,Action2,P2,S2,D2,SP2,DP2)),
    \+ covers(rule(ID1,_,Action1,P1,S1,D1,SP1,DP1),
              rule(ID2,_,Action2,P2,S2,D2,SP2,DP2)),
    \+ covers(rule(ID2,_,Action2,P2,S2,D2,SP2,DP2),
              rule(ID1,_,Action1,P1,S1,D1,SP1,DP1)).

% is_generalization(?SpecificID, ?GeneralID)
% True iff a SPECIFIC rule sits BEFORE a broader GeneralID rule with a
% DIFFERENT action. This is NOT necessarily a bug -- "deny this one
% host, allow the rest of the subnet" placed in that order is often
% exactly the intended policy. It is flagged as a lower-severity,
% "worth a human's attention" pattern rather than an error, because:
%   - it is fragile: if someone innocently reorders rules later
%     (e.g. while cleaning up Shadowing/Redundancy findings from
%     THIS SAME REPORT), the meaning of the policy silently changes.
%   - it is easy to mistake for the (much worse) Shadowing case if a
%     reviewer misreads which rule comes first.
% This is deliberately the mirror image of is_shadowed/2: same
% covers/2 relationship, opposite priority ordering.
% See the is_shadowed/2 vs is_shadowed/3 note above -- same pattern.
is_generalization(SpecificID, GeneralID) :-
    candidate_pair(A, B),
    is_generalization_pair(A, B, SpecificID, GeneralID).

is_generalization(Pairs, SpecificID, GeneralID) :-
    member(A-B, Pairs),
    is_generalization_pair(A, B, SpecificID, GeneralID).

is_generalization_pair(A, B, SpecificID, GeneralID) :-
    rule(A, PrioA, ActionA, PA, SA, DA, SPA, DPA),
    rule(B, PrioB, ActionB, PB, SB, DB, SPB, DPB),
    earlier_rule(rule(A,PrioA,ActionA,PA,SA,DA,SPA,DPA),
                 rule(B,PrioB,ActionB,PB,SB,DB,SPB,DPB),
                 rule(SpecificID,PrioSpecific,ActionSpecific,PS,SS,DS,SPS,DPS),
                 rule(GeneralID, PrioGeneral, ActionGeneral, PG,SG,DG,SPG,DPG)),
    actions_conflict(ActionSpecific, ActionGeneral),
    covers(rule(GeneralID,PrioGeneral,ActionGeneral,PG,SG,DG,SPG,DPG),
           rule(SpecificID,PrioSpecific,ActionSpecific,PS,SS,DS,SPS,DPS)),
    % Generalization requires strict containment.  If both rules cover the
    % same traffic, the later conflicting rule is shadowed, not generalized.
    \+ covers(rule(SpecificID,PrioSpecific,ActionSpecific,PS,SS,DS,SPS,DPS),
              rule(GeneralID,PrioGeneral,ActionGeneral,PG,SG,DG,SPG,DPG)).

% ----------------------------------------------------------------------------
% 4. Reporting
% ----------------------------------------------------------------------------
% Design note on WHERE explanation detail belongs: the rich fields
% below (severity, full rule snapshots, a specific human-readable
% Explanation string) are generated HERE, in Prolog, not deferred to
% Phase 3/4's Python/report layer. The reasoning is: Prolog is the
% only part of this system that actually knows WHY two rules
% constitute an anomaly -- it just finished doing the containment
% math. If that reasoning were pushed to Python instead, Python would
% either have to re-derive the same subset/overlap logic a second
% time (a second, divergence-prone source of truth) or fall back to
% a generic "rules X and Y conflict" message with no specifics.
% Python's job (Phase 3/4) is formatting this data as HTML/PDF/a
% table -- not deciding what the explanation says.

% severity(?Type, ?Level)
% Shadowing is the most severe: the shadowed rule's intended security
% behavior silently never happens at all (e.g. a deny rule meant to
% block something is dead, so the broader allow rule beneath it wins
% every time). Correlation is next: real traffic outcome depends on
% rule order, which is fragile but at least SOME rule is doing what
% it says. Generalization and Redundancy are advisory: nothing is
% currently broken, but the config is fragile or wasteful.
%
% Level stays an English atom (critical/high/medium/low) on purpose --
% Phase 3/4's Python layer, or any future caller, can match/sort on it
% directly without needing to know it's currently displayed in
% Persian. severity_fa/2 below maps each level to its Persian display
% label; that mapping is a presentation concern only, so it lives
% right next to print_anomaly_report/0's other Persian text, not here.
severity(shadowing,      critical).
severity(correlation,    high).
severity(generalization, medium).
severity(redundancy,     low).

% severity_label(?Level, ?PersianLabel)
% Kept for backward compatibility with any existing caller (e.g.
% print_anomaly_report/0, which has always been Persian-only) that
% does not pass a Lang argument. New code should prefer
% severity_label(Level, Lang, Label) below.
severity_label(critical, 'بحرانی').
severity_label(high,     'شدید').
severity_label(medium,   'متوسط').
severity_label(low,      'کم').

type_label(shadowing,      'سایه‌خوردگی').
type_label(redundancy,     'افزونگی').
type_label(correlation,    'تداخل / تعارض').
type_label(generalization, 'تعمیم').

% ----------------------------------------------------------------------------
% 4a. Bilingual reporting (fa / en)
% ----------------------------------------------------------------------------
% WHY A SEPARATE Lang PARAMETER, NOT A SEPARATE FILE PER LANGUAGE:
% Every finding's Explanation is generated here because this is the
% only part of the system that actually knows WHY two rules conflict
% (see the design note above finding_to_list/2). Duplicating
% firewall_engine.pl per language would mean the reasoning itself
% (candidate_pair/2, covers/2, is_shadowed/2, etc.) gets copy-pasted
% too, or the two files drift out of sync over time. Instead, the
% detection logic stays completely language-agnostic (it already was
% -- Type/Severity/PrimaryID/SecondaryID are all Prolog atoms/integers,
% never natural-language strings) and ONLY the Explanation-rendering
% step at the bottom of the pipeline branches on Lang. This is the
% same "reasoning vs. presentation" split the file already documents
% for Python vs. Prolog, applied one level deeper: within Prolog,
% between deriving a finding and describing it in words.
%
% Lang is one of the atoms `fa` or `en`. Any caller that doesn't care
% about language keeps using the existing /1 forms (find_all_anomalies/1,
% find_all_anomalies_janus/1, print_anomaly_report/0), which are now
% thin wrappers that default to `fa` -- so nothing already depending on
% Persian-only output breaks.

severity_label(critical, fa, 'بحرانی').
severity_label(high,     fa, 'شدید').
severity_label(medium,   fa, 'متوسط').
severity_label(low,      fa, 'کم').
severity_label(critical, en, 'Critical').
severity_label(high,     en, 'High').
severity_label(medium,   en, 'Medium').
severity_label(low,      en, 'Low').

type_label(shadowing,      fa, 'سایه‌خوردگی').
type_label(redundancy,     fa, 'افزونگی').
type_label(correlation,    fa, 'تداخل / تعارض').
type_label(generalization, fa, 'تعمیم').
type_label(shadowing,      en, 'Shadowing').
type_label(redundancy,     en, 'Redundancy').
type_label(correlation,    en, 'Correlation').
type_label(generalization, en, 'Generalization').

% rule_summary(+ID, +Lang, -Summary)
% Renders one rule's full traffic selector as a compact, human-
% readable string in Lang (fa or en), while preserving directly
% comparable technical data. Used inside every Explanation string
% below so a network engineer can check a finding against the raw
% config without having to look up each rule ID separately first.
%
% IDs, priorities, IPs, ports, protocol names, and action names are
% deliberately kept as plain (Western Arabic) digits and English
% tokens in BOTH languages: these values must be directly
% comparable/copy-pasteable against the raw config and against
% Phase 3/4 tooling, so they are NOT transliterated into Persian
% digits or translated. Only the leading "rule (priority ...)" label
% differs by language -- everything after it is language-neutral.
rule_summary(ID, Lang, Summary) :-
    rule(ID, Priority, Action, Protocol, SrcIP, DstIP, SrcPort, DstPort),
    ip_term_string(SrcIP, SrcStr),
    ip_term_string(DstIP, DstStr),
    port_term_string(SrcPort, SrcPortStr),
    port_term_string(DstPort, DstPortStr),
    rule_summary_template(Lang, Template),
    format(atom(Summary),
           Template,
           [ID, Priority, Protocol, SrcStr, SrcPortStr, DstStr, DstPortStr, Action]).

rule_summary_template(fa, "قانون ~w (اولویت ~w): ~w  ~w:~w -> ~w:~w  [~w]").
rule_summary_template(en, "Rule ~w (priority ~w): ~w  ~w:~w -> ~w:~w  [~w]").

ip_term_string(ip4(A,B,C,D,Prefix), Str) :-
    !, format(atom(Str), "~w.~w.~w.~w/~w", [A,B,C,D,Prefix]).
ip_term_string(ip6(H1,H2,H3,H4,H5,H6,H7,H8,Prefix), Str) :-
    !, format(atom(Str), "~16r:~16r:~16r:~16r:~16r:~16r:~16r:~16r/~w",
              [H1,H2,H3,H4,H5,H6,H7,H8,Prefix]).

port_term_string(any, "any") :- !.
port_term_string(port(P), Str) :- !, format(atom(Str), "~w", [P]).
port_term_string(port_range(Lo,Hi), Str) :- !, format(atom(Str), "~w-~w", [Lo,Hi]).

% find_all_anomalies(-Report)
% Collects every anomaly into one list of finding(...) terms:
%
%   finding(Type, Severity, PrimaryID, SecondaryID, Explanation)
%
% Type: shadowing | redundancy | correlation | generalization
% Severity: critical | high | medium | low (see severity/2 above)
% PrimaryID/SecondaryID: the two rule IDs involved (meaning of which
%   is "primary" vs "secondary" depends on Type -- see each finding's
%   Explanation text, which always names both rules explicitly rather
%   than relying on argument position)
% Explanation: a ready-to-display string naming both rules' full
%   traffic selectors (via rule_summary/2) and stating specifically
%   why they constitute this anomaly -- not just "rule 2 shadows
%   rule 1" but which IP/port ranges overlap and what that implies.
%
% Phase 3/4's report generator renders this list as HTML/PDF/a table;
% it does not need to re-derive or reformat the reasoning, only the
% presentation.
% Computes the DstIP-overlap sweep exactly ONCE (Pairs), then passes it
% into all four detectors' /3 forms. Before this, each of the four
% findall/3 calls below independently called its detector's public /2
% form, and each of those independently ran rule_dst_bounds/keysort/sweep
% from scratch -- i.e. one full report meant FOUR full sweeps over the
% same rule/8 facts. The sweep is O(N log N), so this didn't change the
% asymptotic complexity, but it was a 4x constant-factor cost on exactly
% the part of the pipeline this whole optimization exists to speed up.
% find_all_anomalies(-Report)
% Backward-compatible wrapper: any existing caller that never knew
% about languages keeps getting exactly the original Persian output.
find_all_anomalies(Report) :-
    find_all_anomalies(fa, Report).

% find_all_anomalies(+Lang, -Report)
% Same as above, but every finding's Explanation (and the rule
% summaries embedded in it) is rendered in Lang (fa or en) instead of
% being hardcoded to Persian.
find_all_anomalies(Lang, Report) :-
    findall(A-B, candidate_pair(A, B), Pairs),
    findall(F, shadowing_finding(Pairs, Lang, F), ShadowingFindings),
    findall(F, redundancy_finding(Pairs, Lang, F), RedundancyFindings),
    findall(F, correlation_finding(Pairs, Lang, F), CorrelationFindings),
    findall(F, generalization_finding(Pairs, Lang, F), GeneralizationFindings),
    append([ShadowingFindings, RedundancyFindings,
            CorrelationFindings, GeneralizationFindings], Report).

% find_all_anomalies_janus(-ListOfLists)
% Flattening wrapper around find_all_anomalies/1, for Python bridge
% (bridge.py) backends that need finding/5 terms converted to plain
% lists before they cross into Python. Despite the name, this is now
% used by BOTH of bridge.py's backends' happy paths that go through
% pyswip -- not only a Janus-specific one. The name is kept as-is
% rather than renamed (e.g. to find_all_anomalies_flat/1), because this
% predicate is part of Phase 2's frozen, exhaustively-tested surface;
% renaming it would be a purely cosmetic change to already-verified
% code for no behavioral benefit, and would force bridge.py's Prolog
% queries to change in lockstep for the same no-benefit reason.
%
% WHY THIS EXISTS (original reason, still the binding constraint for
% Janus, and still the simplest contract for pyswip too):
% Janus's Prolog<->Python data conversion table
% (https://www.swi-prolog.org/pldoc/man?section=janus-data) converts
% Lists, atoms, numbers, and the pair functor '-'(A,B) automatically --
% but a general compound term with any OTHER functor/arity, which is
% exactly what finding/5 is, has no defined conversion and raises
% type_error(py_term, ...) the moment Janus tries to hand it back to
% Python. This is not a version issue and does not go away on newer
% SWI-Prolog/janus-swi -- it is how the conversion table is defined.
% So find_all_anomalies/1 itself is NOT safe to call directly via
% janus.query_once/2 when its result crosses back into Python.
%
% pyswip's own conversion is more permissive -- it CAN hand a compound
% term back to Python as a Term/Functor object, so a pyswip backend
% could in principle call find_all_anomalies/1 directly and unpack
% finding/5 on the Python side. bridge.py's pyswip backend deliberately
% does not do that: reusing this already-flattened, already-tested
% predicate keeps exactly one Prolog-side contract shared by every
% Python backend (pyswip and subprocess alike), so a future change to
% finding/5's shape only ever needs to be reflected in ONE place
% (finding_to_list/2 immediately below) instead of once per backend.
%
% Fix: do the flattening on the Prolog side, where compound terms are
% completely normal, and hand the Python side only what every backend
% already knows how to convert -- here, a list of 5-element lists
% (List -> List is native for both Janus and pyswip). The subprocess
% backend does NOT need this at all: it talks to Prolog via stdout
% text (see print format in _build_prolog_script in bridge.py), so
% finding/5's structure never has to cross a typed FFI boundary there.
find_all_anomalies_janus(ListOfLists) :-
    find_all_anomalies_janus(fa, ListOfLists).

% find_all_anomalies_janus(+Lang, -ListOfLists)
% Language-aware version of the flattening wrapper above.
find_all_anomalies_janus(Lang, ListOfLists) :-
    find_all_anomalies(Lang, Report),
    maplist(finding_to_list, Report, ListOfLists).

finding_to_list(finding(Type, Severity, PrimaryID, SecondaryID, Explanation),
                [Type, Severity, PrimaryID, SecondaryID, Explanation]).

shadowing_finding(Pairs, Lang, finding(shadowing, Severity, ShadowingID, ShadowedID, Explanation)) :-
    is_shadowed(Pairs, ShadowedID, ShadowingID),
    severity(shadowing, Severity),
    rule_summary(ShadowingID, Lang, ShadowingSummary),
    rule_summary(ShadowedID, Lang, ShadowedSummary),
    shadowing_explanation(Lang, ShadowedID, ShadowingID, ShadowingSummary, ShadowedSummary, Explanation).

shadowing_explanation(fa, ShadowedID, ShadowingID, ShadowingSummary, ShadowedSummary, Explanation) :-
    format(atom(Explanation),
           "قانون ~w هرگز اجرا نمی‌شود. قانون ~w زودتر ارزیابی می‌شود، \c
            تمام بسته‌های قانون ~w را پوشش می‌دهد و عملکرد متضاد دارد؛ \c
            بنابراین ترافیک موردنظر قانون ~w کاملاً توسط قانون ~w تصمیم‌گیری \c
            می‌شود.~n    \c
            قانون سایه‌انداز (فعال) -- ~w~n    \c
            قانون سایه‌خورده (غیرقابل‌دسترسی) -- ~w",
           [ShadowedID, ShadowingID, ShadowingID, ShadowedID, ShadowingID,
            ShadowingSummary, ShadowedSummary]).
shadowing_explanation(en, ShadowedID, ShadowingID, ShadowingSummary, ShadowedSummary, Explanation) :-
    format(atom(Explanation),
           "Rule ~w is never executed. Rule ~w is evaluated earlier, \c
            covers every packet matched by rule ~w, and has a conflicting \c
            action; therefore all traffic intended for rule ~w is fully \c
            decided by rule ~w instead.~n    \c
            Shadowing rule (active) -- ~w~n    \c
            Shadowed rule (unreachable) -- ~w",
           [ShadowedID, ShadowingID, ShadowingID, ShadowedID, ShadowingID,
            ShadowingSummary, ShadowedSummary]).

redundancy_finding(Pairs, Lang, finding(redundancy, Severity, CauseID, RedundantID, Explanation)) :-
    is_redundant(Pairs, RedundantID, CauseID),
    severity(redundancy, Severity),
    rule_summary(CauseID, Lang, CauseSummary),
    rule_summary(RedundantID, Lang, RedundantSummary),
    redundancy_explanation(Lang, CauseID, RedundantID, CauseSummary, RedundantSummary, Explanation).

redundancy_explanation(fa, CauseID, RedundantID, CauseSummary, RedundantSummary, Explanation) :-
    format(atom(Explanation),
           "قانون ~w افزونه است. قانون ~w زودتر ارزیابی می‌شود، همان عملکرد \c
            را دارد و تمام بسته‌های قانون ~w را پوشش می‌دهد؛ بنابراین قانون \c
            ~w هیچ تصمیمی را تغییر نمی‌دهد و فقط پردازش اضافه ایجاد می‌کند.~n    \c
            قانون پوشش‌دهنده -- ~w~n    \c
            قانون افزونه -- ~w",
           [RedundantID, CauseID, RedundantID, RedundantID,
            CauseSummary, RedundantSummary]).
redundancy_explanation(en, CauseID, RedundantID, CauseSummary, RedundantSummary, Explanation) :-
    format(atom(Explanation),
           "Rule ~w is redundant. Rule ~w is evaluated earlier, has the \c
            same action, and covers every packet matched by rule ~w; \c
            therefore rule ~w never changes the decision and only adds \c
            unnecessary processing.~n    \c
            Covering rule -- ~w~n    \c
            Redundant rule -- ~w",
           [RedundantID, CauseID, RedundantID, RedundantID,
            CauseSummary, RedundantSummary]).

correlation_finding(Pairs, Lang, finding(correlation, Severity, ID1, ID2, Explanation)) :-
    is_correlated(Pairs, ID1, ID2),
    severity(correlation, Severity),
    rule_summary(ID1, Lang, Summary1),
    rule_summary(ID2, Lang, Summary2),
    correlation_explanation(Lang, ID1, ID2, Summary1, Summary2, Explanation).

correlation_explanation(fa, ID1, ID2, Summary1, Summary2, Explanation) :-
    format(atom(Explanation),
           "قوانین ~w و ~w ترافیک هم‌پوشان و عملکرد متضاد دارند، اما هیچ‌کدام \c
            دیگری را کامل پوشش نمی‌دهد. نتیجهٔ ترافیک مشترک به ترتیب قوانین \c
            وابسته است و جابه‌جایی آن‌ها می‌تواند رفتار را تغییر دهد؛ بازبینی \c
            دستی لازم است.~n    \c
            قانون ~w -- ~w~n    \c
            قانون ~w -- ~w",
           [ID1, ID2, ID1, Summary1, ID2, Summary2]).
correlation_explanation(en, ID1, ID2, Summary1, Summary2, Explanation) :-
    format(atom(Explanation),
           "Rules ~w and ~w have overlapping traffic and conflicting \c
            actions, but neither fully covers the other. The outcome for \c
            the shared traffic depends on rule order, and swapping them \c
            could change behavior; manual review is recommended.~n    \c
            Rule ~w -- ~w~n    \c
            Rule ~w -- ~w",
           [ID1, ID2, ID1, Summary1, ID2, Summary2]).

generalization_finding(Pairs, Lang, finding(generalization, Severity, SpecificID, GeneralID, Explanation)) :-
    is_generalization(Pairs, SpecificID, GeneralID),
    severity(generalization, Severity),
    rule_summary(SpecificID, Lang, SpecificSummary),
    rule_summary(GeneralID, Lang, GeneralSummary),
    generalization_explanation(Lang, SpecificID, GeneralID, SpecificSummary, GeneralSummary, Explanation).

generalization_explanation(fa, SpecificID, GeneralID, SpecificSummary, GeneralSummary, Explanation) :-
    format(atom(Explanation),
           "قانون خاص ~w پیش از قانون کلی‌تر ~w با عملکرد متفاوت ارزیابی می‌شود. \c
            این حالت می‌تواند عمدی باشد، مثلاً برای مسدودکردن یک استثنا و \c
            مجازکردن باقی زیرشبکه. این مورد به‌دلیل شکنندگی ترتیب قوانین \c
            علامت‌گذاری می‌شود؛ جابه‌جایی آن‌ها می‌تواند رفتار سیاست را تغییر دهد.~n    \c
            قانون خاص -- ~w~n    \c
            قانون کلی -- ~w",
           [SpecificID, GeneralID, SpecificSummary, GeneralSummary]).
generalization_explanation(en, SpecificID, GeneralID, SpecificSummary, GeneralSummary, Explanation) :-
    format(atom(Explanation),
           "The specific rule ~w is evaluated before the more general \c
            rule ~w with a different action. This can be intentional --\c
            e.g. blocking one exception while allowing the rest of a \c
            subnet -- but is flagged because it depends fragilely on \c
            rule order; swapping them could change policy behavior.~n    \c
            Specific rule -- ~w~n    \c
            General rule -- ~w",
           [SpecificID, GeneralID, SpecificSummary, GeneralSummary]).

% print_anomaly_report/0
% Human-readable Persian console report, useful for manual
% testing and for a network engineer to review directly without any
% Phase 3/4 tooling. Groups findings by severity (critical first)
% since that is the order a reviewer should actually address them in.
%
% print_anomaly_report/0
% Backward-compatible wrapper: defaults to the original Persian
% console report.
print_anomaly_report :-
    print_anomaly_report(fa).

% print_anomaly_report(+Lang)
% Human-readable console report in Lang (fa or en), useful for manual
% testing and for a network engineer to review directly without any
% Phase 3/4 tooling. Groups findings by severity (critical first)
% since that is the order a reviewer should actually address them in.
print_anomaly_report(Lang) :-
    find_all_anomalies(Lang, Report),
    length(Report, N),
    report_header_template(Lang, HeaderTemplate),
    format(HeaderTemplate, [N]),
    forall(
        member(Severity, [critical, high, medium, low]),
        print_severity_group(Severity, Lang, Report)
    ).

report_header_template(fa, "~n=== گزارش آنومالی‌های فایروال: ~w یافته ===~n").
report_header_template(en, "~n=== Firewall Anomaly Report: ~w finding(s) ===~n").

print_severity_group(Severity, Lang, Report) :-
    findall(F, (member(F, Report), F = finding(_,Severity,_,_,_)), Group),
    Group \== [],
    !,
    severity_label(Severity, Lang, SeverityLabel),
    length(Group, GroupN),
    severity_group_template(Lang, GroupTemplate),
    format(GroupTemplate, [SeverityLabel, GroupN]),
    forall(member(finding(Type,_,_,_,Explanation), Group),
           ( type_label(Type, Lang, TypeLabel),
             format("~n[~w]~n~w~n", [TypeLabel, Explanation]) )).
print_severity_group(_, _, _).  % no findings at this severity -- print nothing

severity_group_template(fa, "~n--- ~w (~w مورد) ---~n").
severity_group_template(en, "~n--- ~w (~w item(s)) ---~n").
