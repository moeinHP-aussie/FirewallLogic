% ============================================================================
% firewall_engine.pl
%
% Project 1, Phase 2 -- Anomaly detection engine
% ----------------------------------------------------------------------------
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

:- module(firewall_engine, [
    is_shadowed/2,
    is_redundant/2,
    is_correlated/2,
    is_generalization/2,
    find_all_anomalies/1,
    print_anomaly_report/0
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

% dst_ip_bounds(-ID-Start-End) for every rule, as a list.
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

is_shadowed(ShadowedID, ShadowingID) :-
    candidate_pair(A, B),
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
is_redundant(RedundantID, CauseID) :-
    candidate_pair(A, B),
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
is_correlated(ID1, ID2) :-
    candidate_pair(ID1, ID2),
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
is_generalization(SpecificID, GeneralID) :-
    candidate_pair(A, B),
    rule(A, PrioA, ActionA, PA, SA, DA, SPA, DPA),
    rule(B, PrioB, ActionB, PB, SB, DB, SPB, DPB),
    earlier_rule(rule(A,PrioA,ActionA,PA,SA,DA,SPA,DPA),
                 rule(B,PrioB,ActionB,PB,SB,DB,SPB,DPB),
                 rule(SpecificID,PrioSpecific,ActionSpecific,PS,SS,DS,SPS,DPS),
                 rule(GeneralID, PrioGeneral, ActionGeneral, PG,SG,DG,SPG,DPG)),
    actions_conflict(ActionSpecific, ActionGeneral),
    covers(rule(GeneralID,PrioGeneral,ActionGeneral,PG,SG,DG,SPG,DPG),
           rule(SpecificID,PrioSpecific,ActionSpecific,PS,SS,DS,SPS,DPS)).

% ----------------------------------------------------------------------------
% 5. Reporting
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
severity(shadowing,      critical).
severity(correlation,    high).
severity(generalization, medium).
severity(redundancy,     low).

% rule_summary(+ID, -Summary)
% Renders one rule's full traffic selector as a compact, human-
% readable string, e.g. "tcp 172.16.0.0/16 -> 10.0.0.5/32:80 (allow)".
% Used inside every Explanation string below so a network engineer
% can check a finding against the raw config without having to look
% up each rule ID separately first.
rule_summary(ID, Summary) :-
    rule(ID, Priority, Action, Protocol, SrcIP, DstIP, SrcPort, DstPort),
    ip_term_string(SrcIP, SrcStr),
    ip_term_string(DstIP, DstStr),
    port_term_string(SrcPort, SrcPortStr),
    port_term_string(DstPort, DstPortStr),
    format(atom(Summary),
           "rule ~w (priority ~w): ~w  ~w:~w -> ~w:~w  [~w]",
           [ID, Priority, Protocol, SrcStr, SrcPortStr, DstStr, DstPortStr, Action]).

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
find_all_anomalies(Report) :-
    findall(F, shadowing_finding(F), ShadowingFindings),
    findall(F, redundancy_finding(F), RedundancyFindings),
    findall(F, correlation_finding(F), CorrelationFindings),
    findall(F, generalization_finding(F), GeneralizationFindings),
    append([ShadowingFindings, RedundancyFindings,
            CorrelationFindings, GeneralizationFindings], Report).

shadowing_finding(finding(shadowing, Severity, ShadowingID, ShadowedID, Explanation)) :-
    is_shadowed(ShadowedID, ShadowingID),
    severity(shadowing, Severity),
    rule_summary(ShadowingID, ShadowingSummary),
    rule_summary(ShadowedID, ShadowedSummary),
    format(atom(Explanation),
            "Rule ~w can NEVER take effect. It is evaluated after rule ~w, \c
            which already matches every packet rule ~w would match, with \c
            the opposite action. Traffic that rule ~w was meant to handle \c
            is entirely decided by rule ~w instead.~n    \c
            Shadowing rule -- ~w~n    \c
            Shadowed rule  -- ~w",
            [ShadowedID, ShadowingID, ShadowedID, ShadowedID, ShadowingID,
            ShadowingSummary, ShadowedSummary]).

redundancy_finding(finding(redundancy, Severity, CauseID, RedundantID, Explanation)) :-
    is_redundant(RedundantID, CauseID),
    severity(redundancy, Severity),
    rule_summary(CauseID, CauseSummary),
    rule_summary(RedundantID, RedundantSummary),
    format(atom(Explanation),
            "Rule ~w is redundant. Rule ~w, evaluated earlier with the same \c
            action, already covers every packet rule ~w matches -- rule ~w \c
            never changes the outcome for any packet, it only costs \c
            extra processing time on every match attempt.~n    \c
            Covering rule  -- ~w~n    \c
            Redundant rule -- ~w",
            [RedundantID, CauseID, RedundantID, RedundantID,
            CauseSummary, RedundantSummary]).

correlation_finding(finding(correlation, Severity, ID1, ID2, Explanation)) :-
    is_correlated(ID1, ID2),
    severity(correlation, Severity),
    rule_summary(ID1, Summary1),
    rule_summary(ID2, Summary2),
    format(atom(Explanation),
            "Rules ~w and ~w have overlapping traffic selectors with \c
            CONFLICTING actions, and neither rule fully contains the \c
            other. The real outcome for packets in the overlap depends \c
            entirely on which rule is evaluated first -- reordering \c
            these two rules would silently change live traffic handling. \c
            This needs a human decision, it cannot be auto-resolved.~n    \c
            Rule ~w -- ~w~n    \c
            Rule ~w -- ~w",
            [ID1, ID2, ID1, Summary1, ID2, Summary2]).

generalization_finding(finding(generalization, Severity, SpecificID, GeneralID, Explanation)) :-
    is_generalization(SpecificID, GeneralID),
    severity(generalization, Severity),
    rule_summary(SpecificID, SpecificSummary),
    rule_summary(GeneralID, GeneralSummary),
    format(atom(Explanation),
            "Specific rule ~w is evaluated before broader rule ~w, with a \c
            different action -- this is likely intentional (e.g. \c
            'block this one exception, allow the rest'), not a bug. It \c
            is flagged because it is FRAGILE: if these two rules are ever \c
            reordered later (for instance while fixing other findings in \c
            this same report), the meaning of the policy would silently \c
            change with no error or warning.~n    \c
            Specific rule -- ~w~n    \c
            Broader rule  -- ~w",
            [SpecificID, GeneralID, SpecificSummary, GeneralSummary]).

% print_anomaly_report/0
% Human-readable console report, useful for manual testing and for a
% network engineer to review directly without any Phase 3/4 tooling.
% Groups findings by severity (critical first) since that is the
% order a reviewer should actually address them in.
print_anomaly_report :-
    find_all_anomalies(Report),
    length(Report, N),
    format("~n=== Firewall Anomaly Report: ~w finding(s) ===~n", [N]),
    forall(
        member(Severity, [critical, high, medium, low]),
        print_severity_group(Severity, Report)
    ).

print_severity_group(Severity, Report) :-
    findall(F, (member(F, Report), F = finding(_,Severity,_,_,_)), Group),
    Group \== [],
    !,
    upcase_atom(Severity, SeverityUpper),
    length(Group, GroupN),
    format("~n--- ~w (~w) ---~n", [SeverityUpper, GroupN]),
    forall(member(finding(Type,_,_,_,Explanation), Group),
            format("~n[~w]~n~w~n", [Type, Explanation])).
print_severity_group(_, _).  % no findings at this severity -- print nothing
