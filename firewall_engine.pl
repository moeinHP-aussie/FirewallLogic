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
% 3. Anomaly detectors
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
is_shadowed(ShadowedID, ShadowingID) :-
    rule(ShadowingID, PrioShadowing, ActionShadowing, _, _, _, _, _),
    rule(ShadowedID,  PrioShadowed,  ActionShadowed,  _, _, _, _, _),
    ShadowingID \== ShadowedID,
    PrioShadowing < PrioShadowed,
    actions_conflict(ActionShadowing, ActionShadowed),
    rule(ShadowingID, PrioShadowing, ActionShadowing, PA, SA, DA, SPA, DPA),
    rule(ShadowedID,  PrioShadowed,  ActionShadowed,  PB, SB, DB, SPB, DPB),
    covers(rule(ShadowingID,PrioShadowing,ActionShadowing,PA,SA,DA,SPA,DPA),
           rule(ShadowedID, PrioShadowed, ActionShadowed, PB,SB,DB,SPB,DPB)).

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
    rule(CauseID,     PrioCause,     Action, _, _, _, _, _),
    rule(RedundantID, PrioRedundant, Action, _, _, _, _, _),
    CauseID \== RedundantID,
    PrioCause < PrioRedundant,
    rule(CauseID,     PrioCause,     Action, PA, SA, DA, SPA, DPA),
    rule(RedundantID, PrioRedundant, Action, PB, SB, DB, SPB, DPB),
    covers(rule(CauseID,PrioCause,Action,PA,SA,DA,SPA,DPA),
           rule(RedundantID,PrioRedundant,Action,PB,SB,DB,SPB,DPB)).

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
is_correlated(ID1, ID2) :-
    rule(ID1, _, Action1, _, _, _, _, _),
    rule(ID2, _, Action2, _, _, _, _, _),
    ID1 < ID2,
    actions_conflict(Action1, Action2),
    rule(ID1, _, Action1, P1, S1, D1, SP1, DP1),
    rule(ID2, _, Action2, P2, S2, D2, SP2, DP2),
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
    rule(SpecificID, PrioSpecific, ActionSpecific, _, _, _, _, _),
    rule(GeneralID,  PrioGeneral,  ActionGeneral,  _, _, _, _, _),
    SpecificID \== GeneralID,
    PrioSpecific < PrioGeneral,
    actions_conflict(ActionSpecific, ActionGeneral),
    rule(SpecificID, PrioSpecific, ActionSpecific, PA, SA, DA, SPA, DPA),
    rule(GeneralID,  PrioGeneral,  ActionGeneral,  PB, SB, DB, SPB, DPB),
    covers(rule(GeneralID,PrioGeneral,ActionGeneral,PB,SB,DB,SPB,DPB),
           rule(SpecificID,PrioSpecific,ActionSpecific,PA,SA,DA,SPA,DPA)).

% ----------------------------------------------------------------------------
% 4. Reporting
% ----------------------------------------------------------------------------

% find_all_anomalies(-Report)
% Collects every anomaly found across all four categories into one
% list of anomaly(Type, Details) terms, so Phase 4's report generator
% has a single, uniform structure to render instead of calling four
% separate predicates and merging results itself.
find_all_anomalies(Report) :-
    findall(anomaly(shadowing, shadowed(Shadowed)-shadowing(Shadowing)),
            is_shadowed(Shadowed, Shadowing),
            ShadowingAnomalies),
    findall(anomaly(redundancy, redundant(Redundant)-cause(Cause)),
            is_redundant(Redundant, Cause),
            RedundancyAnomalies),
    findall(anomaly(correlation, rule(ID1)-rule(ID2)),
            is_correlated(ID1, ID2),
            CorrelationAnomalies),
    findall(anomaly(generalization, specific(Specific)-general(General)),
            is_generalization(Specific, General),
            GeneralizationAnomalies),
    append([ShadowingAnomalies, RedundancyAnomalies,
            CorrelationAnomalies, GeneralizationAnomalies], Report).

% print_anomaly_report/0
% Human-readable console report, useful for manual testing during
% Phase 2 development. Phase 4 will replace/extend this with a proper
% HTML/JSON report generator; this is intentionally simple.
print_anomaly_report :-
    find_all_anomalies(Report),
    length(Report, N),
    format("~n=== Firewall Anomaly Report: ~w finding(s) ===~n~n", [N]),
    forall(member(A, Report), print_one_anomaly(A)).

print_one_anomaly(anomaly(shadowing, shadowed(S)-shadowing(G))) :-
    format("[SHADOWING]      Rule ~w is shadowed by rule ~w (rule ~w can never fire)~n", [S, G, S]).

print_one_anomaly(anomaly(redundancy, redundant(R)-cause(C))) :-
    format("[REDUNDANCY]     Rule ~w is redundant, fully covered by rule ~w (same action)~n", [R, C]).

print_one_anomaly(anomaly(correlation, rule(A)-rule(B))) :-
    format("[CORRELATION]    Rules ~w and ~w overlap with conflicting actions -- order-dependent!~n", [A, B]).

print_one_anomaly(anomaly(generalization, specific(S)-general(G))) :-
    format("[GENERALIZATION] Specific rule ~w precedes broader rule ~w with a different action -- fragile if reordered~n", [S, G]).