% ============================================================================
% test_firewall_engine.pl
%
% Test suite for firewall_engine.pl (Phase 2, v3 -- the sweep-optimized,
% severity/explanation-enriched version).
%
% Run with:
%   swipl test_firewall_engine.pl
%
% This file is SELF-CONTAINED: it does not depend on an external
% sample_rules.pl. All fixture rules are defined right here, in
% sample_rules/0 below, deliberately designed so that EVERY rule
% participates in at least one anomaly of a known type -- this makes
% it easy to eyeball print_anomaly_report/0's output and check "does
% this match what I expected?" without cross-referencing a second file.
%
% Structure:
%   1. sample_rules/0       -- asserts a small, deliberately broken
%                               firewall policy (11 rules) into user:rule/8
%   2. plunit test blocks    -- automated pass/fail checks, one block per
%                               anomaly type, mirroring the hand-derived
%                               expectations documented next to each rule
%   3. main/0                -- runs the automated tests AND prints the
%                               full human-readable report, so you see
%                               both "did it work" (plunit) and "what
%                               does it look like to a network engineer"
%                               (print_anomaly_report/0) in one run.
% ============================================================================

:- use_module(library(plunit)).
:- use_module('ip_subnet.pl').
:- consult('firewall_engine.pl').

% ----------------------------------------------------------------------------
% 1. Fixture: a small, deliberately broken firewall policy
% ----------------------------------------------------------------------------
% Priorities are spaced by 10 (10, 20, 30, ...) so that later, if you
% want to insert a rule between two existing ones while experimenting,
% you don't have to renumber everything else -- same convention real
% firewall UIs use.
%
% Every rule below is annotated with WHY it's there. Rules 1-8 form two
% clean, unambiguous anomaly pairs each (shadowing, redundancy,
% correlation, generalization). Rules 9-11 are edge cases worth seeing
% the engine handle correctly. Rule 12 is a deliberately CLEAN rule
% with no anomaly at all, to confirm the engine doesn't over-report.

sample_rules :-
    retractall(user:rule(_,_,_,_,_,_,_,_)),

    % --- SHADOWING: rule 2 can never fire -----------------------------
    % Rule 1 (priority 10, evaluated first) already ALLOWs all of
    % 172.16.0.0/16 to 10.0.0.5/32:80/tcp. Rule 2 (priority 20, a
    % strict subset of rule 1's source range) tries to DENY a single
    % host within that same range -- but rule 1 already matched and
    % allowed it first, so rule 2's deny NEVER takes effect. This is
    % the textbook "the exception was placed in the wrong order" bug.
    assertz(user:rule(1, 10, allow, tcp, ip4(172,16,0,0,16), ip4(10,0,0,5,32), any, port(80))),
    assertz(user:rule(2, 20, deny,  tcp, ip4(172,16,1,10,32), ip4(10,0,0,5,32), any, port(80))),

    % --- REDUNDANCY: rule 4 is pointless -------------------------------
    % Rule 3 already ALLOWs all of 10.10.0.0/8 to 2.2.2.2/32 (udp, any
    % port). Rule 4 ALLOWs a narrower slice (10.10.10.0/24) of the SAME
    % traffic with the SAME action -- it never changes the outcome for
    % any packet, it's just dead weight in the config.
    assertz(user:rule(3, 30, allow, udp, ip4(10,10,0,0,8),  ip4(2,2,2,2,32), any, any)),
    assertz(user:rule(4, 40, allow, udp, ip4(10,10,10,0,24), ip4(2,2,2,2,32), any, any)),

    % --- CORRELATION: rules 5 and 6 silently depend on evaluation order
    % Both rules match the exact same IPs (192.168.0.0/24 -> 1.1.1.1/32,
    % tcp) but their PORT ranges only partially overlap (1-100 vs
    % 50-150) -- ports 50-100 are claimed by BOTH rules with opposite
    % actions (allow vs deny), and neither rule's selector fully
    % contains the other's. Note: CIDR blocks can never partially
    % overlap (they're always nested-or-disjoint), so a genuine partial
    % overlap like this has to come from ports or from mismatched
    % SrcIP/DstIP combinations -- ports are the simplest way to
    % demonstrate it here.
    assertz(user:rule(5, 50, allow, tcp, ip4(192,168,0,0,24), ip4(1,1,1,1,32), any, port_range(1,100))),
    assertz(user:rule(6, 60, deny,  tcp, ip4(192,168,0,0,24), ip4(1,1,1,1,32), any, port_range(50,150))),

    % --- GENERALIZATION: rule 7 (specific) precedes rule 8 (broad) ----
    % Rule 7 DENYs one host (192.168.5.9/32) first; rule 8 later ALLOWs
    % the whole /24 it lives in. This is very likely INTENTIONAL policy
    % ("block this one troublemaker, allow the rest of the subnet") --
    % not a bug -- but it's fragile: if someone reorders these two
    % rules later, the meaning silently flips.
    assertz(user:rule(7, 70, deny,  tcp, ip4(192,168,5,9,32), ip4(3,3,3,3,32), any, any)),
    assertz(user:rule(8, 80, allow, tcp, ip4(192,168,5,0,24), ip4(3,3,3,3,32), any, any)),

    % --- EDGE CASE: different protocols never anomalize (rules 9/10) --
    % Same IPs and ports, one broader than the other, CONFLICTING
    % actions -- this WOULD be a textbook shadowing pair, except rule 9
    % is udp and rule 10 is tcp. A single packet can never match both,
    % so no anomaly of any kind should be reported for this pair.
    assertz(user:rule(9,  90,  allow, udp, ip4(50,0,0,0,8), ip4(60,0,0,0,8), any, any)),
    assertz(user:rule(10, 100, deny,  tcp, ip4(50,0,0,5,32), ip4(60,0,0,5,32), any, any)),

    % --- EDGE CASE: same-priority tie (rules 11/12) --------------------
    % Rule 11 and rule 12 have the SAME priority (110). Evaluation
    % order between them is ambiguous/config-format-dependent, so the
    % engine must NOT report shadowing or generalization in either
    % direction for this pair (see earlier_rule/4 in firewall_engine.pl
    % -- it fails, on purpose, when priorities are equal).
    assertz(user:rule(11, 110, allow, tcp, ip4(172,20,0,0,16), ip4(4,4,4,4,32), any, any)),
    assertz(user:rule(12, 110, deny,  tcp, ip4(172,20,1,0,24), ip4(4,4,4,4,32), any, any)),

    % --- CLEAN RULE: rule 13, no anomaly with anything else -----------
    % Its IP ranges don't meaningfully overlap with any other rule's
    % (unique /8 zone), so it should not appear in any finding at all.
    % Useful as a check against over-reporting.
    assertz(user:rule(13, 130, allow, icmp, ip4(199,0,0,0,8), ip4(198,0,0,0,8), any, any)).

% ----------------------------------------------------------------------------
% 2. Automated tests
% ----------------------------------------------------------------------------

:- begin_tests(shadowing).

test(rule2_shadowed_by_rule1, [setup(sample_rules)]) :-
    once(is_shadowed(2, 1)).

test(wrong_direction_fails, [setup(sample_rules), fail]) :-
    is_shadowed(1, 2).

test(different_protocols_never_shadow, [setup(sample_rules), fail]) :-
    % rules 9/10 look like shadowing but are different protocols
    ( is_shadowed(9, 10) ; is_shadowed(10, 9) ).

test(same_priority_tie_never_shadows, [setup(sample_rules), fail]) :-
    ( is_shadowed(11, 12) ; is_shadowed(12, 11) ).

:- end_tests(shadowing).

% ----------------------------------------------------------------------------
:- begin_tests(redundancy).

test(rule4_redundant_to_rule3, [setup(sample_rules)]) :-
    once(is_redundant(4, 3)).

test(reverse_direction_fails, [setup(sample_rules), fail]) :-
    is_redundant(3, 4).

test(shadowing_pair_is_not_also_redundant, [setup(sample_rules), fail]) :-
    % rules 1/2 conflict in action -- redundancy requires the SAME
    % action, so this must not fire.
    is_redundant(2, 1).

:- end_tests(redundancy).

% ----------------------------------------------------------------------------
:- begin_tests(correlation).

test(rules_5_6_correlated, [setup(sample_rules)]) :-
    once(is_correlated(5, 6)).

test(only_reported_in_canonical_order, [setup(sample_rules)]) :-
    \+ is_correlated(6, 5).

test(shadowing_pair_is_not_correlation, [setup(sample_rules), fail]) :-
    % rule 2 is fully covered by rule 1 (shadowing) -- correlation
    % requires that NEITHER rule fully covers the other.
    is_correlated(1, 2).

:- end_tests(correlation).

% ----------------------------------------------------------------------------
:- begin_tests(generalization).

test(rule7_generalizes_into_rule8, [setup(sample_rules)]) :-
    once(is_generalization(7, 8)).

test(wrong_direction_fails, [setup(sample_rules), fail]) :-
    is_generalization(8, 7).

test(same_priority_tie_never_generalizes, [setup(sample_rules), fail]) :-
    ( is_generalization(11, 12) ; is_generalization(12, 11) ).

:- end_tests(generalization).

% ----------------------------------------------------------------------------
:- begin_tests(clean_rule_no_anomalies).

test(rule13_not_shadowed_either_direction, [setup(sample_rules)]) :-
    \+ is_shadowed(13, _), \+ is_shadowed(_, 13).

test(rule13_not_redundant_either_direction, [setup(sample_rules)]) :-
    \+ is_redundant(13, _), \+ is_redundant(_, 13).

test(rule13_not_correlated_either_direction, [setup(sample_rules)]) :-
    \+ is_correlated(13, _), \+ is_correlated(_, 13).

test(rule13_not_generalization_either_direction, [setup(sample_rules)]) :-
    \+ is_generalization(13, _), \+ is_generalization(_, 13).

:- end_tests(clean_rule_no_anomalies).

% ----------------------------------------------------------------------------
% Covers the /2 vs /3 shared-sweep design directly: does find_all_anomalies/1
% (which uses the /3 forms internally) agree with calling each /2 predicate
% independently? If the shared-Pairs plumbing had a bug, this is where it
% would show up -- e.g. a /3 clause using the wrong Pairs list.
:- begin_tests(shared_sweep_consistency).

test(find_all_anomalies_matches_individual_predicates, [setup(sample_rules)]) :-
    find_all_anomalies(Report),
    forall(member(finding(shadowing, _, Shadowing, Shadowed, _), Report),
           is_shadowed(Shadowed, Shadowing)),
    forall(member(finding(redundancy, _, Cause, Redundant, _), Report),
           is_redundant(Redundant, Cause)),
    forall(member(finding(correlation, _, ID1, ID2, _), Report),
           is_correlated(ID1, ID2)),
    forall(member(finding(generalization, _, Specific, General, _), Report),
           is_generalization(Specific, General)).

:- end_tests(shared_sweep_consistency).

% ----------------------------------------------------------------------------
:- begin_tests(report_generation).

test(report_contains_exactly_four_findings, [setup(sample_rules)]) :-
    find_all_anomalies(Report),
    length(Report, 4).

test(every_finding_is_well_formed, [setup(sample_rules)]) :-
    find_all_anomalies(Report),
    forall(member(F, Report),
           F = finding(Type, Severity, _, _, Explanation)),
    forall(member(finding(Type,Severity,_,_,_), Report),
           ( memberchk(Type, [shadowing, redundancy, correlation, generalization]),
             memberchk(Severity, [critical, high, medium, low]) )),
    forall(member(finding(_,_,_,_,Explanation), Report),
           ( atom(Explanation) ; string(Explanation) )).

test(shadowing_reported_as_critical, [setup(sample_rules)]) :-
    find_all_anomalies(Report),
    memberchk(finding(shadowing, critical, 1, 2, _), Report).

test(correlation_reported_as_high, [setup(sample_rules)]) :-
    find_all_anomalies(Report),
    memberchk(finding(correlation, high, 5, 6, _), Report).

test(generalization_reported_as_medium, [setup(sample_rules)]) :-
    find_all_anomalies(Report),
    memberchk(finding(generalization, medium, 7, 8, _), Report).

test(redundancy_reported_as_low, [setup(sample_rules)]) :-
    find_all_anomalies(Report),
    memberchk(finding(redundancy, low, 3, 4, _), Report).

:- end_tests(report_generation).

% ----------------------------------------------------------------------------
% 3. Large-scale fixture: many rules, mostly healthy, with a known,
%    controlled number of anomalies injected -- for seeing real
%    performance on something closer to a real firewall's rule count.
% ----------------------------------------------------------------------------
% Design: uniformly-random IPs across the full IPv4 space almost never
% overlap (we saw this earlier: with random /16-/32 blocks scattered
% across 2^32 addresses, the odds two of them share even one address
% are tiny). A rule set built that way would "look big" but never
% exercise the anomaly detectors at all -- every finding would come
% only from the small hand-written block, and find_all_anomalies would
% mostly be paying the cost of the DstIP sweep for nothing.
%
% So healthy_rule/1 below draws destinations from a moderate pool of
% zones (enough to occasionally collide by chance, like a real
% multi-team network sharing address space, but mostly distinct) --
% and separately, inject_anomaly_block/1 below adds a KNOWN, COUNTABLE
% number of genuine anomalies on top, reusing the same four patterns
% from sample_rules/0 above but stamped out programmatically. This
% way the test can assert exact expected counts even at large N,
% instead of "however many the RNG happened to produce."

:- dynamic next_rule_id/1.

reset_id_counter :- retractall(next_rule_id(_)), assertz(next_rule_id(1)).

fresh_id(ID) :-
    retract(next_rule_id(ID)),
    Next is ID + 1,
    assertz(next_rule_id(Next)).

random_octet(O) :- O is random(256).

% Healthy rule: destination zone drawn from a pool of 40 possible /8s,
% source is fully random, port is a random single port or 'any'. With
% 40 zones and a few thousand rules, SOME incidental overlap happens
% (like a real config), but the overwhelming majority of rules share
% no traffic with any other rule -- i.e. genuinely healthy.
healthy_rule(ID) :-
    fresh_id(ID),
    Zone is random(40) + 60,             % zones 60-99, kept away from
                                          % the 1-13 hand-written block's
                                          % addresses and the anomaly
                                          % block's zones below
    random_octet(B), random_octet(C), random_octet(D),
    DstPrefix is 16 + random(17),
    random_octet(SA), random_octet(SB), random_octet(SC), random_octet(SD),
    SrcPrefix is 8 + random(25),
    ( random(2) =:= 0 -> Action = allow ; Action = deny ),
    R is random(4),
    ( R =:= 0 -> Proto = tcp ; R =:= 1 -> Proto = udp
    ; R =:= 2 -> Proto = icmp ; Proto = any ),
    ( random(2) =:= 0 -> DPort = any ; ( P is random(65536), DPort = port(P) ) ),
    assertz(user:rule(ID, ID, Action, Proto,
                       ip4(SA,SB,SC,SD,SrcPrefix),
                       ip4(Zone,B,C,D,DstPrefix),
                       any, DPort)).

gen_healthy(0) :- !.
gen_healthy(N) :- N > 0, healthy_rule(_), N1 is N - 1, gen_healthy(N1).

% One programmatic copy of each of the four anomaly patterns from
% sample_rules/0, using a private /8 zone (Zone) so it doesn't
% accidentally collide with the healthy pool (zones 60-99) or the
% hand-written block (zones used in sample_rules/0 above). Returns
% the four rule ID pairs so the test can assert on them by name
% instead of by guessing IDs.
inject_anomaly_block(Zone, shadow(SDId,SGId)-redund(RId,CId)-corr(C1,C2)-gen(GSId,GGId)) :-
    % shadowing
    fresh_id(SGId),
    assertz(user:rule(SGId, SGId, allow, tcp, ip4(Zone,0,0,0,16), ip4(9,9,9,9,32), any, port(80))),
    fresh_id(SDId),
    assertz(user:rule(SDId, SDId, deny,  tcp, ip4(Zone,0,1,10,32), ip4(9,9,9,9,32), any, port(80))),
    % redundancy
    fresh_id(CId),
    assertz(user:rule(CId, CId, allow, udp, ip4(Zone,10,0,0,8), ip4(8,8,4,4,32), any, any)),
    fresh_id(RId),
    assertz(user:rule(RId, RId, allow, udp, ip4(Zone,10,10,0,24), ip4(8,8,4,4,32), any, any)),
    % correlation (partial port overlap, same IPs)
    fresh_id(C1),
    assertz(user:rule(C1, C1, allow, tcp, ip4(Zone,20,0,0,24), ip4(7,7,7,7,32), any, port_range(1,100))),
    fresh_id(C2),
    assertz(user:rule(C2, C2, deny,  tcp, ip4(Zone,20,0,0,24), ip4(7,7,7,7,32), any, port_range(50,150))),
    % generalization
    fresh_id(GSId),
    assertz(user:rule(GSId, GSId, deny,  tcp, ip4(Zone,30,5,9,32), ip4(6,6,6,6,32), any, any)),
    fresh_id(GGId),
    assertz(user:rule(GGId, GGId, allow, tcp, ip4(Zone,30,5,0,24), ip4(6,6,6,6,32), any, any)).

% large_scale_rules(+NumHealthy, +NumAnomalyBlocks, -AnomalyIDs)
% Builds a rule set of roughly NumHealthy + 8*NumAnomalyBlocks rules:
% NumHealthy healthy rules, plus NumAnomalyBlocks copies of the four-
% anomaly pattern above (each copy in its own /8 zone so the blocks
% don't interfere with each other), for a KNOWN total of exactly
% NumAnomalyBlocks findings of each of the four types.
large_scale_rules(NumHealthy, NumAnomalyBlocks, AnomalyIDs) :-
    NumAnomalyBlocks =< 100,  % zones 150-249 leaves 100 usable /8s
    retractall(user:rule(_,_,_,_,_,_,_,_)),
    reset_id_counter,
    gen_healthy(NumHealthy),
    AnomalyZoneStart = 150,  % zones 150-249, away from healthy (60-99)
                             % and hand-written (sample_rules/0) ranges
    findall(Ids,
            ( between(1, NumAnomalyBlocks, I),
              Zone is AnomalyZoneStart + I,
              inject_anomaly_block(Zone, Ids)
            ),
            AnomalyIDs).

% ----------------------------------------------------------------------------
% 4. Large-scale test: correctness AND timing at realistic rule counts
% ----------------------------------------------------------------------------
:- begin_tests(large_scale).

test(finding_count_matches_injected_anomalies_exactly) :-
    NumHealthy = 3000,
    NumAnomalyBlocks = 50,   % -> exactly 50 shadowing + 50 redundancy
                              %    + 50 correlation + 50 generalization
                              %    = 200 findings, no more, no less
    large_scale_rules(NumHealthy, NumAnomalyBlocks, _),
    find_all_anomalies(Report),
    length(Report, Total),
    format("~n    [large_scale] ~w healthy + ~w anomaly-blocks (~w rules total) -> ~w findings (expected ~w)~n",
           [NumHealthy, NumAnomalyBlocks, NumHealthy + NumAnomalyBlocks*8, Total, NumAnomalyBlocks*4]),
    Total =:= NumAnomalyBlocks * 4.

test(every_injected_shadow_pair_is_actually_found) :-
    large_scale_rules(500, 10, AnomalyIDs),
    forall(member(shadow(SDId,SGId)-_-_-_, AnomalyIDs),
           is_shadowed(SDId, SGId)).

test(every_injected_redundancy_pair_is_actually_found) :-
    large_scale_rules(500, 10, AnomalyIDs),
    forall(member(_-redund(RId,CId)-_-_, AnomalyIDs),
           is_redundant(RId, CId)).

test(every_injected_correlation_pair_is_actually_found) :-
    large_scale_rules(500, 10, AnomalyIDs),
    forall(member(_-_-corr(C1,C2)-_, AnomalyIDs),
           is_correlated(C1, C2)).

test(every_injected_generalization_pair_is_actually_found) :-
    large_scale_rules(500, 10, AnomalyIDs),
    forall(member(_-_-_-gen(GSId,GGId), AnomalyIDs),
           is_generalization(GSId, GGId)).

:- end_tests(large_scale).

% ----------------------------------------------------------------------------
% 5. Timing benchmark: prints wall-clock time for find_all_anomalies/1
%    at several rule-set sizes, so you can see the speed directly.
% ----------------------------------------------------------------------------
% NOTE ON FINDING COUNTS BELOW: the "expected" count is
% NumAnomalyBlocks * 4 (one of each type per injected block). At larger
% healthy-rule counts you may occasionally see ONE OR TWO extra findings
% beyond that. This is NOT a bug: with thousands of independently-random
% "healthy" rules, a small number of them will, purely by chance, end up
% with genuinely overlapping IPs and conflicting actions -- a real
% coincidental correlation, exactly like two unrelated rules in a real
% multi-team firewall config occasionally colliding by accident. This
% was verified directly (is_correlated/2 called standalone agreed with
% find_all_anomalies/1 in every case checked) -- it is the engine
% correctly finding a real, if rare, accidental overlap, not a false
% positive from the sweep optimization.
run_timing_benchmark :-
    set_random(seed(42)),  % fixed seed -- same numbers every run, for reproducibility
    format("~n~`=t~60|~n"),
    format("TIMING: find_all_anomalies/1 at increasing rule-set sizes~n"),
    format("~`=t~60|~n"),
    format("~w~t~15|~w~t~30|~w~t~45|~w~n",
           ['Healthy rules', 'Anomaly blocks', 'Total rules', 'Time (s)']),
    format("~`-t~60|~n"),
    forall(
        member(NumHealthy-NumBlocks, [500-5, 2000-15, 5000-30, 10000-50, 20000-75, 49900-100]),
        ( large_scale_rules(NumHealthy, NumBlocks, _),
          TotalRules is NumHealthy + NumBlocks * 8,
          get_time(T0),
          find_all_anomalies(Report),
          get_time(T1),
          length(Report, Count),
          Elapsed is T1 - T0,
          format("~w~t~15|~w~t~30|~w~t~45|~2f  (~w findings)~n",
                 [NumHealthy, NumBlocks, TotalRules, Elapsed, Count])
        )
    ),
    format("~`=t~60|~n").

% ----------------------------------------------------------------------------
% 6. Entry point: run automated tests, print the human-readable report
%    on the small hand-written fixture, then run the timing benchmark.
% ----------------------------------------------------------------------------
main :-
    format("~n############################################################~n"),
    format("# PART 1: Automated tests (plunit)~n"),
    format("############################################################~n"),
    run_tests,

    format("~n############################################################~n"),
    format("# PART 2: Human-readable report (print_anomaly_report/0)~n"),
    format("# -- this is what a network engineer reviewing the config~n"),
    format("#    would actually see. (small, hand-written fixture)~n"),
    format("############################################################~n"),
    sample_rules,
    print_anomaly_report,

    format("~n############################################################~n"),
    format("# PART 3: Performance at scale~n"),
    format("############################################################~n"),
    run_timing_benchmark,

    halt.

:- initialization(main, main).