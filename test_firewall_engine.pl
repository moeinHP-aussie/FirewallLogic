% ============================================================================
% test_firewall_engine.pl
%
% Test suite for firewall_engine.pl (Phase 2).
%
% Run with:
%   swipl test_firewall_engine.pl
%
% Loads sample_rules.pl as fixture data, then checks the engine's
% output against hand-derived expected results (see the comments in
% sample_rules.pl for the reasoning behind each expected anomaly).
% Also covers negative cases and the two subtler design points in the
% schema: protocol-mismatch never anomalies, and Priority (not ID)
% governs evaluation order.
% ============================================================================

:- use_module(library(plunit)).
:- consult('firewall_engine.pl').
:- consult('sample_rules.pl').

% ----------------------------------------------------------------------------
:- begin_tests(shadowing).

test(rule2_shadowed_by_rule1) :- is_shadowed(2, 1).
test(rule6_shadowed_by_rule5) :- is_shadowed(6, 5).

test(wrong_direction_fails, [fail]) :- is_shadowed(1, 2).

test(shadowing_requires_earlier_priority, [fail]) :-
    % Rule 10 (priority 100) comes AFTER rule 9 (priority 90) and is
    % broader with a conflicting action -- but "broader rule placed
    % AFTER" is Generalization, not Shadowing. Rule 9 must not be
    % reported as shadowed by rule 10.
    is_shadowed(9, 10).

:- end_tests(shadowing).

% ----------------------------------------------------------------------------
:- begin_tests(redundancy).

test(rule4_redundant_to_rule3) :- is_redundant(4, 3).
test(reverse_direction_fails, [fail]) :- is_redundant(3, 4).

test(shadowing_pair_is_not_also_redundant, [fail]) :-
    % Rules 1/2 conflict in action (allow vs deny) -- redundancy
    % requires the SAME action, so this must not fire.
    is_redundant(2, 1).

:- end_tests(redundancy).

% ----------------------------------------------------------------------------
:- begin_tests(correlation).

test(rules_7_8_correlated) :- is_correlated(7, 8).

test(only_reported_in_canonical_order) :-
    % is_correlated/2 enforces ID1 < ID2, so (8,7) must fail even
    % though the relationship is symmetric -- callers should treat it
    % as one unordered fact, not query both directions.
    \+ is_correlated(8, 7).

test(shadowing_pair_is_not_correlation, [fail]) :-
    % Rule 6 is fully covered by rule 5 (Shadowing) -- correlation
    % requires that NEITHER rule fully covers the other, so this
    % must not also be reported as correlation.
    is_correlated(5, 6).

:- end_tests(correlation).

% ----------------------------------------------------------------------------
:- begin_tests(generalization).

test(rule9_generalizes_into_rule10) :- is_generalization(9, 10).
test(wrong_direction_fails, [fail]) :- is_generalization(10, 9).

:- end_tests(generalization).

% ----------------------------------------------------------------------------
:- begin_tests(clean_rule_no_anomalies).

test(rule11_not_shadowed_either_direction) :-
    \+ is_shadowed(11, _), \+ is_shadowed(_, 11).

test(rule11_not_redundant_either_direction) :-
    \+ is_redundant(11, _), \+ is_redundant(_, 11).

test(rule11_not_correlated_either_direction) :-
    \+ is_correlated(11, _), \+ is_correlated(_, 11).

test(rule11_not_generalization_either_direction) :-
    \+ is_generalization(11, _), \+ is_generalization(_, 11).

:- end_tests(clean_rule_no_anomalies).

% ----------------------------------------------------------------------------
% NOTE ON assertz(user:rule(...)): every plunit test block is its own
% private module (e.g. plunit_protocol_and_priority_semantics). An
% UNQUALIFIED assertz(rule(...)) inside a test body asserts into THAT
% module's own private rule/8, not into user:rule/8 -- even though
% firewall_engine.pl declares rule/8 dynamic+multifile for user. The
% multifile declaration only permits clauses from multiple SOURCE
% FILES to contribute to the same predicate; it does not change where
% an unqualified assert at runtime lands. is_shadowed/2 and friends
% look up user:rule/8, so if a test's setup asserts into its own
% private module instead, the engine will correctly, silently find
% ZERO matching facts -- not an error, just a wrong (empty) answer,
% which is a much easier bug to miss. Every assertz/retractall of
% rule/8 in this file is therefore explicitly qualified as user:rule(...).
%
% NOTE: plunit runs `cleanup` after EVERY individual test in a block,
% not once after the whole block -- so a single setup/cleanup pair
% shared across multiple tests only leaves fixture facts in place for
% the FIRST test; every test after that runs against an already-empty
% fixture. Each test below is therefore self-contained: it asserts
% exactly the facts it needs and retracts exactly those facts,
% independent of the others.
:- begin_tests(protocol_and_priority_semantics).

test(different_concrete_protocols_never_shadow,
     [ setup(( assertz(user:rule(100, 10, allow, tcp, ip4(10,0,0,0,24), ip4(20,0,0,0,24), any, any)),
               assertz(user:rule(101, 20, deny,  udp, ip4(10,0,0,5,32), ip4(20,0,0,5,32), any, any)) )),
       cleanup(( retractall(user:rule(100,_,_,_,_,_,_,_)),
                 retractall(user:rule(101,_,_,_,_,_,_,_)) )),
       fail
     ]) :-
    is_shadowed(101, 100).

test(priority_governs_order_not_id,
     [ setup(( assertz(user:rule(200, 5,  allow, tcp, ip4(30,0,0,0,24), ip4(40,0,0,0,24), any, any)),
               assertz(user:rule(50,  99, deny,  tcp, ip4(30,0,0,5,32), ip4(40,0,0,5,32), any, any)) )),
       cleanup(( retractall(user:rule(200,_,_,_,_,_,_,_)),
                 retractall(user:rule(50,_,_,_,_,_,_,_)) ))
     ]) :-
    % Rule 50 has the LOWER id but the HIGHER priority number (99 vs
    % 5), so rule 200 is actually evaluated first and shadows rule 50
    % -- despite rule 50's id being numerically smaller.
    is_shadowed(50, 200).

test(id_order_alone_would_have_given_wrong_answer,
     [ setup(( assertz(user:rule(200, 5,  allow, tcp, ip4(30,0,0,0,24), ip4(40,0,0,0,24), any, any)),
               assertz(user:rule(50,  99, deny,  tcp, ip4(30,0,0,5,32), ip4(40,0,0,5,32), any, any)) )),
       cleanup(( retractall(user:rule(200,_,_,_,_,_,_,_)),
                 retractall(user:rule(50,_,_,_,_,_,_,_)) )),
       fail
     ]) :-
    % Confirms we are NOT accidentally using ID as a proxy for
    % evaluation order: if we were, this (id-ascending) direction
    % would incorrectly succeed.
    is_shadowed(200, 50).

:- end_tests(protocol_and_priority_semantics).

% ----------------------------------------------------------------------------
:- begin_tests(report_generation).

test(report_contains_exactly_five_findings_on_sample_rules) :-
    find_all_anomalies(Report),
    length(Report, 5).

test(every_finding_is_a_well_formed_anomaly_term) :-
    find_all_anomalies(Report),
    forall(member(A, Report), A = anomaly(Type, _Details)),
    forall(member(anomaly(Type,_), Report),
           memberchk(Type, [shadowing, redundancy, correlation, generalization])).

:- end_tests(report_generation).

:- initialization(main, main).

main :-
    run_tests.
