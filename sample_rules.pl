% ============================================================================
% sample_rules.pl
%
% A small, hand-designed firewall rule set used to manually test and
% demonstrate firewall_engine.pl during Phase 2 development. Every
% anomaly in here was placed on purpose, and the comment above each
% rule states exactly what it's meant to trigger, so we can verify the
% engine's output against a human-verified expectation instead of
% trusting the engine to grade its own homework.
%
% rule(ID, Priority, Action, Protocol, SrcIP, DstIP, SrcPort, DstPort).
% ============================================================================

:- dynamic rule/8.
:- discontiguous rule/8.

% --- Shadowing example -------------------------------------------------
% Rule 1 (priority 10, evaluated first) ALLOWs all of 172.16.0.0/16 to
% reach 10.0.0.5 on port 80. Rule 2 (priority 20) tries to DENY a
% single host inside that same /16 on the same port -- but rule 1 has
% already matched every such packet with the opposite action, so rule
% 2 can never fire. Expect: is_shadowed(2, 1).
rule(1, 10, allow, tcp, ip4(172,16,0,0,16),  ip4(10,0,0,5,32), any, port(80)).
rule(2, 20, deny,  tcp, ip4(172,16,1,10,32), ip4(10,0,0,5,32), any, port(80)).

% --- Redundancy example -------------------------------------------------
% Rule 3 (priority 30) ALLOWs all of 10.1.0.0/16 on any port. Rule 4
% (priority 40) ALLOWs a narrower /24 inside that same range, same
% action, same protocol -- rule 4 changes nothing, it's dead weight.
% Expect: is_redundant(4, 3).
rule(3, 30, allow, tcp, ip4(192,168,0,0,16), ip4(10,1,0,0,16), any, any).
rule(4, 40, allow, tcp, ip4(192,168,0,0,16), ip4(10,1,5,0,24), any, any).

% --- Correlation / Conflict example -------------------------------------
% Rule 5 (priority 50) ALLOWs 10.2.0.0/23 (covers 10.2.0.0-10.2.1.255)
% on port 443. Rule 6 (priority 60) DENYs 10.2.1.0/24 (covers
% 10.2.1.0-10.2.1.255) on port 443. These two ranges genuinely overlap
% (10.2.1.0/24 is entirely inside 10.2.0.0/23) -- wait, that actually
% makes rule 6 a SUBSET of rule 5, which is Shadowing, not Correlation!
% To get real Correlation we need two rules where NEITHER contains the
% other. Fixed below: rule 5 covers 10.2.0.0/24, rule 6 covers
% 10.2.0.128/25 -- no wait, that's also a subset relationship.
% Real Correlation needs source AND destination to each partially
% overlap without full containment in either. See rules 5/6 below.
rule(5, 50, allow, tcp, ip4(10,3,0,0,24),  ip4(10,2,0,0,23), any, port(443)).
rule(6, 60, deny,  tcp, ip4(10,3,0,128,25), ip4(10,2,1,0,24), any, port(443)).
% Rule 5's source is 10.3.0.0/24 (.0-.255), rule 6's source is
% 10.3.0.128/25 (.128-.255) -- rule 6's source IS a subset of rule 5's.
% Rule 5's dest is 10.2.0.0/23 (10.2.0.0-10.2.1.255), rule 6's dest is
% 10.2.1.0/24 (10.2.1.0-10.2.1.255) -- also a subset relationship.
% Since BOTH dimensions have rule 6 fully inside rule 5, covers(5,6)
% is actually true, making this Shadowing (5 shadows 6), not
% Correlation. Kept as a worked comment on purpose: getting "genuine
% partial overlap" right requires checking EVERY dimension, and it is
% easy to accidentally construct a full-containment case while aiming
% for a partial one. The real Correlation fixture is rules 7/8 below.

% Rule 7 source range: 10.4.0.0 - 10.4.0.127 (/25)
% Rule 8 source range: 10.4.0.64 - 10.4.0.127 (0.64/26, i.e. contained in 7's)
% To force genuine partial overlap we vary DESTINATION instead, so
% that neither rule's full (src,dst) selector contains the other's:
%   Rule 7: src 10.4.0.0/25  (.0-.127),  dst 10.5.0.0/24   (.0-.255)
%   Rule 8: src 10.4.0.0/24  (.0-.255),  dst 10.5.0.128/25 (.128-.255)
% Source: rule 7's src (.0-.127) IS a subset of rule 8's src (.0-.255).
% Dest:   rule 8's dst (.128-.255) IS a subset of rule 7's dst (.0-.255).
% So each rule is broader than the other in exactly one dimension and
% narrower in the other -- neither's full (src AND dst) selector
% contains the other's, but their traffic still overlaps (the
% intersection: src .0-.127, dst .128-.255 is real traffic both
% rules match). This is genuine Correlation.
% Expect: is_correlated(7, 8).
rule(7, 70, allow, tcp, ip4(10,4,0,0,25), ip4(10,5,0,0,24),   any, port(22)).
rule(8, 80, deny,  tcp, ip4(10,4,0,0,24), ip4(10,5,0,128,25), any, port(22)).

% --- Generalization example ----------------------------------------------
% Rule 9 (priority 90, evaluated FIRST) DENYs one specific bad host.
% Rule 10 (priority 100) ALLOWs the whole /24 that host lives in. This
% is a normal, probably-intentional "block the exception, then allow
% the rest" pattern -- not a bug, but flagged as fragile since
% reordering rules 9 and 10 later would silently let the bad host in.
% Expect: is_generalization(9, 10).
rule(9,  90,  deny,  tcp, ip4(0,0,0,0,0), ip4(10,6,0,99,32), any, any).
rule(10, 100, allow, tcp, ip4(0,0,0,0,0), ip4(10,6,0,0,24),  any, any).

% --- Clean rule, no anomaly ----------------------------------------------
% Rule 11 shares nothing in common with any other rule here (disjoint
% destination, unrelated to everything above) -- included so the
% engine has at least one rule that should show up in ZERO anomaly
% findings, proving the detectors don't over-fire on unrelated rules.
rule(11, 110, allow, udp, ip4(0,0,0,0,0), ip4(203,0,113,0,24), any, port_range(1,1024)).
