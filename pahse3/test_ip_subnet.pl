% ============================================================================
% test_ip_subnet.pl
%
% Test suite for ip_subnet.pl (Phase 1, IPv4+IPv6+wildcard version).
%
% Run with:
%   swipl test_ip_subnet.pl
%
% If ANY test fails, fix it before starting Phase 2 -- the anomaly
% detectors we write next have no way to be more correct than the
% subset logic they're built on.
% ============================================================================

:- use_module(library(plunit)).
:- consult('ip_subnet.pl').

% ----------------------------------------------------------------------------
:- begin_tests(valid_ip_term).

test(valid_ip4) :- valid_ip_term(ip4(192,168,1,1,24)).
test(invalid_ip4_octet_fails, [fail]) :- valid_ip_term(ip4(300,1,1,1,24)).
test(invalid_ip4_prefix_fails, [fail]) :- valid_ip_term(ip4(1,1,1,1,33)).
test(valid_ip6) :- valid_ip_term(ip6(0x2001,0xdb8,0,0,0,0,0,1,128)).
test(invalid_ip6_hextet_fails, [fail]) :- valid_ip_term(ip6(0x10000,0,0,0,0,0,0,0,64)).
test(invalid_ip6_prefix_fails, [fail]) :- valid_ip_term(ip6(0,0,0,0,0,0,0,0,129)).

:- end_tests(valid_ip_term).

% ----------------------------------------------------------------------------
:- begin_tests(ip_to_int_v4).

test(basic_conversion) :-
    ip_to_int(ip4(192,168,1,1,32), N), N =:= 3232235777.

test(zero_address) :-
    ip_to_int(ip4(0,0,0,0,0), N), N =:= 0.

test(broadcast_address) :-
    ip_to_int(ip4(255,255,255,255,32), N), N =:= 4294967295.

test(bad_term_raises_error) :-
    catch(
        ( ip_to_int(ip4(999,0,0,0,32), _), fail ),
        error(_,_),
        true
    ).

:- end_tests(ip_to_int_v4).

% ----------------------------------------------------------------------------
:- begin_tests(ip_to_int_v6).

test(loopback) :-
    % ::1
    ip_to_int(ip6(0,0,0,0,0,0,0,1,128), N), N =:= 1.

test(documentation_prefix_matches_python_ground_truth) :-
    % 2001:db8::1 -- cross-checked independently against Python's
    % ipaddress module: int(ip_address('2001:db8::1')) == this value.
    ip_to_int(ip6(0x2001,0x0db8,0,0,0,0,0,1,128), N),
    N =:= 42540766411282592856903984951653826561.

test(all_ff_is_max_128bit) :-
    ip_to_int(ip6(0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,128), N),
    N =:= (1 << 128) - 1.

:- end_tests(ip_to_int_v6).

% ----------------------------------------------------------------------------
:- begin_tests(ip_range_v4).

test(slash_24) :-
    ip_range(ip4(192,168,1,0,24), Start, End),
    ip_to_int(ip4(192,168,1,0,32), Start),
    ip_to_int(ip4(192,168,1,255,32), End).

test(slash_32_is_single_host) :-
    ip_range(ip4(10,0,0,5,32), Start, End),
    Start =:= End,
    ip_to_int(ip4(10,0,0,5,32), Start).

test(slash_0_is_everything) :-
    ip_range(ip4(0,0,0,0,0), Start, End),
    Start =:= 0, End =:= 4294967295.

test(slash_31_point_to_point_link) :-
    % /31 is a real-world convention for point-to-point links: only
    % two usable addresses, no traditional network/broadcast split.
    ip_range(ip4(10,0,0,0,31), Start, End),
    Start =:= 167772160,   % 10.0.0.0
    End =:= 167772161.     % 10.0.0.1

test(non_aligned_base_still_masks_correctly) :-
    ip_range(ip4(192,168,1,77,24), Start, End),
    ip_to_int(ip4(192,168,1,0,32), Start),
    ip_to_int(ip4(192,168,1,255,32), End).

:- end_tests(ip_range_v4).

% ----------------------------------------------------------------------------
:- begin_tests(ip_range_v6).

test(slash_64_common_lan_prefix) :-
    % /64 is the standard LAN prefix size in IPv6.
    ip_range(ip6(0x2001,0xdb8,0,0,0,0,0,0,64), Start, End),
    ip_to_int(ip6(0x2001,0xdb8,0,0,0,0,0,0,128), Start),
    ip_to_int(ip6(0x2001,0xdb8,0,0,0xFFFF,0xFFFF,0xFFFF,0xFFFF,128), End).

test(slash_128_is_single_host) :-
    ip_range(ip6(0,0,0,0,0,0,0,1,128), Start, End),
    Start =:= End, Start =:= 1.

test(slash_0_is_everything_v6) :-
    ip_range(ip6(0,0,0,0,0,0,0,0,0), Start, End),
    Start =:= 0,
    End =:= (1 << 128) - 1.

test(slash_127_point_to_point) :-
    % IPv6 equivalent of the IPv4 /31 convention.
    ip_range(ip6(0,0,0,0,0,0,0,0,127), Start, End),
    Start =:= 0, End =:= 1.

:- end_tests(ip_range_v6).

% ----------------------------------------------------------------------------
:- begin_tests(is_subset_ip_v4).

test(host_inside_slash24) :-
    is_subset_ip(ip4(192,168,1,5,32), ip4(192,168,1,0,24)).

test(host_outside_slash24_fails, [fail]) :-
    is_subset_ip(ip4(192,168,2,5,32), ip4(192,168,1,0,24)).

test(slash24_inside_slash16) :-
    is_subset_ip(ip4(172,16,5,0,24), ip4(172,16,0,0,16)).

test(bigger_not_inside_smaller_fails, [fail]) :-
    is_subset_ip(ip4(172,16,0,0,16), ip4(172,16,5,0,24)).

test(identical_blocks_are_subsets) :-
    is_subset_ip(ip4(10,0,0,0,24), ip4(10,0,0,0,24)).

test(everything_is_subset_of_slash0) :-
    is_subset_ip(ip4(8,8,8,8,32), ip4(0,0,0,0,0)).

test(slash0_not_subset_of_smaller_fails, [fail]) :-
    is_subset_ip(ip4(0,0,0,0,0), ip4(8,8,8,8,32)).

test(adjacent_disjoint_blocks_fail, [fail]) :-
    is_subset_ip(ip4(192,168,2,0,24), ip4(192,168,1,0,24)).

test(partial_overlap_is_not_subset_either_direction) :-
    \+ is_subset_ip(ip4(10,0,0,128,25), ip4(10,0,1,0,24)),
    \+ is_subset_ip(ip4(10,0,1,0,24), ip4(10,0,0,128,25)).

:- end_tests(is_subset_ip_v4).

% ----------------------------------------------------------------------------
:- begin_tests(is_subset_ip_v6).

test(host_inside_slash64) :-
    is_subset_ip(ip6(0x2001,0xdb8,0,0,0,0,0,1,128),
                 ip6(0x2001,0xdb8,0,0,0,0,0,0,64)).

test(host_outside_slash64_fails, [fail]) :-
    is_subset_ip(ip6(0x2001,0xdb8,0,1,0,0,0,1,128),
                 ip6(0x2001,0xdb8,0,0,0,0,0,0,64)).

test(slash64_inside_slash32) :-
    is_subset_ip(ip6(0x2001,0xdb8,5,0,0,0,0,0,64),
                 ip6(0x2001,0xdb8,0,0,0,0,0,0,32)).

test(identical_v6_blocks_are_subsets) :-
    is_subset_ip(ip6(0xfe80,0,0,0,0,0,0,0,10), ip6(0xfe80,0,0,0,0,0,0,0,10)).

:- end_tests(is_subset_ip_v6).

% ----------------------------------------------------------------------------
:- begin_tests(mixed_family_rejection).

test(v4_not_subset_of_v6_fails, [fail]) :-
    is_subset_ip(ip4(10,0,0,1,32), ip6(0,0,0,0,0,0,0,0,0)).

test(v6_not_subset_of_v4_fails, [fail]) :-
    is_subset_ip(ip6(0,0,0,0,0,0,0,1,128), ip4(0,0,0,0,0)).

test(v4_v6_never_overlap_fails, [fail]) :-
    ip_overlaps(ip4(0,0,0,0,0), ip6(0,0,0,0,0,0,0,0,0)).

:- end_tests(mixed_family_rejection).

% ----------------------------------------------------------------------------
:- begin_tests(ip_overlaps).

test(subset_blocks_overlap) :-
    ip_overlaps(ip4(192,168,1,5,32), ip4(192,168,1,0,24)).

test(disjoint_blocks_do_not_overlap_fails, [fail]) :-
    ip_overlaps(ip4(192,168,1,0,24), ip4(192,168,2,0,24)).

test(genuinely_partial_overlap) :-
    ip_overlaps(ip4(10,0,0,0,23), ip4(10,0,1,0,24)).

test(symmetry) :-
    ip_overlaps(ip4(10,0,0,0,24), ip4(10,0,0,128,25)),
    ip_overlaps(ip4(10,0,0,128,25), ip4(10,0,0,0,24)).

:- end_tests(ip_overlaps).

% ----------------------------------------------------------------------------
:- begin_tests(wildcard_conversion).

test(slash24_wildcard) :-
    wildcard_to_prefix(wc(0,0,0,255), P), P =:= 24.

test(prefix24_wildcard) :-
    wildcard_to_prefix(W, 24), W == wc(0,0,0,255).

test(slash32_wildcard_is_all_zero) :-
    wildcard_to_prefix(wc(0,0,0,0), P), P =:= 32.

test(slash0_wildcard_is_all_ones) :-
    wildcard_to_prefix(wc(255,255,255,255), P), P =:= 0.

test(slash16_wildcard) :-
    wildcard_to_prefix(wc(0,0,255,255), P), P =:= 16.
test(prefix16_wildcard) :-
    wildcard_to_prefix(W, 16), W == wc(0,0,255,255).

test(roundtrip_all_prefixes) :-
    % Every prefix length 0-32 should round-trip cleanly through
    % prefix -> wildcard -> prefix.
    forall(
        between(0,32,P0),
        ( wildcard_to_prefix(W, P0),
          wildcard_to_prefix(W, P1),
          P1 =:= P0 )
    ).

test(discontiguous_wildcard_rejected, [fail]) :-
    % 0.0.0.85 = binary 01010101 -- not a valid contiguous mask,
    % this is the kind of advanced/unsupported Cisco ACL trick this
    % project explicitly does not attempt to model.
    wildcard_to_prefix(wc(0,0,0,85), _).

:- end_tests(wildcard_conversion).

% ----------------------------------------------------------------------------
:- begin_tests(is_subset_port).

test(anything_subset_of_any) :-
    is_subset_port(port(80), any),
    is_subset_port(port_range(1,1024), any),
    is_subset_port(any, any).

test(any_not_subset_of_specific_port_fails, [fail]) :-
    is_subset_port(any, port(80)).

test(port_in_range) :-
    is_subset_port(port(80), port_range(1,1024)).

test(port_outside_range_fails, [fail]) :-
    is_subset_port(port(8080), port_range(1,1024)).

test(same_port_is_subset) :-
    is_subset_port(port(443), port(443)).

test(different_single_ports_fail, [fail]) :-
    is_subset_port(port(443), port(80)).

test(range_inside_range) :-
    is_subset_port(port_range(100,200), port_range(1,1024)).

test(range_partially_outside_fails, [fail]) :-
    is_subset_port(port_range(1000,2000), port_range(1,1024)).

test(degenerate_range_matches_single_port) :-
    is_subset_port(port_range(80,80), port(80)).

test(nondegenerate_range_not_subset_of_single_port_fails, [fail]) :-
    is_subset_port(port_range(80,90), port(80)).

:- end_tests(is_subset_port).

:- initialization(main, main).

main :-
    run_tests.
