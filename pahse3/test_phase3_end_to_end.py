"""
test_phase3_end_to_end.py
===========================
FULL-PIPELINE test suite for Phase 3: parser.py -> bridge.py -> the
live SWI-Prolog engine (firewall_engine.pl / ip_subnet.pl) -> Finding
objects. Unlike test_parser_and_bridge_pure.py, every test here
actually calls bridge.run_engine() and therefore actually starts
(or shells out to) a real SWI-Prolog process.

REQUIREMENTS TO RUN THIS FILE:
  - SWI-Prolog installed and on PATH (the `swipl` command must work --
    this is what makes the subprocess backend testable at all).
  - Ideally also `pip install pyswip`, so the pyswip backend itself
    gets exercised, not only the subprocess fallback. If pyswip is not
    installed, every test still runs (bridge.run_engine() will
    silently use the subprocess backend for all of them), but you will
    not have actually verified the pyswip code path this session
    rewrote. See test_backend_availability() below -- it reports which
    backend actually ran, every time, specifically so this is visible
    in the test output rather than silently assumed.

WHY THIS COULD NOT BE RUN OR VERIFIED IN THE environment THAT WROTE IT:
This file was produced in a sandboxed environment with no network
access and no local swipl binary (both `apt-get install swi-prolog`
and `pip install pyswip` failed for lack of network access -- this is
an environment limitation, not a design choice). Every test below has
been written as carefully as possible against firewall_engine.pl's and
ip_subnet.pl's documented behavior and the pyswip API docs, but NONE OF
THEM HAVE ACTUALLY BEEN RUN AGAINST A LIVE ENGINE. Run this file
yourself and treat its output as the real verification -- if anything
here fails, that is genuinely useful signal, not a formality.

Run with:
    python3 -m unittest test_phase3_end_to_end -v
or:
    python3 test_phase3_end_to_end.py
"""

import json
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from parser import parse
import bridge


def _swipl_available() -> bool:
    return shutil.which("swipl") is not None


@unittest.skipUnless(_swipl_available(), "swipl not found on PATH -- install SWI-Prolog to run this suite")
class TestBackendAvailability(unittest.TestCase):
    """Not a correctness test -- just reports, loudly, which backend is
    actually serving these tests, so a silent all-subprocess run (pyswip
    not installed) doesn't get mistaken for "the pyswip rewrite was
    verified"."""

    def test_report_active_backend(self):
        rules, _ = parse("-A FORWARD -p tcp --dport 80 -j ACCEPT")
        findings, error = bridge.run_engine(rules)
        self.assertIsNone(error, f"engine error on the simplest possible input: {error}")
        used = bridge.backend_name()
        print(f"\n[test] backend actually used this run: {used!r} "
              f"(pyswip importable at module load: {bridge._PYSWIP_IMPORTABLE})")
        if used != "pyswip":
            print("[test] WARNING: pyswip was NOT used for this run -- install pyswip "
                  "(`pip install pyswip`) and re-run this file to actually exercise "
                  "the rewritten pyswip backend, not just the subprocess fallback.")


@unittest.skipUnless(_swipl_available(), "swipl not found on PATH -- install SWI-Prolog to run this suite")
class TestEngineSmoke(unittest.TestCase):
    """Minimal sanity checks before trusting any anomaly-specific result."""

    def test_empty_ruleset_no_engine_call_no_error(self):
        findings, error = bridge.run_engine([])
        self.assertEqual(findings, [])
        self.assertIsNone(error)


class TestParserSafety(unittest.TestCase):
    """Parser behavior that prevents false security findings."""

    def test_iptables_chain_is_retained(self):
        rules, errors = parse("-A INPUT -p tcp --dport 22 -j ACCEPT")
        self.assertEqual(errors, [])
        self.assertEqual(rules[0].chain, "INPUT")

    def test_unsupported_nonterminal_target_is_rejected(self):
        rules, errors = parse("-A FORWARD -p tcp --dport 443 -j LOG")
        self.assertEqual(rules, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("unsupported target 'LOG'", errors[0].reason)


@unittest.skipUnless(_swipl_available(), "swipl not found on PATH -- install SWI-Prolog to run this suite")
class TestChainIsolationAndCliOutput(unittest.TestCase):

    def test_different_chains_do_not_create_false_shadowing(self):
        rules, errors = parse("\n".join([
            "-A INPUT -s 10.50.0.0/16 -d 192.0.2.10 -p tcp --dport 443 -j ACCEPT",
            "-A FORWARD -s 10.50.1.10 -d 192.0.2.10 -p tcp --dport 443 -j DROP",
        ]))
        self.assertEqual(errors, [])
        findings, error = bridge.run_engine(rules)
        self.assertIsNone(error)
        self.assertEqual(findings, [])

    def test_cli_json_is_utf8_and_explanations_are_persian(self):
        config = "\n".join([
            "*filter",
            ":FORWARD DROP [0:0]",
            "-A FORWARD -s 10.1.0.0/16 -d 172.31.10.10 -p tcp --dport 443 -j ACCEPT",
            "-A FORWARD -s 10.1.4.0/24 -d 172.31.10.10 -p tcp --dport 443 -j DROP",
            "COMMIT",
        ])
        with tempfile.NamedTemporaryFile("w", suffix=".rules", encoding="utf-8", delete=False) as f:
            f.write(config)
            config_path = f.name
        try:
            result = subprocess.run(
                [sys.executable, "main.py", config_path, "--format", "json"],
                capture_output=True,
                encoding="utf-8",
                env={**os.environ, "PYTHONIOENCODING": "cp1252"},
                check=False,
            )
        finally:
            os.unlink(config_path)

        self.assertEqual(result.returncode, 0, result.stderr)
        finding = json.loads(result.stdout)["findings"][0]
        self.assertTrue(finding["explanation"].startswith("زنجیره FORWARD:"))
        self.assertIn("قانون 2 هرگز اجرا نمی‌شود", finding["explanation"])


@unittest.skipUnless(_swipl_available(), "swipl not found on PATH -- install SWI-Prolog to run this suite")
class TestPhase4WebReport(unittest.TestCase):

    def test_web_report_renders_persian_finding_and_recommendation(self):
        import webapp

        config = "\n".join([
            "*filter",
            ":FORWARD DROP [0:0]",
            "-A FORWARD -s 10.1.0.0/16 -d 172.31.10.10 -p tcp --dport 443 -j ACCEPT",
            "-A FORWARD -s 10.1.4.0/24 -d 172.31.10.10 -p tcp --dport 443 -j DROP",
            "COMMIT",
        ])
        client = webapp.app.test_client()
        response = client.post(
            "/analyze",
            data={"config": (io.BytesIO(config.encode("utf-8")), "policy.rules"), "strict": "on"},
            content_type="multipart/form-data",
        )
        page = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("گزارش ممیزی", page)
        self.assertIn("قانون 2 هرگز اجرا نمی‌شود", page)
        self.assertIn("پیشنهاد:", page)

    def test_strict_web_report_blocks_unsupported_rule(self):
        import webapp

        config = "-A FORWARD -p tcp --dport 443 -j LOG\n-A FORWARD -p tcp --dport 443 -j ACCEPT"
        client = webapp.app.test_client()
        response = client.post(
            "/analyze",
            data={"config": (io.BytesIO(config.encode("utf-8")), "partial.rules"), "strict": "on"},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 422)
        self.assertIn("تحلیل در حالت دقیق متوقف شد", response.get_data(as_text=True))

    def test_single_rule_no_anomalies(self):
        rules, perrors = parse("-A FORWARD -p tcp --dport 80 -j ACCEPT")
        self.assertEqual(perrors, [])
        findings, error = bridge.run_engine(rules)
        self.assertIsNone(error)
        self.assertEqual(findings, [], "a single rule can never be shadowed/redundant/"
                                        "correlated/generalized with anything")

    def test_two_unrelated_rules_no_anomalies(self):
        # Disjoint destination subnets, disjoint ports -- nothing should
        # fire across any of the four detectors.
        text = "\n".join([
            "-A FORWARD -s 10.0.0.1 -d 10.1.0.0/24 -p tcp --dport 80 -j ACCEPT",
            "-A FORWARD -s 10.0.0.2 -d 10.2.0.0/24 -p udp --dport 53 -j ACCEPT",
        ])
        rules, perrors = parse(text)
        self.assertEqual(perrors, [])
        findings, error = bridge.run_engine(rules)
        self.assertIsNone(error)
        self.assertEqual(findings, [])


@unittest.skipUnless(_swipl_available(), "swipl not found on PATH -- install SWI-Prolog to run this suite")
class TestShadowingDetection(unittest.TestCase):
    """rule 2 can never fire: rule 1 (evaluated first, lower priority)
    already matches everything rule 2 matches, with a conflicting action."""

    def test_classic_shadowing_is_detected(self):
        text = "\n".join([
            "-A FORWARD -s 172.16.0.0/16 -d 10.0.0.5 -p tcp --dport 80 -j ACCEPT",  # id 1
            "-A FORWARD -s 172.16.1.10   -d 10.0.0.5 -p tcp --dport 80 -j DROP",     # id 2, shadowed
        ])
        rules, perrors = parse(text)
        self.assertEqual(perrors, [])
        findings, error = bridge.run_engine(rules)
        self.assertIsNone(error)

        shadowing = [f for f in findings if f.type == "shadowing"]
        self.assertEqual(len(shadowing), 1, f"expected exactly 1 shadowing finding, got: {findings}")
        f = shadowing[0]
        self.assertEqual(f.severity, "critical")
        # ShadowingID (primary) = rule 1 (the broader, earlier rule);
        # ShadowedID (secondary) = rule 2 (the dead rule) -- see
        # shadowing_finding/3 in firewall_engine.pl.
        self.assertEqual(f.primary_id, 1)
        self.assertEqual(f.secondary_id, 2)

    def test_same_action_is_not_shadowing(self):
        # Same coverage relationship as above, but SAME action -- this
        # must NOT be shadowing (it's redundancy instead, if anything).
        text = "\n".join([
            "-A FORWARD -s 172.16.0.0/16 -d 10.0.0.5 -p tcp --dport 80 -j ACCEPT",
            "-A FORWARD -s 172.16.1.10   -d 10.0.0.5 -p tcp --dport 80 -j ACCEPT",
        ])
        rules, _ = parse(text)
        findings, error = bridge.run_engine(rules)
        self.assertIsNone(error)
        self.assertEqual([f for f in findings if f.type == "shadowing"], [])

    def test_reversed_order_is_generalization_not_shadowing(self):
        # Same two rules, but the SPECIFIC one now comes first -- this
        # is Generalization (fragile-but-often-intentional), not
        # Shadowing (broken). Order must matter for the classification.
        text = "\n".join([
            "-A FORWARD -s 172.16.1.10   -d 10.0.0.5 -p tcp --dport 80 -j DROP",     # specific, first
            "-A FORWARD -s 172.16.0.0/16 -d 10.0.0.5 -p tcp --dport 80 -j ACCEPT",   # general, second
        ])
        rules, _ = parse(text)
        findings, error = bridge.run_engine(rules)
        self.assertIsNone(error)
        self.assertEqual([f for f in findings if f.type == "shadowing"], [])
        generalization = [f for f in findings if f.type == "generalization"]
        self.assertEqual(len(generalization), 1)

    def test_different_protocol_never_shadows(self):
        # Identical IP/port coverage, but tcp vs udp -- these can never
        # match the same packet, so no anomaly of any kind should fire.
        text = "\n".join([
            "-A FORWARD -s 172.16.0.0/16 -d 10.0.0.5 -p tcp --dport 80 -j ACCEPT",
            "-A FORWARD -s 172.16.1.10   -d 10.0.0.5 -p udp --dport 80 -j DROP",
        ])
        rules, _ = parse(text)
        findings, error = bridge.run_engine(rules)
        self.assertIsNone(error)
        self.assertEqual(findings, [])


@unittest.skipUnless(_swipl_available(), "swipl not found on PATH -- install SWI-Prolog to run this suite")
class TestRedundancyDetection(unittest.TestCase):

    def test_classic_redundancy_is_detected(self):
        text = "\n".join([
            "-A FORWARD -s 192.168.0.0/16 -d 10.1.0.0/16 -p tcp --dport 443 -j ACCEPT",  # id 1
            "-A FORWARD -s 192.168.0.0/16 -d 10.1.5.0/24 -p tcp --dport 443 -j ACCEPT",  # id 2, redundant
        ])
        rules, perrors = parse(text)
        self.assertEqual(perrors, [])
        findings, error = bridge.run_engine(rules)
        self.assertIsNone(error)

        redundancy = [f for f in findings if f.type == "redundancy"]
        self.assertEqual(len(redundancy), 1, f"expected exactly 1 redundancy finding, got: {findings}")
        f = redundancy[0]
        self.assertEqual(f.severity, "low")
        self.assertEqual(f.primary_id, 1)    # CauseID
        self.assertEqual(f.secondary_id, 2)  # RedundantID

    def test_identical_rule_twice_is_redundant(self):
        text = "\n".join([
            "-A FORWARD -s 10.0.0.0/24 -d 10.1.0.0/24 -p tcp --dport 22 -j ACCEPT",
            "-A FORWARD -s 10.0.0.0/24 -d 10.1.0.0/24 -p tcp --dport 22 -j ACCEPT",
        ])
        rules, _ = parse(text)
        findings, error = bridge.run_engine(rules)
        self.assertIsNone(error)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "redundancy")


@unittest.skipUnless(_swipl_available(), "swipl not found on PATH -- install SWI-Prolog to run this suite")
class TestCorrelationDetection(unittest.TestCase):

    def test_partial_overlap_conflicting_actions_is_correlation(self):
        # Two CIDR blocks are, mathematically, either fully disjoint or
        # one is a strict subset of the other -- a single dimension can
        # never be a "partial overlap" on its own. Genuine partial
        # overlap at the RULE level comes from combining two dimensions
        # asymmetrically: rule 1's source is broader than rule 2's, but
        # rule 2's destination is broader than rule 1's. Neither rule
        # then covers the other (covers/2 requires EVERY dimension to
        # be broader-or-equal), while both dimensions individually
        # still overlap (since a subset relationship is itself a form
        # of overlap) -- exactly is_correlated_pair/2's definition in
        # firewall_engine.pl.
        text = "\n".join([
            "-A FORWARD -s 10.0.0.0/24   -d 10.1.0.128/25 -p tcp --dport 80 -j ACCEPT",  # broader src, narrower dst
            "-A FORWARD -s 10.0.0.128/25 -d 10.1.0.0/24    -p tcp --dport 80 -j DROP",   # narrower src, broader dst
        ])
        rules, perrors = parse(text)
        self.assertEqual(perrors, [])
        findings, error = bridge.run_engine(rules)
        self.assertIsNone(error)

        correlation = [f for f in findings if f.type == "correlation"]
        self.assertEqual(len(correlation), 1, f"expected exactly 1 correlation finding, got: {findings}")
        f = correlation[0]
        self.assertEqual(f.severity, "high")
        self.assertEqual({f.primary_id, f.secondary_id}, {1, 2})

    def test_full_containment_is_not_correlation(self):
        # Full containment with conflicting action is Shadowing/
        # Generalization, NOT Correlation -- covers/2 in either
        # direction must exclude it from is_correlated/2.
        text = "\n".join([
            "-A FORWARD -s 172.16.0.0/16 -d 10.0.0.5 -p tcp --dport 80 -j ACCEPT",
            "-A FORWARD -s 172.16.1.10   -d 10.0.0.5 -p tcp --dport 80 -j DROP",
        ])
        rules, _ = parse(text)
        findings, error = bridge.run_engine(rules)
        self.assertIsNone(error)
        self.assertEqual([f for f in findings if f.type == "correlation"], [])


@unittest.skipUnless(_swipl_available(), "swipl not found on PATH -- install SWI-Prolog to run this suite")
class TestGeneralizationDetection(unittest.TestCase):

    def test_specific_then_general_different_action_is_generalization(self):
        text = "\n".join([
            "-A FORWARD -s 10.0.0.5 -d 10.1.0.0/16 -p tcp --dport 80 -j DROP",          # specific, id 1
            "-A FORWARD -s 10.0.0.0/24 -d 10.1.0.0/16 -p tcp --dport 80 -j ACCEPT",     # general, id 2
        ])
        rules, perrors = parse(text)
        self.assertEqual(perrors, [])
        findings, error = bridge.run_engine(rules)
        self.assertIsNone(error)

        generalization = [f for f in findings if f.type == "generalization"]
        self.assertEqual(len(generalization), 1, f"expected exactly 1 generalization finding, got: {findings}")
        f = generalization[0]
        self.assertEqual(f.severity, "medium")
        self.assertEqual(f.primary_id, 1)    # SpecificID
        self.assertEqual(f.secondary_id, 2)  # GeneralID

    def test_specific_then_general_same_action_is_neither(self):
        text = "\n".join([
            "-A FORWARD -s 10.0.0.5 -d 10.1.0.0/16 -p tcp --dport 80 -j ACCEPT",
            "-A FORWARD -s 10.0.0.0/24 -d 10.1.0.0/16 -p tcp --dport 80 -j ACCEPT",
        ])
        rules, _ = parse(text)
        findings, error = bridge.run_engine(rules)
        self.assertIsNone(error)
        self.assertEqual([f for f in findings if f.type == "generalization"], [])

    def test_identical_conflicting_rules_are_not_generalization(self):
        # Equal traffic scopes are Shadowing in first-match firewalls, not
        # Generalization.  Generalization requires the later rule to be
        # strictly broader.
        text = "\n".join([
            "-A FORWARD -s 10.0.0.0/24 -d 10.1.0.0/24 -p tcp --dport 443 -j ACCEPT",
            "-A FORWARD -s 10.0.0.0/24 -d 10.1.0.0/24 -p tcp --dport 443 -j DROP",
        ])
        rules, errors = parse(text)
        self.assertEqual(errors, [])
        findings, error = bridge.run_engine(rules)
        self.assertIsNone(error)
        self.assertEqual(
            [(f.type, f.primary_id, f.secondary_id) for f in findings],
            [("shadowing", 1, 2)],
        )


@unittest.skipUnless(_swipl_available(), "swipl not found on PATH -- install SWI-Prolog to run this suite")
class TestFullDemoConfig(unittest.TestCase):
    """Runs main.py's own DEMO_CONFIG end to end and checks it produces
    exactly the anomalies its inline comments claim it does -- this is
    the same config `python3 main.py --demo` runs, so a human eyeballing
    that output and this test should always agree."""

    def test_demo_config_produces_expected_anomaly_counts(self):
        import main
        rules, perrors = parse(main.DEMO_CONFIG)
        self.assertEqual(perrors, [], f"demo config should have zero unparseable lines, got: {perrors}")
        self.assertEqual(len(rules), 6, "demo config should parse to exactly 6 rules")

        findings, error = bridge.run_engine(rules)
        self.assertIsNone(error)

        by_type = {}
        for f in findings:
            by_type.setdefault(f.type, []).append(f)

        # Per the DEMO_CONFIG comments in main.py:
        #   [2] SHADOWED by [1]
        #   [4] REDUNDANT because of [3]
        # No comment claims a correlation or generalization anomaly, so
        # those should be empty for this particular config.
        self.assertEqual(len(by_type.get("shadowing", [])), 1,
                          f"expected 1 shadowing finding (rule 2 shadowed by rule 1), got: {findings}")
        self.assertEqual(len(by_type.get("redundancy", [])), 1,
                          f"expected 1 redundancy finding (rule 4 redundant vs rule 3), got: {findings}")

        shadow = by_type["shadowing"][0]
        self.assertEqual((shadow.primary_id, shadow.secondary_id), (1, 2))

        redund = by_type["redundancy"][0]
        self.assertEqual((redund.primary_id, redund.secondary_id), (3, 4))

    def test_demo_config_findings_sorted_by_severity(self):
        import main
        rules, _ = parse(main.DEMO_CONFIG)
        findings, error = bridge.run_engine(rules)
        self.assertIsNone(error)
        ranks = [f.severity_rank() for f in findings]
        self.assertEqual(ranks, sorted(ranks), "run_engine() must return findings sorted by severity")


@unittest.skipUnless(_swipl_available(), "swipl not found on PATH -- install SWI-Prolog to run this suite")
class TestIPv6AndMixedFamily(unittest.TestCase):
    """Confirms ip_subnet.pl's same_family/2 guard actually holds
    end-to-end: an IPv4 rule and an IPv6 rule must never be reported as
    anomalous with each other, no matter how their integer ranges
    happen to overlap."""

    def test_ipv6_shadowing_detected_within_family(self):
        text = """
table ip6 filter {
    chain FORWARD {
        ip6 saddr 2001:db8::/32 ip6 daddr 2001:db8:1::1 tcp dport 80 accept
        ip6 saddr 2001:db8::1   ip6 daddr 2001:db8:1::1 tcp dport 80 drop
    }
}
"""
        rules, perrors = parse(text)
        self.assertEqual(perrors, [])
        findings, error = bridge.run_engine(rules)
        self.assertIsNone(error)
        shadowing = [f for f in findings if f.type == "shadowing"]
        self.assertEqual(len(shadowing), 1, f"expected IPv6-vs-IPv6 shadowing to be detected, got: {findings}")

    def test_ipv4_and_ipv6_never_cross_react(self):
        # Deliberately constructed so the two rules' DstIP integer
        # ranges could plausibly collide in the sweep-line pre-filter
        # (see firewall_engine.pl's "NOTE ON MIXED IPv4/IPv6 CONFIGS"),
        # but same_family/2 must reject the pair before any finding is
        # produced.
        text = "\n".join([
            "-A FORWARD -s 10.0.0.0/8 -d 10.0.0.5 -p tcp --dport 80 -j ACCEPT",
        ])
        rules_v4, _ = parse(text)
        rules_v6, _ = parse("""
table ip6 filter {
    chain FORWARD {
        ip6 saddr ::/0 ip6 daddr ::1 tcp dport 80 drop
    }
}
""")
        # Merge manually with distinct ids/priorities, since parse()
        # only handles one format per call.
        combined = rules_v4 + [
            r for r in rules_v6
        ]
        for i, r in enumerate(combined, start=1):
            r.id = i
            r.priority = i * 10

        findings, error = bridge.run_engine(combined)
        self.assertIsNone(error)
        self.assertEqual(findings, [], "an IPv4 rule and an IPv6 rule must never be "
                                        "reported as anomalous with each other")


if __name__ == "__main__":
    unittest.main(verbosity=2)
