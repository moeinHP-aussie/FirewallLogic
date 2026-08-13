"""
incremental.py — "Check new rules against the existing firewall" mode
=========================================================================
Answers a narrower, faster question than a full audit: "we already
trust our current ruleset (base_config) -- if we add these proposed
new rules (new_rules_config), do THEY create any anomaly, either
against each other or against the existing base?"

This deliberately does NOT re-run detection on old-rule-vs-old-rule
pairs. Those were already reviewed the last time the base config was
audited; re-flagging them on every incremental check would bury the
one thing the IT staff actually asked about (the new rules) under
findings they've already seen and accepted.

DESIGN CONSTRAINT (read before editing): this module calls
bridge.run_engine() exactly the way full_check already does, and does
not import from or modify firewall_engine.pl, ip_subnet.pl, bridge.py,
or parser.py's parsing logic. It is a pure post-processing filter on
top of the existing, tested pipeline:

    1. Parse base_config       -> existing rules, keep their real IDs.
    2. Parse new_rules_config   -> proposed rules, RENUMBERED to start
       right after the highest ID/priority in the base config (see
       _renumber below) so they can never collide with an existing ID
       and always sort as evaluated last within their chain.
    3. Run run_engine(existing + renumbered_new) -- completely
       unchanged, full detection, same as a normal full audit.
    4. Filter: keep a Finding only if primary_id or secondary_id is
       one of the new rules. Findings where BOTH sides are old rules
       are dropped -- not because they don't exist, but because the
       base config that produced them was (by construction of this
       mode) already accepted as-is.

This filter can only ever HIDE old-vs-old findings the user has
already implicitly signed off on by supplying that base config as
"the current, trusted state" -- it can never hide or fabricate a
finding that involves a new rule, because run_engine() still sees
every rule and runs the exact same detector Phase 2 already tested.
"""

from __future__ import annotations

from dataclasses import dataclass

from parser import Rule, ParseError, parse
from bridge import Finding, run_engine


@dataclass
class IncrementalResult:
    new_rules:       list[Rule]           # proposed rules, as renumbered/asserted
    base_rules_count: int
    base_errors:      list[ParseError]     # unsupported lines in the BASE config
    new_errors:        list[ParseError]     # unsupported lines in the NEW-rules file
    findings:          list[Finding]        # only findings touching >=1 new rule
    engine_error:       str | None


def _renumber(new_rules: list[Rule], base_rules: list[Rule]) -> list[Rule]:
    """Shift every new rule's id/priority so it sorts strictly after every
    base rule *within the same chain*, and so no id collides with a base
    rule's id (ids must be unique across the whole merged set, since
    Finding.primary_id/secondary_id are bare ints with no chain tag).

    Rationale for "after every base rule, not just same-chain ones": ids
    are compared globally when the caller reports "rule #N" to a human,
    so reusing an id across chains (even though findings themselves stay
    chain-scoped -- see bridge.run_engine's per-chain split) would still
    let two DIFFERENT reported rules show the same number in one
    conversation with IT staff. Using one global offset avoids that
    confusion entirely, at zero cost.

    IMPORTANT: priority must sort after every priority actually present
    in base_rules, not just after base_rules' ids. A prior version of
    this function set priority = id (a small integer like 28), which
    could be LOWER than an existing base rule's priority (e.g. base
    rule id=1 has priority=10 under parser.py's id*10 scheme) even
    though the new rule's id was numerically larger. Since every
    detector in firewall_engine.pl reasons about evaluation order using
    Priority (deliberately kept separate from ID -- see project
    README), that mismatch could make a newly-added rule look like it
    evaluates BEFORE an existing rule it should come after, silently
    flipping which finding type gets reported (e.g. shadowing vs.
    generalization) for that pair. Fixed by computing new priorities
    from the actual max priority found in base_rules (not derived from
    id), so this holds regardless of what priority scheme the base
    config's rules actually use.
    """
    if not base_rules:
        next_id = 1
        priority_floor = 0
    else:
        next_id = max(r.id for r in base_rules) + 1
        # Use the actual max priority present in base_rules as the floor,
        # not an assumption about how it relates to id. This is robust
        # even if a base config's priorities don't follow parser.py's
        # usual id*10 pattern (e.g. a hand-edited or externally-generated
        # config) -- the new rule only needs to sort after whatever
        # priorities are actually there.
        priority_floor = max(r.priority for r in base_rules)

    renumbered = []
    for offset, rule in enumerate(new_rules):
        new_id = next_id + offset
        renumbered.append(Rule(
            id=new_id,
            priority=priority_floor + (offset + 1) * 10,
            action=rule.action,
            protocol=rule.protocol,
            src_ip=rule.src_ip,
            dst_ip=rule.dst_ip,
            src_port=rule.src_port,
            dst_port=rule.dst_port,
            chain=rule.chain,
        ))
    return renumbered


def check_new_rules(
    base_config_text: str,
    new_rules_config_text: str,
    timeout_seconds: int = 120,
    lang: str = "fa",
) -> IncrementalResult:
    """Parse both inputs, run the existing full detector on the union,
    and return only the findings that involve at least one new rule.

    base_config_text       -- the current, already-trusted firewall config.
    new_rules_config_text  -- ONLY the proposed additional rules (same
                               file format as base_config_text: iptables-save
                               or nftables). Rule ids in this text are
                               ignored/discarded -- see _renumber above.
    lang                   -- "fa" (default) or "en"; forwarded to
                               run_engine() so every finding's Explanation
                               comes back already rendered in that language.
    """
    base_rules, base_errors = parse(base_config_text)
    new_rules_parsed, new_errors = parse(new_rules_config_text)

    new_rules = _renumber(new_rules_parsed, base_rules)
    new_ids = {r.id for r in new_rules}

    all_rules = base_rules + new_rules
    if not all_rules:
        return IncrementalResult(
            new_rules=new_rules,
            base_rules_count=len(base_rules),
            base_errors=base_errors,
            new_errors=new_errors,
            findings=[],
            engine_error=None,
        )

    findings, engine_error = run_engine(all_rules, timeout_seconds=timeout_seconds, lang=lang)
    if engine_error:
        return IncrementalResult(
            new_rules=new_rules,
            base_rules_count=len(base_rules),
            base_errors=base_errors,
            new_errors=new_errors,
            findings=[],
            engine_error=engine_error,
        )

    relevant = [
        f for f in findings
        if f.primary_id in new_ids or f.secondary_id in new_ids
    ]
    relevant.sort(key=lambda f: f.severity_rank())

    return IncrementalResult(
        new_rules=new_rules,
        base_rules_count=len(base_rules),
        base_errors=base_errors,
        new_errors=new_errors,
        findings=relevant,
        engine_error=None,
    )
