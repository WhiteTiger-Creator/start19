"""Verifier tests for this task.

Every test below corresponds to something instruction.md states is graded.
Shared machinery lives in harness.py.
"""

from harness import *  # noqa: F401,F403

@pytest.fixture(scope="session")
def primary_outputs():
    return _run_pipeline()


@pytest.fixture(scope="session")
def alternate_outputs():
    return _run_pipeline(input_path=ALT_INPUT)


# --------------------------------------------------------------------------
# Step one: the truncated rule base must be rebuilt before anything is compiled
# --------------------------------------------------------------------------
def test_recovery_sources_are_intact():
    """Every rule source is read, not rewritten."""
    live = {n: hashlib.sha256(Path(p).read_bytes()).hexdigest() for n, p in (
        ("snapshot", SNAPSHOT_PATH), ("journal", JOURNAL_PATH), ("groups", GROUPS_PATH),
        ("policy", POLICY_PATH), ("log", LOG_PATH))}
    assert _digest(live) == FIXTURE["rule_sources_digest"]


def test_rule_base_was_recovered():
    """The rebuilt rule base matches the governed replay exactly."""
    recovered = _load_json(RULES_PATH)
    assert len(recovered) == FIXTURE["recovered_rule_count"]
    assert _digest(recovered) == FIXTURE["recovered_rules_digest"]


def test_recovered_rules_carry_only_the_declared_fields():
    """Migrator bookkeeping never survives the replay."""
    for row in _load_json(RULES_PATH):
        assert set(row) == RULE_KEYS


def test_recovered_rule_base_is_sorted():
    """The rule base ascends by sequence, then rule id."""
    rows = _load_json(RULES_PATH)
    keys = [(r["sequence"], r["rule_id"]) for r in rows]
    assert keys == sorted(keys)


def test_resolved_sides_are_masked_deduplicated_and_ordered():
    """Each resolved side is a clean prefix set in the governed order."""
    for row in _load_json(RULES_PATH):
        for side in ("source_cidrs", "destination_cidrs"):
            values = row[side]
            assert isinstance(values, list)
            assert len(values) == len(set(values)), (row["rule_id"], side)
            parsed = [_parse_cidr(c) for c in values]
            for text, (base, plen) in zip(values, parsed):
                octets = (base >> 24 & 255, base >> 16 & 255, base >> 8 & 255, base & 255)
                assert text == "%d.%d.%d.%d/%d" % (*octets, plen), text
            assert parsed == sorted(parsed), (row["rule_id"], side)


def test_object_groups_resolve_transitively_and_terminate():
    """The verifier's own transitive closure agrees with every resolved side.

    The catalogue nests groups inside groups, names groups that do not exist, and
    holds a pair that reference each other; a one-level expansion, a resolver that
    keeps dangling members, and one that recurses without marking what it has
    entered all disagree with this closure.
    """
    catalogue = {g["group_id"]: g["members"] for g in _load_json(GROUPS_PATH)}

    def closure(gid, seen):
        if gid in seen or gid not in catalogue:
            return set()
        seen.add(gid)
        out = set()
        for m in catalogue[gid]:
            if m.startswith("@"):
                out |= closure(m[1:], seen)
            else:
                base, plen = _parse_cidr(m)
                out.add("%d.%d.%d.%d/%d" % (base >> 24 & 255, base >> 16 & 255,
                                            base >> 8 & 255, base & 255, plen))
        return out

    resolved = {g: closure(g, set()) for g in catalogue}
    assert any(len(v) == 0 for v in resolved.values()), "no empty group in the catalogue"
    assert max(len(v) for v in resolved.values()) > 1

    snapshot = {r["rule_id"]: r for r in _load_json(SNAPSHOT_PATH)}
    expected_sets = {frozenset(v) for v in resolved.values()}
    literal_seen = 0
    for row in _load_json(RULES_PATH):
        origin = snapshot.get(row["rule_id"])
        if origin is None:
            continue
        for side, field in (("source_cidrs", "source"), ("destination_cidrs", "destination")):
            ref = origin[field]
            if not ref.startswith("@"):
                literal_seen += 1
                continue
            # the side may have been amended by the journal, so accept any
            # resolution the catalogue can actually produce
            assert frozenset(row[side]) in expected_sets, (row["rule_id"], side)
    assert literal_seen > 0


def test_wrong_recoveries_differ_from_the_governed_rule_base():
    """Four plausible misreadings of the recovery each give a different rule base."""
    expected = FIXTURE["recovered_rules_digest"]
    assert FIXTURE["shipped_truncated_digest"] != expected
    snapshot = {r["rule_id"]: r for r in _load_json(SNAPSHOT_PATH)}
    journal = _load_json(JOURNAL_PATH)
    catalogue = {g["group_id"]: g["members"] for g in _load_json(GROUPS_PATH)}

    def resolve(ref, deep):
        out = set()

        def walk(gid, seen):
            if gid in seen or gid not in catalogue:
                return
            seen.add(gid)
            for m in catalogue[gid]:
                if m.startswith("@"):
                    if deep:
                        walk(m[1:], seen)
                else:
                    b, p = _parse_cidr(m)
                    out.add("%d.%d.%d.%d/%d" % (b >> 24 & 255, b >> 16 & 255, b >> 8 & 255, b & 255, p))

        if ref.startswith("@"):
            walk(ref[1:], set())
        else:
            b, p = _parse_cidr(ref)
            out.add("%d.%d.%d.%d/%d" % (b >> 24 & 255, b >> 16 & 255, b >> 8 & 255, b & 255, p))
        return sorted(out, key=_parse_cidr)

    def replay(by_seq: bool, restore_from_snapshot: bool, deep_groups: bool):
        live = {k: dict(v) for k, v in snapshot.items()}
        held = {}
        for c in (sorted(journal, key=lambda x: x["seq"]) if by_seq else journal):
            k, kind = c["rule_id"], c["kind"]
            if kind == "amend" and k in live:
                live[k][c["field"]] = c["value"]
            elif kind == "retract" and k in live:
                held[k] = dict(live.pop(k))
            elif kind == "restore":
                if restore_from_snapshot:
                    if k in snapshot and k not in live:
                        live[k] = dict(snapshot[k])
                elif k in held:
                    live[k] = held.pop(k)
        rows = []
        for r in live.values():
            rows.append({
                "rule_id": r["rule_id"], "sequence": r["sequence"], "action": r["action"],
                "protocol": r["protocol"], "source_cidrs": resolve(r["source"], deep_groups),
                "destination_cidrs": resolve(r["destination"], deep_groups),
                "port_low": r["port_low"], "port_high": r["port_high"], "enabled": r["enabled"]})
        rows.sort(key=lambda r: (r["sequence"], r["rule_id"]))
        return _digest(rows)

    assert replay(True, False, True) == expected      # the governed reading
    assert replay(False, False, True) != expected     # replayed in file order
    assert replay(True, True, True) != expected       # restore re-reads the snapshot
    assert replay(True, False, False) != expected     # groups expanded one level deep


# --------------------------------------------------------------------------
# Step two: the compiled policy itself
# --------------------------------------------------------------------------
def test_primary_summary_matches_fixture(primary_outputs):
    """Every summary field matches the sealed reference run."""
    _, summary, _, _ = primary_outputs
    assert summary == FIXTURE["primary"]["summary"]


def test_primary_artifacts_match_fixture(primary_outputs):
    """The compiled policy and the exception queue match the sealed digests."""
    _, _, policy, queue = primary_outputs
    assert _digest(policy) == FIXTURE["primary"]["policy_digest"]
    assert _digest(queue) == FIXTURE["primary"]["queue_digest"]


def test_alternate_rule_base_matches_fixture(alternate_outputs):
    """A held-out rule base the agent never sees produces the sealed result."""
    _, summary, policy, queue = alternate_outputs
    assert summary == FIXTURE["alternate"]["summary"]
    assert _digest(policy) == FIXTURE["alternate"]["policy_digest"]
    assert _digest(queue) == FIXTURE["alternate"]["queue_digest"]


def test_output_dir_contains_exactly_three_files(primary_outputs):
    """A run writes the three contracted artifacts and nothing else."""
    out_dir, _, _, _ = primary_outputs
    assert sorted(p.name for p in out_dir.iterdir()) == [
        "compiled_policy.json", "exception_queue.jsonl", "summary.json"]


def test_summary_schema_and_types(primary_outputs):
    """The summary carries exactly the contracted fields at the contracted types."""
    _, summary, _, _ = primary_outputs
    assert set(summary) == SUMMARY_KEYS
    for field, kind in SPEC["outputs"]["summary"]["field_types"].items():
        value = summary[field]
        if kind == "integer":
            assert isinstance(value, int) and not isinstance(value, bool), field
        else:
            assert isinstance(value, str), field


def test_compiled_schema_and_ordering(primary_outputs):
    """Compiled rules carry the contracted fields and the contracted order."""
    _, _, policy, _ = primary_outputs
    keys = [(r["sequence"], r["rule_id"]) for r in policy]
    assert keys == sorted(keys)
    for r in policy:
        assert set(r) == COMPILED_KEYS
        assert isinstance(r["shadowed"], bool)
        assert r["action"] in {"permit", "deny"}
        assert r["port_low"] <= r["port_high"]
        assert r["address_span"] == sum(1 << (32 - _parse_cidr(c)[1]) for c in r["source_cidrs"])


def test_queue_schema_and_ordering(primary_outputs):
    """Queue rows carry the contracted fields and the contracted order."""
    _, _, _, queue = primary_outputs
    keys = [(r["reason"], r["rule_id"]) for r in queue]
    assert keys == sorted(keys)
    for r in queue:
        assert set(r) == QUEUE_KEYS
        assert r["reason"] in QUEUE_REASONS


def test_policy_closes_with_an_explicit_deny(primary_outputs):
    """The last rule denies everything, at the sequence the policy names."""
    _, summary, policy, _ = primary_outputs
    last = policy[-1]
    assert last["rule_id"] == "FW-DEFAULT"
    assert last["sequence"] == summary["effective_default_deny_sequence"]
    assert last["action"] == "deny" and last["protocol"] == "any"
    assert last["source_cidrs"] == ["0.0.0.0/0"] and last["destination_cidrs"] == ["0.0.0.0/0"]
    assert (last["port_low"], last["port_high"]) == (0, summary["effective_port_ceiling"])
    assert [r["rule_id"] for r in policy].count("FW-DEFAULT") == 1


def test_no_inert_rule_reaches_the_policy(primary_outputs):
    """Disabled rules and empty-set rules never appear in the compiled policy."""
    _, _, policy, queue = primary_outputs
    inert = {r["rule_id"] for r in queue if r["reason"] == "inert"}
    installed = {r["rule_id"] for r in policy}
    assert inert and not (inert & installed)
    base = {r["rule_id"]: r for r in _load_json(RULES_PATH)}
    for rid in inert:
        r = base[rid]
        assert (not r["enabled"]) or not r["source_cidrs"] or not r["destination_cidrs"]
    for r in policy:
        if r["rule_id"] == "FW-DEFAULT":
            continue
        assert base[r["rule_id"]]["enabled"]
        assert r["source_cidrs"] and r["destination_cidrs"]


def test_shadowed_rules_stay_in_the_policy(primary_outputs):
    """Shadowing is a report, not a removal: the flagged rules are still installed."""
    _, summary, policy, queue = primary_outputs
    flagged = [r for r in policy if r["shadowed"]]
    # the verdict is settled before the cap, so the count covers live rules the
    # cap later displaced as well as the ones still installed
    assert 0 < len(flagged) <= summary["shadowed_count"]
    queued = {r["rule_id"] for r in queue}
    for r in flagged:
        assert r["shadowed_by"]
        assert r["rule_id"] not in queued
    displaced = {r["rule_id"] for r in queue if r["reason"] == "over_cap"}
    assert summary["shadowed_count"] > len(flagged), "the cap displaced no shadowed rule"
    assert displaced, "the cap displaced nothing, so the count cannot be pre-cap"


def test_every_shadowing_claim_is_independently_confirmed(primary_outputs):
    """The verifier re-derives each claim: the named rule really does cover it."""
    _, _, policy, _ = primary_outputs
    by_id = {r["rule_id"]: r for r in policy}
    checked = 0
    for r in policy:
        if not r["shadowed"]:
            continue
        a = by_id[r["shadowed_by"]]
        assert a["sequence"] < r["sequence"], r["rule_id"]
        assert a["protocol"] in ("any", r["protocol"])
        assert a["port_low"] <= r["port_low"] and r["port_high"] <= a["port_high"]
        for side in ("source_cidrs", "destination_cidrs"):
            for inner in r[side]:
                ib, ip = _parse_cidr(inner)
                assert any(op <= ip and ib & (0 if op == 0 else (0xFFFFFFFF << (32 - op)) & 0xFFFFFFFF) == ob
                           for ob, op in map(_parse_cidr, a[side])), (r["rule_id"], side, inner)
        checked += 1
    assert checked > 0


def test_summary_counts_track_the_artifacts(primary_outputs):
    """The summary's own totals agree with the artifacts beside it."""
    _, summary, policy, queue = primary_outputs
    assert summary["rule_count"] == len(_load_json(RULES_PATH))
    assert summary["compiled_count"] == len(policy)
    assert summary["queued_count"] == len(queue)
    assert summary["inert_count"] == sum(1 for r in queue if r["reason"] == "inert")
    assert summary["permit_count"] == sum(1 for r in policy if r["action"] == "permit")
    assert summary["deny_count"] == sum(1 for r in policy if r["action"] == "deny")
    assert summary["total_source_addresses"] == sum(
        r["address_span"] for r in policy if r["rule_id"] != "FW-DEFAULT")


def test_both_queue_reasons_occur(primary_outputs):
    """The graded run exercises every documented queue reason."""
    _, _, _, queue = primary_outputs
    assert {r["reason"] for r in queue} == QUEUE_REASONS


def test_the_rule_cap_actually_binds(primary_outputs):
    """More rules survive than the cap admits, so the cap is load-bearing."""
    _, summary, policy, _ = primary_outputs
    operator_rules = [r for r in policy if r["rule_id"] != "FW-DEFAULT"]
    assert len(operator_rules) == summary["effective_max_rules"]
    assert summary["rule_count"] - summary["inert_count"] > summary["effective_max_rules"]


# --------------------------------------------------------------------------
# Each reversed rule, pinned on a crafted rule base where the drafts disagree
# --------------------------------------------------------------------------
def _rule(rid, seq, *, action="permit", protocol="tcp", src=("10.0.0.0/8",),
          dst=("192.168.0.0/16",), lo=80, hi=80, enabled=True):
    return {"rule_id": rid, "sequence": seq, "action": action, "protocol": protocol,
            "source_cidrs": list(src), "destination_cidrs": list(dst),
            "port_low": lo, "port_high": hi, "enabled": enabled}


def _probe(rules, *, max_rules=1000, port_ceiling=65535, lookback=120, deny_seq=999000):
    """Run the submitted compiler over a crafted rule base and return its artifacts."""
    saved = POLICY_PATH.read_text(encoding="utf-8")
    staged = _CWORK / f"probe-{next(_run_ctr)}.json"
    try:
        _write_json(POLICY_PATH, {"default": {
            "max_rules": max_rules, "port_ceiling": port_ceiling,
            "max_shadow_lookback": lookback, "default_deny_sequence": deny_seq}})
        _write_json(staged, rules)
        os.chmod(staged, 0o644)
        return _run_pipeline(input_path=staged)
    finally:
        POLICY_PATH.write_text(saved, encoding="utf-8")


def test_a_rule_an_earlier_rule_covers_is_flagged_but_still_installed():
    """The narrower later rule is reported shadowed and stays in the policy.

    The most-specific draft would drop FW-0002 as redundant; the governed rule
    installs it in sequence with the flag set.
    """
    _, summary, policy, queue = _probe([
        _rule("FW-0001", 10, src=("10.0.0.0/8",)),
        _rule("FW-0002", 20, src=("10.1.2.0/24",))])
    assert [r["rule_id"] for r in policy] == ["FW-0001", "FW-0002", "FW-DEFAULT"]
    assert [(r["rule_id"], r["shadowed"], r["shadowed_by"]) for r in policy[:2]] == [
        ("FW-0001", False, ""), ("FW-0002", True, "FW-0001")]
    assert summary["shadowed_count"] == 1
    assert queue == []


def test_a_rule_only_a_later_rule_covers_is_not_shadowed():
    """Coverage by a rule further down the sequence is not shadowing at all.

    The device takes the first match, so the narrow rule at sequence 10 fires
    before the broad one at 20 ever sees the packet.
    """
    _, summary, policy, _ = _probe([
        _rule("FW-0001", 10, src=("10.1.2.0/24",)),
        _rule("FW-0002", 20, src=("10.0.0.0/8",))])
    assert [r["shadowed"] for r in policy[:2]] == [False, False]
    assert summary["shadowed_count"] == 0


def test_the_union_of_two_earlier_rules_does_not_establish_shadowing():
    """Shadowing needs one rule that covers the lot, not two that cover it between them."""
    _, summary, policy, _ = _probe([
        _rule("FW-0001", 10, src=("10.0.0.0/9",)),
        _rule("FW-0002", 20, src=("10.128.0.0/9",)),
        _rule("FW-0003", 30, src=("10.0.0.0/8",))])
    assert [r["shadowed"] for r in policy[:3]] == [False, False, False]
    assert summary["shadowed_count"] == 0


def test_containment_must_hold_on_every_prefix_of_the_later_rule():
    """One uncovered prefix in the set is enough to defeat the claim."""
    _, _, policy, _ = _probe([
        _rule("FW-0001", 10, src=("10.0.0.0/8",)),
        _rule("FW-0002", 20, src=("10.1.0.0/16", "172.16.0.0/12"))])
    assert [r["shadowed"] for r in policy[:2]] == [False, False]


def test_containment_must_hold_on_the_destination_as_well():
    """A rule covered on the source but not the destination is not shadowed."""
    _, _, policy, _ = _probe([
        _rule("FW-0001", 10, src=("10.0.0.0/8",), dst=("192.168.1.0/24",)),
        _rule("FW-0002", 20, src=("10.1.0.0/16",), dst=("192.168.2.0/24",))])
    assert [r["shadowed"] for r in policy[:2]] == [False, False]


def test_containment_must_hold_on_the_protocol():
    """A tcp rule never shadows a udp rule, however wide its prefixes."""
    _, _, policy, _ = _probe([
        _rule("FW-0001", 10, protocol="tcp", src=("0.0.0.0/0",), dst=("0.0.0.0/0",), lo=0, hi=65535),
        _rule("FW-0002", 20, protocol="udp", src=("10.1.0.0/16",))])
    assert [r["shadowed"] for r in policy[:2]] == [False, False]


def test_a_rule_of_any_protocol_shadows_a_specific_one():
    """The wildcard protocol does cover a named protocol."""
    _, _, policy, _ = _probe([
        _rule("FW-0001", 10, protocol="any", src=("0.0.0.0/0",), dst=("0.0.0.0/0",), lo=0, hi=65535),
        _rule("FW-0002", 20, protocol="udp", src=("10.1.0.0/16",))])
    assert [(r["shadowed"], r["shadowed_by"]) for r in policy[:2]] == [
        (False, ""), (True, "FW-0001")]


def test_containment_must_hold_on_the_port_range():
    """A rule reaching outside the earlier rule's ports is not shadowed."""
    _, _, policy, _ = _probe([
        _rule("FW-0001", 10, src=("0.0.0.0/0",), dst=("0.0.0.0/0",), lo=80, hi=443),
        _rule("FW-0002", 20, src=("10.1.0.0/16",), lo=80, hi=8080)])
    assert [r["shadowed"] for r in policy[:2]] == [False, False]


def test_an_empty_object_group_makes_a_rule_inert_rather_than_a_wildcard():
    """A side that resolved to nothing matches nothing and shadows nothing.

    The wildcard interim would treat FW-0001 as 0.0.0.0/0, install it, and let it
    shadow FW-0002; the governed rule queues it and leaves FW-0002 unshadowed.
    """
    _, summary, policy, queue = _probe([
        _rule("FW-0001", 10, src=(), lo=0, hi=65535),
        _rule("FW-0002", 20, src=("10.1.0.0/16",))])
    assert [r["rule_id"] for r in policy] == ["FW-0002", "FW-DEFAULT"]
    assert policy[0]["shadowed"] is False
    assert [(r["rule_id"], r["reason"]) for r in queue] == [("FW-0001", "inert")]
    assert summary["inert_count"] == 1 and summary["shadowed_count"] == 0


def test_an_empty_destination_group_is_inert_too():
    """Emptiness on either side is enough to make the rule inert."""
    _, _, policy, queue = _probe([_rule("FW-0001", 10, dst=())])
    assert [r["rule_id"] for r in policy] == ["FW-DEFAULT"]
    assert [(r["rule_id"], r["reason"]) for r in queue] == [("FW-0001", "inert")]


def test_a_disabled_rule_is_inert_and_shadows_nothing():
    """A disabled rule leaves the policy and does not cover the rule behind it."""
    _, _, policy, queue = _probe([
        _rule("FW-0001", 10, src=("10.0.0.0/8",), enabled=False),
        _rule("FW-0002", 20, src=("10.1.2.0/24",))])
    assert [r["rule_id"] for r in policy] == ["FW-0002", "FW-DEFAULT"]
    assert policy[0]["shadowed"] is False
    assert [(r["rule_id"], r["reason"]) for r in queue] == [("FW-0001", "inert")]


def test_the_lookback_window_bounds_the_shadow_scan():
    """A covering rule further back than the window is not consulted.

    With a lookback of one, only FW-0002 is examined for FW-0003, and it does not
    cover it; widening the window to two finds FW-0001 and does.
    """
    rules = [_rule("FW-0001", 10, src=("10.0.0.0/8",)),
             _rule("FW-0002", 20, src=("172.16.0.0/12",)),
             _rule("FW-0003", 30, src=("10.1.2.0/24",))]
    _, narrow, narrow_policy, _ = _probe(rules, lookback=1)
    _, wide, wide_policy, _ = _probe(rules, lookback=2)
    assert narrow["shadowed_count"] == 0
    assert [r["shadowed"] for r in narrow_policy[:3]] == [False, False, False]
    assert wide["shadowed_count"] == 1
    assert wide_policy[2]["shadowed_by"] == "FW-0001"


def test_port_ranges_are_clamped_to_the_policy_ceiling():
    """The ceiling is applied before any coverage question is asked."""
    _, summary, policy, _ = _probe([
        _rule("FW-0001", 10, src=("0.0.0.0/0",), dst=("0.0.0.0/0",), lo=0, hi=65535),
        _rule("FW-0002", 20, src=("10.1.0.0/16",), lo=900, hi=5000)],
        port_ceiling=1024)
    assert [(r["port_low"], r["port_high"]) for r in policy] == [
        (0, 1024), (900, 1024), (0, 1024)]
    assert summary["shadowed_count"] == 1


def test_the_closing_deny_is_emitted_even_once_the_cap_is_full():
    """The cap counts the operator's rules alone; the deny is always appended."""
    _, summary, policy, queue = _probe([
        _rule("FW-0001", 10), _rule("FW-0002", 20), _rule("FW-0003", 30)],
        max_rules=2)
    assert [r["rule_id"] for r in policy] == ["FW-0001", "FW-0002", "FW-DEFAULT"]
    assert [(r["rule_id"], r["reason"]) for r in queue] == [("FW-0003", "over_cap")]
    assert summary["compiled_count"] == 3 and summary["effective_max_rules"] == 2


def test_the_cap_takes_the_rules_in_sequence_order():
    """The rules the cap keeps are the earliest by sequence, not by file order."""
    _, _, policy, queue = _probe([
        _rule("FW-0003", 30), _rule("FW-0001", 10), _rule("FW-0002", 20)],
        max_rules=2)
    assert [r["rule_id"] for r in policy] == ["FW-0001", "FW-0002", "FW-DEFAULT"]
    assert [r["rule_id"] for r in queue] == ["FW-0003"]


# --------------------------------------------------------------------------
# Contract, budget, determinism and isolation
# --------------------------------------------------------------------------
def test_policy_path_actually_influences_the_output():
    """The policy is resolved from its fixed path, not inlined as constants."""
    saved = POLICY_PATH.read_text(encoding="utf-8")
    try:
        _write_json(POLICY_PATH, {"default": {
            "max_rules": 25, "port_ceiling": 1024,
            "max_shadow_lookback": 3, "default_deny_sequence": 123456}})
        _, summary, policy, _ = _run_pipeline()
        assert summary["effective_max_rules"] == 25
        assert summary["effective_port_ceiling"] == 1024
        assert summary["effective_shadow_lookback"] == 3
        assert summary["effective_default_deny_sequence"] == 123456
        assert policy[-1]["sequence"] == 123456
        assert summary != FIXTURE["primary"]["summary"]
    finally:
        POLICY_PATH.write_text(saved, encoding="utf-8")


def test_run_is_idempotent(primary_outputs):
    """Re-running over the same rule base reproduces the same artifacts."""
    _, summary, policy, queue = primary_outputs
    _, s2, p2, q2 = _run_pipeline()
    assert s2 == summary and _digest(p2) == _digest(policy) and _digest(q2) == _digest(queue)


def test_no_argument_run_writes_to_the_documented_defaults(primary_outputs):
    """With no flags at all the program reads and writes its documented defaults.

    The previous form still passed --output-dir, so it only exercised the --input
    default; a changed default output directory went unnoticed.
    """
    binary = _build(WORKFLOW_PATH)
    _publish_inputs()
    default_out = Path("/app/output")
    shutil.rmtree(default_out, ignore_errors=True)
    default_out.mkdir(parents=True, exist_ok=True)
    os.chmod(default_out, 0o777)
    result = _run_agent([binary], cwd=_candidate_dir())
    assert result.returncode == 0, result.stderr
    assert sorted(q.name for q in default_out.iterdir()) == ['compiled_policy.json', 'exception_queue.jsonl', 'summary.json']
    _, summary, doc, queue = primary_outputs
    assert _load_json(default_out / "summary.json") == summary
    assert _digest(_load_json(default_out / "compiled_policy.json")) == _digest(doc)
    assert _digest(_load_jsonl(default_out / "exception_queue.jsonl")) == _digest(queue)


def test_the_budget_is_enforced_by_killing_an_overrunning_run(primary_outputs):
    """The budget is enforced, and not by timing the grading machine.

    Every candidate run is executed with the contract's published budget as its
    hard timeout, so a run that overruns is killed and the suite fails. Nothing
    compares a measured elapsed time against a threshold.
    """
    assert HARD_TIMEOUT_SEC == int(RUNTIME_BUDGET_SEC)
    assert primary_outputs[1]["compiled_count"] > 0, "the graded run did not complete"



def test_runtime_budget_is_stated_in_the_contract():
    """The budget enforced above is the one the contract publishes."""
    assert int(SPEC["runtime_budget_seconds"]) == int(RUNTIME_BUDGET_SEC)


def test_submitted_program_runs_unprivileged_and_cannot_write_reward(tmp_path):
    """The graded program runs as nobody and cannot touch the reward path."""
    probe = tmp_path / "main.go"
    probe.write_text(
        'package main\n\nimport ("fmt"; "os")\n\n'
        'func main() {\n\tfmt.Println(os.Getuid())\n'
        '\terr := os.WriteFile("/logs/verifier/reward.txt", []byte("1"), 0o644)\n'
        '\tfmt.Println(err != nil)\n}\n', encoding="utf-8")
    binary = _build(probe)
    result = _run_agent([binary], cwd=_candidate_dir())
    assert result.returncode == 0, result.stderr
    parts = result.stdout.split()
    assert parts[0] == str(CANDIDATE_UID) and parts[1] == "true"


def test_frozen_snapshot_preserved():
    """The migration's compiler must still be on disk, unmodified."""
    assert ORIGINAL_WORKFLOW_PATH.exists()
    assert hashlib.sha256(ORIGINAL_WORKFLOW_PATH.read_bytes()).hexdigest() == \
        FIXTURE["broken_compiler_sha256"]


def test_frozen_snapshot_is_wrong(primary_outputs):
    """The shipped compiler does not already produce the governed policy."""
    _, summary, _, _ = primary_outputs
    _, broken, _, _ = _run_pipeline(script_path=ORIGINAL_WORKFLOW_PATH)
    assert broken != summary


def test_governance_log_present():
    """The minute book the rules are reconstructed from is in the environment."""
    assert LOG_PATH.exists() and LOG_PATH.stat().st_size > 0


def test_shipped_contract_matches_the_golden_copy():
    """The output contract in the environment is unmodified.

    Field lists, container shapes and sort orders are golden metadata and are read
    from the verifier's own image; this proves the agent's copy still agrees with
    it, so the contract cannot be trimmed to weaken a schema check.
    """
    shipped = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    assert shipped == json.loads(GOLDEN_CONTRACT_PATH.read_text(encoding="utf-8"))
