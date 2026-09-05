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


def _as_contract_layout(raw: str) -> str:
    """The text with encoder-specific escaping normalised away.

    The contract fixes the LAYOUT -- two-space indent, trailing newline -- not the
    escape style, and the two encoders disagree: Go's json.Marshal writes `<`, `>`
    and `&` as \\u003c, \\u003e and \\u0026 and emits non-ASCII as literal UTF-8,
    while Python's json.dumps does the opposite on both counts. Comparing raw bytes
    against Python's rendering would fail a correct Go compiler the moment any of
    those characters reached a rule name, an object-group label or a comment.
    """
    for escaped, literal in (("\\u003c", "<"), ("\\u003e", ">"), ("\\u0026", "&")):
        raw = raw.replace(escaped, literal)
    return raw


def test_the_artifacts_are_serialised_exactly_as_the_contract_states(primary_outputs):
    """Read off the raw bytes, which every other check throws away by parsing.

    The contract fixes a form for all four documents and nothing here looked at
    one, so a run emitting the summary compactly, or the queue with an indent,
    matched every sealed digest.
    """
    out_dir = primary_outputs[0]
    spec = SPEC["outputs"]
    for name, section in (("summary.json", "summary"),
                          ("compiled_policy.json", "compiled_policy")):
        raw = (out_dir / name).read_text(encoding="utf-8")
        stated = spec[section]["serialisation"]
        assert "two-space indent" in stated and "trailing newline" in stated, stated
        assert raw.endswith("\n") and not raw.endswith("\n\n"), name
        assert _as_contract_layout(raw) == json.dumps(
            json.loads(raw), indent=2, ensure_ascii=False) + "\n", (
            f"{name} is not the contract's two-space indent")

    raw = (out_dir / "exception_queue.jsonl").read_text(encoding="utf-8")
    assert "compact JSON object per line" in spec["exception_queue"]["serialisation"]
    assert raw == "" or raw.endswith("\n")
    for line in raw.splitlines():
        assert line.strip(), "the queue carries a blank line"
        assert _as_contract_layout(line) == json.dumps(
            json.loads(line), separators=(",", ":"), ensure_ascii=False), (
            "a queue line is not compact JSON")

    # the rebuilt rule base is a graded artifact too, and carries its own rule
    raw = RULES_PATH.read_text(encoding="utf-8")
    stated = SPEC["reconciled_inputs"]["policy_rules"]["serialisation"]
    assert "two-space indent" in stated and "trailing newline" in stated, stated
    assert raw.endswith("\n") and not raw.endswith("\n\n")
    assert _as_contract_layout(raw) == json.dumps(
        json.loads(raw), indent=2, ensure_ascii=False) + "\n", (
        "the rebuilt rule base is not the contract's two-space indent")


def test_output_dir_contains_exactly_three_files(primary_outputs):
    """A run writes the three contracted artifacts and nothing else."""
    out_dir, _, _, _ = primary_outputs
    assert sorted(p.name for p in out_dir.iterdir()) == sorted(OUTPUT_FILES)


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
    types = SPEC["outputs"]["compiled_policy"]["field_types"]
    for r in policy:
        assert set(r) == COMPILED_KEYS
        for field, kind in types.items():
            value = r[field]
            if kind.startswith("integer"):
                assert isinstance(value, int) and not isinstance(value, bool), field
            elif kind.startswith("boolean"):
                assert isinstance(value, bool), field
            elif kind.startswith("array"):
                assert isinstance(value, list) and all(
                    isinstance(v, str) for v in value), field
            else:
                assert isinstance(value, str), field
        assert r["action"] in {"permit", "deny"}
        assert r["port_low"] <= r["port_high"]
        # #NET-9214 reversed the union draft #NET-9050: every prefix of the
        # resolved source set is counted in full and on its own, so a nested pair
        # is counted twice between them.
        assert r["address_span"] == sum(1 << (32 - _parse_cidr(c)[1]) for c in r["source_cidrs"])
        # #NET-9218 keeps shadowed_by a string throughout; the contract names the
        # empty string as what an unshadowed rule carries, not null.
        assert (r["shadowed_by"] != "") == r["shadowed"], r


def test_the_address_total_passes_over_the_closing_deny(primary_outputs):
    """#NET-9218: the summary total covers the operator's own rules alone.

    The reversed draft #NET-9056 read the total off the policy as installed, the
    closing deny included, which is 2^32 more. The deny is still a compiled row
    and still a deny, so this pins the boundary from both sides: the row counts
    in compiled_count and deny_count and does not count in the address total.
    """
    _, summary, policy, _ = primary_outputs
    closing = [r for r in policy if r["rule_id"] == "FW-DEFAULT"]
    assert len(closing) == 1, "the policy does not close with a single FW-DEFAULT deny"
    assert closing[0]["address_span"] == 1 << 32, closing[0]
    assert summary["total_source_addresses"] == sum(
        r["address_span"] for r in policy if r["rule_id"] != "FW-DEFAULT"), (
        "total_source_addresses does not pass over the closing deny")
    assert summary["compiled_count"] == len(policy)
    assert summary["deny_count"] == sum(1 for r in policy if r["action"] == "deny")


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
    assert displaced, "the cap displaced nothing, so the count cannot be pre-cap"
    # #NET-9222 closes the policy at the max_rules-th UNSHADOWED rule, so the run
    # the cap kept is unbroken from the top and every shadower a surviving row
    # names is still installed beside it
    installed = {r["rule_id"] for r in policy}
    for r in flagged:
        assert r["shadowed_by"] in installed, (
            f'{r["rule_id"]} names {r["shadowed_by"]} as its shadower, and the cap '
            "took that rule out of the policy")


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
    """More rules survive than the cap admits, so the cap is load-bearing.

    #NET-9222 counts the cap over the rules the device evaluates, so it is the
    UNSHADOWED rows that come to exactly max_rules; the shadowed ones ride along
    and the policy carries more rows than the cap while still being inside it.
    """
    _, summary, policy, _ = primary_outputs
    operator_rules = [r for r in policy if r["rule_id"] != "FW-DEFAULT"]
    evaluated = [r for r in operator_rules if not r["shadowed"]]
    assert len(evaluated) == summary["effective_max_rules"]
    assert len(operator_rules) > summary["effective_max_rules"], (
        "no shadowed rule rode along, so the cap's accounting proves nothing here")
    assert summary["rule_count"] - summary["inert_count"] > summary["effective_max_rules"]


# --------------------------------------------------------------------------
# Each reversed rule, pinned on a crafted rule base where the drafts disagree
# --------------------------------------------------------------------------
def _rule(rid, seq, *, action="permit", protocol="tcp", src=("10.0.0.0/8",),
          dst=("192.168.0.0/16",), lo=80, hi=80, enabled=True):
    return {"rule_id": rid, "sequence": seq, "action": action, "protocol": protocol,
            "source_cidrs": list(src), "destination_cidrs": list(dst),
            "port_low": lo, "port_high": hi, "enabled": enabled}


def _probe(rules, *, max_rules=1000, port_ceiling=65535, lookback=120, deny_seq=999000,
           omit=()):
    """Run the submitted compiler over a crafted rule base and return its artifacts.

    `omit` names policy fields to leave OUT of the file altogether, which is how
    #NET-9210's per-field baselines are exercised: every other caller writes all
    four, so a compiler that read the map directly and never fell back was never
    caught by anything here.
    """
    saved = POLICY_PATH.read_text(encoding="utf-8")
    staged = _CWORK / f"probe-{next(_run_ctr)}.json"
    try:
        default = {"max_rules": max_rules, "port_ceiling": port_ceiling,
                   "max_shadow_lookback": lookback, "default_deny_sequence": deny_seq}
        for field in omit:
            del default[field]
        _write_json(POLICY_PATH, {"default": default})
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
    """The cap counts the operator's rules alone; the deny is always appended.

    Three rules that cover no ground of each other's, so all three count against
    the cap and it really does close on the third.
    """
    _, summary, policy, queue = _probe([
        _rule("FW-0001", 10, src=("10.0.0.0/8",)),
        _rule("FW-0002", 20, src=("172.16.0.0/12",)),
        _rule("FW-0003", 30, src=("192.0.2.0/24",))],
        max_rules=2)
    assert [r["rule_id"] for r in policy] == ["FW-0001", "FW-0002", "FW-DEFAULT"]
    assert [(r["rule_id"], r["reason"]) for r in queue] == [("FW-0003", "over_cap")]
    assert summary["compiled_count"] == 3 and summary["effective_max_rules"] == 2


def test_the_cap_takes_the_rules_in_sequence_order():
    """The rules the cap sheds are the last by sequence, not the last in the file.

    None of the three covers another, so every one counts against the cap and the
    surplus comes off the end of the SEQUENCE, whatever order the file listed
    them in.
    """
    _, _, policy, queue = _probe([
        _rule("FW-0003", 30, src=("10.3.0.0/16",)),
        _rule("FW-0001", 10, src=("10.1.0.0/16",)),
        _rule("FW-0002", 20, src=("10.2.0.0/16",))],
        max_rules=2)
    assert [r["shadowed"] for r in policy[:2]] == [False, False]
    assert [r["rule_id"] for r in policy] == ["FW-0001", "FW-0002", "FW-DEFAULT"]
    assert [r["rule_id"] for r in queue] == ["FW-0003"]


def test_a_shadowed_rule_costs_nothing_against_the_cap_and_stays_in_the_policy():
    """#NET-9222: the cap counts the rules the device will actually evaluate.

    FW-0002 sits inside FW-0001 and is reported shadowed, so it is never reached
    and never counted. Under the reversed draft #NET-9068, which took the surplus
    off the end however it got there, a cap of two would have queued FW-0003 --
    a live rule -- while the dead one rode along inside the count.
    """
    _, summary, policy, queue = _probe([
        _rule("FW-0001", 10, src=("10.0.0.0/8",)),
        _rule("FW-0002", 20, src=("10.1.0.0/16",)),
        _rule("FW-0003", 30, src=("172.16.0.0/12",))],
        max_rules=2)
    assert [r["rule_id"] for r in policy] == [
        "FW-0001", "FW-0002", "FW-0003", "FW-DEFAULT"], (
        "a shadowed rule was counted against the cap, or was queued by it")
    assert queue == [], queue
    assert [r["shadowed"] for r in policy[:3]] == [False, True, False]
    # the policy carries more rows than the cap and is still inside it
    assert summary["compiled_count"] == 4
    assert summary["effective_max_rules"] == 2
    assert summary["shadowed_count"] == 1


def test_the_cap_queues_the_unshadowed_rules_past_it_and_no_shadowed_one():
    """Only what the device evaluates is shed, and the rest keeps its place."""
    rules = [
        _rule("FW-0001", 10, src=("10.0.0.0/8",)),
        _rule("FW-0002", 20, src=("10.1.0.0/16",)),
        _rule("FW-0003", 30, src=("172.16.0.0/12",)),
        _rule("FW-0004", 40, src=("192.0.2.0/24",)),
    ]
    _, summary, policy, queue = _probe(rules, max_rules=2)
    assert [r["rule_id"] for r in queue] == ["FW-0004"], (
        "the cap queued something other than the unshadowed rule past it")
    assert [(r["rule_id"], r["sequence"]) for r in policy] == [
        ("FW-0001", 10), ("FW-0002", 20), ("FW-0003", 30), ("FW-DEFAULT", 999000)], (
        "the rules that stayed did not keep the sequence they always had")
    assert summary["shadowed_count"] == 1


def test_the_cap_is_reached_on_the_unshadowed_rules_in_sequence_order():
    """A shadowed rule between two live ones does not move where the cap falls."""
    rules = [
        _rule("FW-0001", 10, src=("10.0.0.0/8",)),
        _rule("FW-0002", 20, src=("10.1.0.0/16",)),
        _rule("FW-0003", 30, src=("10.2.0.0/16",)),
        _rule("FW-0004", 40, src=("172.16.0.0/12",)),
        _rule("FW-0005", 50, src=("192.0.2.0/24",)),
    ]
    _, summary, policy, queue = _probe(rules, max_rules=2)
    assert summary["shadowed_count"] == 2, "the crafted base carries two shadowed rules"
    # FW-0001 and FW-0004 are the first two the device evaluates; FW-0005 is past
    # the cap, while the shadowed FW-0002 and FW-0003 stay where they are
    assert [r["rule_id"] for r in policy] == [
        "FW-0001", "FW-0002", "FW-0003", "FW-0004", "FW-DEFAULT"]
    assert [r["rule_id"] for r in queue] == ["FW-0005"]


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
    # /app is root-owned, so the run cannot replace this directory -- only empty
    # it, which is what the instruction and the contract ask for. The contents
    # are cleared here for the same reason.
    default_out = Path("/app/output")
    default_out.mkdir(parents=True, exist_ok=True)
    for stale in sorted(default_out.iterdir()):
        stale.unlink() if stale.is_file() or stale.is_symlink() else shutil.rmtree(stale)
    os.chmod(default_out, 0o777)
    # something for the run to clear, so the rule is exercised and not assumed
    (default_out / "left_behind.json").write_text("{}\n", encoding="utf-8")
    os.chmod(default_out / "left_behind.json", 0o666)
    (default_out / "scratch").mkdir()
    os.chmod(default_out / "scratch", 0o777)
    result = _run_agent([binary], cwd=_candidate_dir())
    assert result.returncode == 0, result.stderr
    assert sorted(q.name for q in default_out.iterdir()) == [
        'compiled_policy.json', 'exception_queue.jsonl', 'summary.json'], (
        "the run did not clear what an earlier run left in the output directory")
    _, summary, doc, queue = primary_outputs
    assert _load_json(default_out / "summary.json") == summary
    assert _digest(_load_json(default_out / "compiled_policy.json")) == _digest(doc)
    assert _digest(_load_jsonl(default_out / "exception_queue.jsonl")) == _digest(queue)


PROBED_PATHS = [
    "/logs/verifier/reward.txt",
    "/tests/fixtures/expected_report.json",
    "/tests/fixtures/contract_golden.json",
    "/tests/test_outputs.py",
]


def test_submitted_program_runs_unprivileged_and_cannot_reach_verifier_assets(tmp_path):
    """The graded program runs as nobody and can neither write the reward nor read the goldens.

    Separate mode keeps the sealed fixtures out of the agent's container, but this
    suite rebuilds the agent's source and runs it HERE, where those fixtures and
    /logs/verifier both exist. Dropping the uid is what stands between that process
    and them, so the probe reads as well as writes. Nothing here asserts a mode or
    an owner -- the builder assigns those -- only that the boundary holds.
    """
    probe = tmp_path / "main.go"
    probe.write_text(
        'package main\n\nimport ("fmt"; "os")\n\n'
        'func readable(p string) bool {\n'
        '\tf, err := os.Open(p)\n'
        '\tif err != nil {\n\t\treturn false\n\t}\n'
        '\tdefer f.Close()\n'
        '\tb := make([]byte, 1)\n'
        '\t_, err = f.Read(b)\n'
        '\treturn err == nil\n}\n\n'
        'func main() {\n\tfmt.Println(os.Getuid())\n'
        '\terr := os.WriteFile("/logs/verifier/reward.txt", []byte("1"), 0o644)\n'
        '\tfmt.Println(err != nil)\n'
        '\tfor _, p := range []string{\n'
        '\t\t"/logs/verifier/reward.txt",\n'
        '\t\t"/tests/fixtures/expected_report.json",\n'
        '\t\t"/tests/fixtures/contract_golden.json",\n'
        '\t\t"/tests/test_outputs.py",\n'
        '\t} {\n\t\tfmt.Println(p, readable(p))\n\t}\n}\n',
        encoding="utf-8")
    binary = _build(probe)
    result = _run_agent([binary], cwd=_candidate_dir())
    assert result.returncode == 0, (
        f"the probe exited {result.returncode}\n"
        f"stdout: {result.stdout[-2000:]}\nstderr: {result.stderr[-2000:]}")
    # Every line is read as written: filtering blanks out of captured output would
    # let a probe that printed nothing clear the reachability check, so the line
    # count is asserted and a blank line is a failure rather than something skipped.
    lines = result.stdout.split("\n")
    assert lines and lines[-1] == "", "the probe's output does not end in a newline"
    lines = lines[:-1]
    assert len(lines) == 2 + len(PROBED_PATHS), (
        f"the probe printed {len(lines)} lines, expected {2 + len(PROBED_PATHS)}: {lines!r}")
    assert lines[0] == str(CANDIDATE_UID), (
        f"the graded program ran as uid {lines[0]!r}, not {CANDIDATE_UID}")
    assert lines[1] == "true", "the graded program could write the reward file"
    reported = dict(line.rsplit(" ", 1) for line in lines[2:])
    assert sorted(reported) == sorted(PROBED_PATHS), (
        f"the probe did not report on every path: {sorted(reported)}")
    reachable = sorted(path for path, seen in reported.items() if seen == "true")
    assert reachable == [], (
        "code run the way the agent's program is run can read verifier-only "
        f"assets: {reachable}")


def test_this_suite_defines_every_test_name_once():
    """A repeated def silently discards the earlier body, and pytest says nothing.

    Two tests bound to one name leave the first never running, with no warning.
    This reads the module's own parse tree so the collision cannot go unnoticed.
    """
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    names = [node.name for node in tree.body if isinstance(node, ast.FunctionDef)]
    repeated = sorted({n for n in names if names.count(n) > 1})
    assert not repeated, (
        f"these names are defined more than once, so the earlier body never runs: {repeated}")


def test_the_compiler_is_one_go_source_compiled_from_that_file_alone():
    """instruction.md makes the deliverable that one Go source, built on its own.

    _build copies /app/workflow/compile_policy.go to a temporary directory and
    compiles it there, so a submission split across siblings fails with an
    undefined-symbol error that does not say why. This states the rule and names
    the siblings when the build fails. It does not ban them: nothing else in the
    directory can join a build that never sees the directory.
    """
    engine = WORKFLOW_PATH.resolve()
    # the go tool ignores sources whose name starts with "." or "_", so the frozen
    # copy beside the compiler is not a sibling in the sense that matters
    siblings = sorted(q.name for q in WORKFLOW_PATH.parent.glob("*.go")
                      if q.resolve() != engine and not q.name.startswith((".", "_")))
    try:
        _build(WORKFLOW_PATH)
    except AssertionError as exc:
        raise AssertionError(
            f"{WORKFLOW_PATH.name} does not compile on its own, as instruction.md "
            f"requires. Sibling sources beside it, which never join this build: "
            f"{siblings}\n\n{exc}") from exc


def test_a_run_writes_nothing_outside_its_output_directory():
    """instruction.md scopes a run to its --output-dir, and nothing checked it.

    Every other run here reads the artifacts by name, so a run that also dropped a
    scratch file beside them, or in the directory it was started from, satisfied
    all of them. This walks the whole work area afterwards.
    """
    binary = _build(WORKFLOW_PATH)
    _publish_inputs()
    work = _candidate_dir()
    out_dir = work / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o777)
    staged = work / "rules.json"
    _stage_input(RULES_PATH, staged)

    before = {str(q.relative_to(work)) for q in work.rglob("*")}
    result = _run_agent(
        [binary, "--input", str(staged), "--output-dir", str(out_dir)], cwd=work)
    assert result.returncode == 0, (
        f"the run exited {result.returncode}\n"
        f"stdout: {result.stdout[-2000:]}\nstderr: {result.stderr[-2000:]}")
    after = {str(q.relative_to(work)) for q in work.rglob("*")}
    written = sorted(after - before)
    expected = sorted("output/" + n for n in OUTPUT_FILES)
    assert written == expected, (
        f"the run wrote outside its output directory: {sorted(set(written) - set(expected))}")


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


# --------------------------------------------------------------------------
# #NET-9210: what an omitted policy field falls back to, and #NET-9198 at zero
# --------------------------------------------------------------------------
BASELINES = {"max_rules": 420, "port_ceiling": 65535,
             "max_shadow_lookback": 120, "default_deny_sequence": 999000}


def test_a_policy_that_omits_every_field_keeps_all_four_baselines():
    """#NET-9210 names a baseline per field; an empty policy takes all of them.

    A compiler that read each setting straight out of the map and never fell
    back passed every other probe here, because they all write all four fields
    and the shipped policy carries all four. A missing key in Go reads as zero,
    which would cap the policy at nothing, clamp every port to nought and put
    the closing deny at sequence zero, so this run separates the two readings on
    four counts at once.
    """
    rules = [_rule("FW-0001", 10), _rule("FW-0002", 20, lo=1000, hi=2000)]
    _, summary, policy, queue = _probe(rules, omit=tuple(BASELINES))
    assert {k: summary[f"effective_{n}"] for k, n in (
        ("max_rules", "max_rules"), ("port_ceiling", "port_ceiling"),
        ("max_shadow_lookback", "shadow_lookback"),
        ("default_deny_sequence", "default_deny_sequence"))} == BASELINES, summary
    # and the baselines are what the run actually used, not merely what it echoed
    assert [r["rule_id"] for r in policy] == ["FW-0001", "FW-0002", "FW-DEFAULT"], (
        "an omitted max_rules capped the policy rather than falling back to 420")
    assert policy[-1]["sequence"] == 999000
    assert policy[-1]["port_high"] == 65535, (
        "an omitted port_ceiling clamped the closing deny to nought")
    assert [r["port_high"] for r in policy[:2]] == [80, 2000], (
        "an omitted port_ceiling clamped the operator's own ranges away")
    assert queue == []


def test_each_policy_field_falls_back_on_its_own():
    """One field left out at a time, so no fallback hides behind another.

    Omitting all four together would pass a compiler that fell back on only one
    of them and read zero for the rest, provided nothing in the run depended on
    the other three.
    """
    rules = [_rule("FW-0001", 10), _rule("FW-0002", 20, lo=1000, hi=2000)]
    for field, baseline in BASELINES.items():
        _, summary, policy, _ = _probe(rules, omit=(field,))
        name = "shadow_lookback" if field == "max_shadow_lookback" else field
        assert summary[f"effective_{name}"] == baseline, (
            f"{field} left out of the policy did not fall back to {baseline}: {summary}")
        assert [r["rule_id"] for r in policy] == [
            "FW-0001", "FW-0002", "FW-DEFAULT"], (field, policy)


def test_a_max_rules_of_zero_is_a_cap_of_zero_and_not_an_absent_cap():
    """#NET-9198 names no minimum and no reading under which nought means no cap.

    #NET-9210 has an OMITTED field fall back to 420, so a policy that carries a
    zero meant the zero: every operator rule leaves the policy and is queued,
    and the closing deny is emitted anyway, never having counted against the cap.
    """
    rules = [_rule("FW-0001", 10, src=("10.0.0.0/8",)),
             _rule("FW-0002", 20, src=("172.16.0.0/12",))]
    _, summary, policy, queue = _probe(rules, max_rules=0)
    assert summary["effective_max_rules"] == 0
    assert [r["rule_id"] for r in policy] == ["FW-DEFAULT"], (
        "a cap of zero was read as no cap at all")
    assert [(r["rule_id"], r["reason"]) for r in queue] == [
        ("FW-0001", "over_cap"), ("FW-0002", "over_cap")]
    assert summary["compiled_count"] == 1 and summary["deny_count"] == 1
    assert summary["total_source_addresses"] == 0, (
        "the closing deny's own span reached the operator total")
