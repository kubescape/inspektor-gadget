#!/usr/bin/env python3
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0
"""Validate returned VM artifacts, distinguishing mutant kills from failures."""
import argparse
import json
import pathlib
import re

KERNELS = {
    "al2023-k612": "6.12.113-138.209.amzn2023.x86_64",
    "al2023-k618": "6.18.56-125.164.amzn2023.x86_64",
    "debian12": "6.1.0-54-amd64",
}
CASES = ["graceful", "sigkill", "partial-move", "abi-skew", "cgroup-exit",
         "selfexec", "thread-selfexec", "failed-selfexec", "uninstall",
         "load-failure", "nonce", "mixed-mode"]
KILLS = {
    "no-exit-arm": r"FAIL sigkill: (?:.*target=denied errno=0 want=1|live incarnation=[1-9][0-9]* want=0)",
    "no-nonce": r"FAIL nonce: unauthorized nonce changed live owner: live incarnation=[1-9][0-9]* want=0",
    "never-move": r"FAIL graceful: target=allowed errno=1 want=0 policy=0",
    "restart-lift": r"FAIL graceful: .*target=denied errno=0 want=1",
}
MIXED_TRANSITIONS = (
    ("omitted-retained", "owner-down"),
    ("recovered-mixed", "refenced-before-backend-withdraw"),
    ("refenced-before-backend-withdraw", "backend-withdrawn-still-fenced"),
)


def verify_transition_coverage(events, probe_rows, expected_transitions, expected_probes, phase_pairs=()):
    starts = [(i, e["value"]) for i, e in enumerate(events) if e["event"] == "transition-start"]
    ends = [(i, e["value"]) for i, e in enumerate(events) if e["event"] == "transition-end"]
    assert len(starts) == len(ends) == expected_transitions, "missing transition lifecycle bounds"
    previous_pos, previous_time = -1, 0
    for t, ((start_pos, start), (end_pos, end)) in enumerate(zip(starts, ends)):
        assert previous_pos < start_pos < end_pos, "out-of-order transition lifecycle events"
        assert 0 < start < end and previous_time <= start, "invalid transition action interval"
        previous_pos, previous_time = end_pos, end
        if phase_pairs:
            (before_pos, before), (after_pos, after) = phase_pairs[t]
            assert (before_pos < start_pos < end_pos < after_pos
                    and before["monotonic_ns"] <= start < end <= after["monotonic_ns"]), (
                "transition outside its mixed lifecycle phases"
            )
    covers = [(i, e["value"]) for i, e in enumerate(events) if e["event"] == "transition-coverage"]
    expected_keys = {(t, p) for t in range(expected_transitions) for p in expected_probes}
    assert len(covers) == len(expected_keys), "missing or extra transition coverage"
    seen = set()
    for pos, c in covers:
        key = (c["transition"], c["probe"])
        assert key in expected_keys and key not in seen, f"unexpected or duplicate coverage {key}"
        seen.add(key)
        t = c["transition"]
        start_pos, start = starts[t]
        end_pos, end = ends[t]
        assert start_pos < pos < end_pos, "coverage outside its transition lifecycle events"
        rows = probe_rows[c["probe"]]
        start_idx, end_idx = c["start_index"], c["end_index"]
        assert 0 <= start_idx < end_idx <= len(rows), "coverage index out of range"
        assert end_idx - start_idx == c["samples"] >= 400, "insufficient transition observations"
        assert rows[start_idx]["start_ns"] == c["first_ns"], "coverage start_ns mismatch"
        assert rows[end_idx - 1]["end_ns"] == c["last_ns"], "coverage last_ns mismatch"
        assert c["action_start_ns"] == start, "coverage action_start_ns mismatch"
        assert c["action_end_ns"] == end, "coverage action_end_ns mismatch"
        assert c["first_ns"] < start < end < c["last_ns"], "observations do not bracket the action"
        if phase_pairs:
            (_, before), (_, after) = phase_pairs[t]
            i = c["probe"]
            assert before["value"]["ends"][i] <= start_idx < end_idx <= after["value"]["starts"][i], (
                "transition observations outside their mixed lifecycle phases"
            )
        assert any(
            0 < start <= row["start_ns"] < row["end_ns"] <= end
            for row in rows[start_idx:end_idx]
        ), f"no raw observation contained in transition {t} for probe {c['probe']}"
    assert seen == expected_keys, "missing transition coverage"
    return len(covers)


def validate_batch_sequence(rows, start, end, label):
    batch = rows[start:end]
    assert len(batch) == 200, f"{label} batch size"
    batch_id = batch[0]["batch"]
    assert type(batch_id) is int and batch_id > 0, f"{label} batch identity"
    if start:
        assert rows[start - 1]["batch"] < batch_id, f"{label} batch ordering"
    if end < len(rows):
        assert batch_id < rows[end]["batch"], f"{label} batch ordering"
    for j, row in enumerate(batch):
        assert (type(row["batch"]) is int and row["batch"] == batch_id
                and type(row["sample"]) is int and row["sample"] == j // 2
                and 0 < row["start_ns"] < row["end_ns"]), f"{label} batch identity"
        assert row["target"] == ("denied" if j % 2 == 0 else "allowed"), f"{label} targets"


def validate_mixed_accounting(events, probe_rows, phases):
    owners = [(i, e) for i, e in enumerate(events) if e["event"] == "owner-start"]
    incarnations = [e["value"]["incarnation"] for _, e in owners]
    assert len(owners) == 2 and 0 < incarnations[0] < incarnations[1], "missing successor proof"
    assert (owners[0][0] < phases["live-mixed"][0]
            < phases["owner-down"][0] < owners[1][0] < phases["partial-child-move"][0]), "owner outside mixed lifecycle"

    def one(name, value):
        matches = [(i, e) for i, e in enumerate(events) if e["event"] == name and e["value"] == value]
        assert len(matches) == 1, f"missing or duplicate {name}"
        return matches[0]

    refenced = one("mixed-refenced", 1)
    acknowledged = one("mixed-accounting-acknowledged", 0)
    moves = [(i, e) for i, e in enumerate(events) if e["event"] == "protected-moved" and i > owners[1][0]]
    assert [e["value"] for _, e in moves] == [0, 1, 2], "invalid successor move ordering"
    assert (phases["partial-child-move"][0] < moves[1][0] < moves[2][0]
            < acknowledged[0] < phases["recovered-mixed"][0]), "acknowledgment outside recovery"
    assert moves[1][1]["monotonic_ns"] <= moves[2][1]["monotonic_ns"] <= acknowledged[1]["monotonic_ns"]
    transition = next((i, {"monotonic_ns": e["value"]}) for i, e in enumerate(events)
                      if e["event"] == "transition-start")
    # (batch, probe, live owner, Audit, lower event, upper event, bounding phases)
    expected = (
        ("same-owner-unbound", 1, incarnations[0], False, refenced, transition, "omitted-retained", "owner-down", 100, 0),
        ("owner-down-audit", 2, 0, True, phases["owner-down"], owners[1], "owner-down", "partial-child-move", 200, 200),
        ("owner-down-nested-audit", 5, 0, True, phases["owner-down"], owners[1], "owner-down", "partial-child-move", 200, 200),
        ("inherited-unbound", 1, incarnations[1], False, owners[1], moves[0], "owner-down", "partial-child-move", 200, 200),
        ("unreconciled-fallback-after-one-move", 4, incarnations[1], False, moves[0], phases["partial-child-move"], "owner-down", "partial-child-move", 200, 200),
        ("acknowledged-fallback-remains-fenced", 4, incarnations[1], False, acknowledged, phases["recovered-mixed"], "partial-child-move", "recovered-mixed", 200, 0),
    )
    assert (phases["omitted-retained"][0] < refenced[0] < transition[0]
            and phases["omitted-retained"][1]["monotonic_ns"] <= refenced[1]["monotonic_ns"]), "refence outside same-owner phase"
    accounting = [(i, e) for i, e in enumerate(events) if e["event"] == "mixed-accounting"]
    assert len(accounting) == len(expected), "missing mixed accounting proof"
    fields = ("Denied", "Audit", "Lost", "OutageDenied", "OutageAudit", "OutageLost")
    last_end = 0
    for (pos, event), (name, probe, incarnation, audit, lower, upper, before_phase, after_phase, count, outage) in zip(accounting, expected):
        value = event["value"]
        assert (value["name"], value["probe"], value["before_incarnation"], value["incarnation"]) == (name, probe, incarnation, incarnation), "accounting owner changed"
        bs, be, a_s, ae = (value[k] for k in ("before_snapshot_start_ns", "before_snapshot_end_ns",
                                               "after_snapshot_start_ns", "after_snapshot_end_ns"))
        assert (lower[0] < pos < upper[0]
                and 0 < lower[1]["monotonic_ns"] <= bs <= be < a_s <= ae <= event["monotonic_ns"]
                <= upper[1]["monotonic_ns"] and last_end <= bs), f"accounting outside lifecycle bounds for {name}"
        last_end = ae
        rows = probe_rows[probe]
        start, end = value["start_index"], value["end_index"]
        assert (0 <= start < end <= len(rows) and end-start == 200
                and phases[before_phase][1]["value"]["ends"][probe] <= start
                and end <= phases[after_phase][1]["value"]["starts"][probe]), f"accounting probe bounds for {name}"
        batch = rows[start:end]
        assert be <= batch[0]["start_ns"] < batch[-1]["end_ns"] <= a_s, f"accounting snapshot bounds for {name}"
        validate_batch_sequence(rows, start, end, f"accounting {name}")
        for row in batch:
            assert row["errno"] == (0 if audit else 1), f"accounting verdict for {name}"
        for other, stream in enumerate(probe_rows):
            outside = stream[:start] + stream[end:] if other == probe else stream
            assert all(r["end_ns"] <= bs or ae <= r["start_ns"] for r in outside), f"nonisolated accounting batch {name}"
        before, after = value["before"], value["after"]
        assert all(type(v[k]) is int and v[k] >= 0 for v in (before, after) for k in fields)
        delta = {k: after[k] - before[k] for k in fields}
        want = dict.fromkeys(fields, 0)
        want["Audit" if audit else "Denied"] = count
        want["OutageAudit" if audit else "OutageDenied"] = outage
        assert delta == want, f"incorrect counter deltas for {name}"


def validate_mixed(root, events):
    indexed_phases = [(i, e) for i, e in enumerate(events) if e["event"] == "mixed-phase"]
    phases = [e for _, e in indexed_phases]
    expected = {
        "live-mixed": [0, 0, 3, 3, 1, 3],
        "omitted-retained": [0, 0, 3, 3, 1, 3],
        "owner-down": [1, 1, 3, 3, 1, 3],
        "partial-child-move": [0, 1, 3, 3, 1, 3],
        "recovered-mixed": [0, 0, 3, 3, 1, 3],
        "refenced-before-backend-withdraw": [1, 0, 3, 3, 1, 3],
        "backend-withdrawn-still-fenced": [1, 0, 3, 3, 1, 3],
        "authorized-child-off": [3, 0, 3, 3, 1, 3],
        "all-known-off-unknown-fenced": [3, 3, 3, 3, 1, 3],
        "authorized-scope-inactive": [3, 3, 3, 3, 3, 3],
    }
    assert [p["value"]["name"] for p in phases] == list(expected), "missing mixed phases"
    assert sum(e["event"] == "mixed-withdrawal-attested" for e in events) == 1
    assert not any(e["event"] == "uninstall-retired" for e in events)
    probe_rows = []
    for i in range(6):
        raw = [json.loads(line) for line in (root / f"probe-{i}.jsonl").read_text().splitlines()]
        assert raw[0]["ready_pid"] > 0
        probe_rows.append(raw[1:])
    phase_index = {e["value"]["name"]: (i, e) for i, e in indexed_phases}
    phase_pairs = [(phase_index[before], phase_index[after]) for before, after in MIXED_TRANSITIONS]
    verify_transition_coverage(events, probe_rows, len(MIXED_TRANSITIONS), range(6), phase_pairs)
    validate_mixed_accounting(events, probe_rows, phase_index)
    for event in events:
        if event["event"] != "transition-coverage":
            continue
        coverage = event["value"]
        if (coverage["transition"], coverage["probe"]) in ((0, 1), (2, 0)):
            rows = probe_rows[coverage["probe"]]
            assert all(row["errno"] == 1 for row in rows[coverage["start_index"]:coverage["end_index"]]), (
                "already-fenced transition allowed an exec"
            )
    boundaries = [e for e in events if e["event"] == "mixed-off-boundary"]
    strict_probes = (0, 1, 4)
    assert [e["value"]["probe"] for e in boundaries] == list(strict_probes), (
        "missing or invalid authorized Off boundaries"
    )
    off_boundary = dict(zip(strict_probes, boundaries))
    total = 0
    for i in range(6):
        rows = probe_rows[i]
        cutoff = 0
        if i in off_boundary:
            boundary = off_boundary[i]
            cutoff = boundary["value"]["observed"]
            first_off = next(j for j, p in enumerate(phases) if expected[p["value"]["name"]][i] == 3)
            previous, off_phase = phases[first_off - 1], phases[first_off]
            moment = boundary["monotonic_ns"]
            assert 0 < cutoff < len(rows) and (
                previous["value"]["ends"][i] <= cutoff == off_phase["value"]["starts"][i]
                and previous["monotonic_ns"] <= moment < off_phase["monotonic_ns"]
                and rows[cutoff - 1]["end_ns"] <= moment <= rows[cutoff]["start_ns"]
            ), f"invalid authorized Off boundary for child {i}"
        last_end = 0
        for j, r in enumerate(rows):
            assert r["target"] in ("allowed", "denied")
            assert r["start_ns"] > 0 and r["end_ns"] >= r["start_ns"]
            assert r["start_ns"] >= last_end, "out-of-order mixed observation"
            last_end = r["end_ns"]
            assert r["signal"] == 0 and r["errno"] in (0, 1)
            assert r["exit"] == (100 if r["errno"] else 0)
            if i in (2, 3, 5):
                assert r["errno"] == 0, "Audit/Off descendant blocked"
            if j < cutoff and (i == 4 or r["target"] == "denied"):
                assert r["errno"] == 1, f"denied-path exec succeeded before authorized Off for child {i}"
        last_end = 0
        for event in phases:
            phase = event["value"]
            assert phase["policies"] == expected[phase["name"]]
            start, end = phase["starts"][i], phase["ends"][i]
            assert last_end <= start and end - start == 200 and end <= len(rows)
            assert rows[end - 1]["end_ns"] <= event["monotonic_ns"], "mixed phase observed after its event"
            last_end = end
            validate_batch_sequence(rows, start, end, f"mixed {phase['name']} child {i}")
            policy = expected[phase["name"]][i]
            for r in rows[start:end]:
                want = int(policy == 1 or (policy == 0 and r["target"] == "denied"))
                assert r["errno"] == want, f"mixed {phase['name']} child {i}: {r}"
        total += len(rows)
    return total


def validate(root, variant):
    manifest = json.loads((root / "run-manifest.json").read_text())
    assert manifest["distro"] in KERNELS, "unexpected distro"
    assert manifest["guest_uname_r"] == KERNELS[manifest["distro"]], "wrong kernel"
    assert manifest["accel"] == "kvm", "not KVM"
    assert manifest["timed_out"] == 0, "VM timed out"
    guest = root / "guest"
    log = (guest / "oracle.log").read_text()
    assert "SKIP" not in log, "SKIP is failure"
    code = int((guest / "oracle.exit").read_text())
    assert int((guest / "payload.exit").read_text()) == manifest["exit_code"], "payload exit mismatch"
    if variant != "baseline":
        assert variant in KILLS, "unknown mutant"
        assert manifest["exit_code"] == code == 1, "mutant failed outside behavioral oracle"
        match = re.search(KILLS[variant], log)
        assert match, f"not an expected {variant} kill: {log}"
        return {"variant": variant, "kernel": manifest["guest_uname_r"],
                "expected_mutant_failure": True, "assertion": match.group(0)}
    assert manifest["exit_code"] == code == 0, "nonzero baseline exit"
    assert log.splitlines() == [f"PASS {name}" for name in CASES], "missing/extra baseline result"
    total = 0
    coverage = 0
    for case in CASES:
        events = [json.loads(line) for line in (guest / case / "lifecycle.jsonl").read_text().splitlines()]
        if case == "mixed-mode":
            total += validate_mixed(guest / case, events)
            coverage += len(MIXED_TRANSITIONS) * 6
            continue
        retire = next((e["monotonic_ns"] for e in events if e["event"] == "uninstall-retired"), None)
        assert (retire is not None) == (case == "uninstall"), "unexpected retirement"
        probe_rows = []
        for index in range(4):
            rows = [json.loads(line) for line in (guest / case / f"probe-{index}.jsonl").read_text().splitlines()]
            assert rows[0]["ready_pid"] > 0, "probe never ready"
            assert len(rows) >= 601, "insufficient observations"
            probe_rows.append(rows[1:])
        coverage += verify_transition_coverage(events, probe_rows, 2 if case == "partial-move" else 1, range(4))
        assert sum(e["event"] == "outage-counters-attested" for e in events) == 1, "counter assertion absent"
        for index, rows in enumerate(probe_rows):
            for row in rows:
                assert row["start_ns"] <= row["end_ns"] and row["signal"] == 0, "invalid observation"
                assert row["errno"] in (0, 1), "unexpected errno"
                assert row["exit"] == (100 if row["errno"] else 0), "observation failure"
                if index == 3:
                    assert row["errno"] == 0, "Audit blocked"
                elif row["target"] == "denied" and row["errno"] == 0:
                    assert retire is not None and row["start_ns"] > retire, "denied exec succeeded before uninstall"
                total += 1
    return {"variant": variant, "kernel": manifest["guest_uname_r"], "cases_passed": len(CASES),
            "observations": total, "transition_coverage_records": coverage,
            "unexpected_denied_successes": 0, "audit_blocks": 0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("row", type=pathlib.Path)
    parser.add_argument("--variant", default="baseline", choices=["baseline", *KILLS])
    args = parser.parse_args()
    print(json.dumps(validate(args.row, args.variant), indent=2))
