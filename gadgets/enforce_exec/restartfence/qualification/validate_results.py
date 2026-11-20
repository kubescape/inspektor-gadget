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
            0 < row["start_ns"] < row["end_ns"] and row["start_ns"] < end and start < row["end_ns"]
            for row in rows[start_idx:end_idx]
        ), f"no raw observation overlaps transition {t} for probe {c['probe']}"
    assert seen == expected_keys, "missing transition coverage"
    return len(covers)


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
    incarnations = [e["value"]["incarnation"] for e in events if e["event"] == "owner-start"]
    assert len(incarnations) == 2 and 0 < incarnations[0] < incarnations[1], "missing successor proof"
    accounting = [e["value"] for e in events if e["event"] == "mixed-accounting"]
    expected_accounting = (
        ("same-owner-unbound", 1, incarnations[0], 100, 0),
        ("inherited-unbound", 1, incarnations[1], 200, 200),
        ("unreconciled-fallback-after-one-move", 4, incarnations[1], 200, 200),
        ("acknowledged-fallback-remains-fenced", 4, incarnations[1], 200, 0),
    )
    assert len(accounting) == len(expected_accounting), "missing mixed accounting proof"
    for value, (name, probe, incarnation, want_denied, want_outage) in zip(accounting, expected_accounting):
        assert (value["name"], value["probe"], value["incarnation"]) == (name, probe, incarnation)
        before, after = value["before"], value["after"]
        denied = after["Denied"] - before["Denied"]
        outage_denied = after["OutageDenied"] - before["OutageDenied"]
        assert (denied, outage_denied) == (want_denied, want_outage), f"incorrect counter deltas for {name}"
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
