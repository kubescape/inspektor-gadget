#!/usr/bin/env python3
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0
"""Pure host tests for archived mixed-mode evidence, with no kernel activity."""
import json
import unittest

from validate_results import validate_mixed, verify_transition_coverage


class InMemoryEvidence:
    def __init__(self, streams):
        self.streams = streams

    def __truediv__(self, name):
        return self.streams[name]


class Stream:
    def __init__(self, rows):
        self.rows = rows

    def read_text(self):
        return "\n".join(json.dumps(row) for row in self.rows)


def mixed_evidence():
    phases = (
        ("live-mixed", [0, 0, 3, 3, 1, 3]),
        ("omitted-retained", [0, 0, 3, 3, 1, 3]),
        ("owner-down", [1, 1, 3, 3, 1, 3]),
        ("partial-child-move", [0, 1, 3, 3, 1, 3]),
        ("recovered-mixed", [0, 0, 3, 3, 1, 3]),
        ("refenced-before-backend-withdraw", [1, 0, 3, 3, 1, 3]),
        ("backend-withdrawn-still-fenced", [1, 0, 3, 3, 1, 3]),
        ("authorized-child-off", [3, 0, 3, 3, 1, 3]),
        ("all-known-off-unknown-fenced", [3, 3, 3, 3, 1, 3]),
        ("authorized-scope-inactive", [3, 3, 3, 3, 3, 3]),
    )
    streams = {f"probe-{i}.jsonl": Stream([{"ready_pid": i + 1}]) for i in range(6)}
    rows = [stream.rows for stream in streams.values()]
    events = []
    clock = 10

    def event(name, value):
        nonlocal clock
        events.append(dict(event=name, monotonic_ns=clock, value=value))
        clock += 10

    def append_batch(modes, count, probes=range(6)):
        nonlocal clock
        for i in probes:
            mode = modes[i]
            batch_id = len(rows[i])
            for j in range(count):
                target = "denied" if j % 2 == 0 else "allowed"
                errno = int(mode == 1 or (mode == 0 and target == "denied"))
                ts = clock + j * 10
                rows[i].append(dict(target=target, batch=batch_id, sample=j//2, start_ns=ts, end_ns=ts + 1, signal=0,
                                    exit=100 * errno, errno=errno))
        clock += count * 10

    def accounting(name, probe, inc, audit, count, outage):
        nonlocal clock
        bs, be = clock, clock + 1
        clock += 10
        start = len(rows[probe]) - 1
        append_batch([3 if audit else 1] * 6, 200, (probe,))
        a_s, ae = clock, clock + 1
        clock += 10
        before = dict(Denied=412, Audit=200, Lost=0, OutageDenied=251, OutageAudit=100, OutageLost=0)
        after = dict(before)
        after["Audit" if audit else "Denied"] += count
        after["OutageAudit" if audit else "OutageDenied"] += outage
        event("mixed-accounting", dict(name=name, probe=probe, before_incarnation=inc, incarnation=inc, before=before, after=after,
                                       start_index=start, end_index=start+200,
                                       before_snapshot_start_ns=bs, before_snapshot_end_ns=be,
                                       after_snapshot_start_ns=a_s, after_snapshot_end_ns=ae))

    event("owner-start", dict(incarnation=1))
    for i in range(3):
        event("protected-moved", i)
    inject_at = None
    for phase, (name, modes) in enumerate(phases):
        if phase == 2:
            event("mixed-refenced", 1)
            accounting("same-owner-unbound", 1, 1, False, 100, 0)
        if phase == 3:
            accounting("owner-down-audit", 2, 0, True, 200, 200)
            accounting("owner-down-nested-audit", 5, 0, True, 200, 200)
            event("owner-start", dict(incarnation=2))
            accounting("inherited-unbound", 1, 2, False, 200, 200)
            event("protected-moved", 0)
            accounting("unreconciled-fallback-after-one-move", 4, 2, False, 200, 200)
        if phase == 4:
            event("protected-moved", 1)
            event("protected-moved", 2)
            event("mixed-accounting-acknowledged", 0)
            accounting("acknowledged-fallback-remains-fenced", 4, 2, False, 200, 0)
        if phase in (2, 5, 6):
            t = (2, 5, 6).index(phase)
            starts = [len(r)-1 for r in rows]
            if t == 0:
                inject_at = starts[0] + 1
            action_start, action_end = clock + 20, clock + 3981
            append_batch([0, 0, 3, 3, 1, 3], 400)
            event("transition-start", action_start)
            for i in range(6):
                event("transition-coverage", dict(
                    transition=t, probe=i, start_index=starts[i], end_index=starts[i]+400,
                    first_ns=rows[i][1 + starts[i]]["start_ns"], action_start_ns=action_start,
                    action_end_ns=action_end, last_ns=rows[i][-1]["end_ns"], samples=400))
            event("transition-end", action_end)
        starts = [len(r)-1 for r in rows]
        boundary_probe = {7: 0, 8: 1, 9: 4}.get(phase)
        if boundary_probe is not None:
            event("mixed-off-boundary", dict(probe=boundary_probe, observed=starts[boundary_probe]))
        append_batch(modes, 200)
        event("mixed-phase", dict(name=name, policies=modes, starts=starts, ends=[n+200 for n in starts]))

    event("mixed-withdrawal-attested", {})
    return InMemoryEvidence(streams), events, rows, inject_at


class MixedEvidenceTest(unittest.TestCase):
    def test_valid_transition_and_off_observations(self):
        root, events, rows, _ = mixed_evidence()
        self.assertEqual(validate_mixed(root, events), sum(len(r) - 1 for r in rows))

    def test_denied_path_success_in_transition_is_flagged(self):
        root, events, rows, index = mixed_evidence()
        self.assertEqual(rows[0][index]["target"], "denied")
        rows[0][index].update(errno=0, exit=0)
        with self.assertRaisesRegex(AssertionError, "before authorized Off"):
            validate_mixed(root, events)

    def test_missing_off_authorization_boundary_is_flagged(self):
        root, events, _, _ = mixed_evidence()
        events = [e for e in events if e["event"] != "mixed-off-boundary"]
        with self.assertRaisesRegex(AssertionError, "authorized Off boundaries"):
            validate_mixed(root, events)

    def test_premature_off_boundary_is_flagged(self):
        root, events, _, index = mixed_evidence()
        boundary = next(e for e in events if e["event"] == "mixed-off-boundary")
        boundary["value"]["observed"] = index - 1
        with self.assertRaisesRegex(AssertionError, "invalid authorized Off boundary"):
            validate_mixed(root, events)

    def test_missing_accounting_evidence_is_flagged(self):
        root, events, _, _ = mixed_evidence()
        events = [e for e in events if e["event"] != "mixed-accounting"]
        with self.assertRaisesRegex(AssertionError, "missing mixed accounting proof"):
            validate_mixed(root, events)

    def test_incorrect_phase_counter_deltas_are_flagged(self):
        for phase, increment, outage in ((0, 200, 0), (3, 100, 100), (4, 100, 100),
                                         (5, 100, 0), (5, 201, 0), (5, 200, 1)):
            with self.subTest(phase=phase, increment=increment, outage=outage):
                root, events, _, _ = mixed_evidence()
                accounting = [e["value"] for e in events if e["event"] == "mixed-accounting"][phase]
                accounting["after"].update(Denied=412 + increment, OutageDenied=251 + outage)
                with self.assertRaisesRegex(AssertionError, "incorrect counter deltas"):
                    validate_mixed(root, events)

    def test_probe4_allowed_success_before_off_is_flagged(self):
        root, events, rows, index = mixed_evidence()
        allowed_row = rows[4][index + 1]
        self.assertEqual(allowed_row["target"], "allowed")
        allowed_row.update(errno=0, exit=0)
        with self.assertRaisesRegex(AssertionError, "before authorized Off"):
            validate_mixed(root, events)

    def test_duplicate_or_mismatched_transition_coverage_is_flagged(self):
        root, events, _, _ = mixed_evidence()
        covers = [e for e in events if e["event"] == "transition-coverage"]
        covers[1]["value"] = dict(covers[0]["value"])
        with self.assertRaisesRegex(AssertionError, "duplicate coverage"):
            validate_mixed(root, events)
        root, events, _, _ = mixed_evidence()
        cover = next(e for e in events if e["event"] == "transition-coverage")
        cover["value"]["first_ns"] -= 1
        with self.assertRaisesRegex(AssertionError, "coverage start_ns mismatch"):
            validate_mixed(root, events)
        root, events, _, _ = mixed_evidence()
        cover = next(e for e in events if e["event"] == "transition-coverage")
        cover["value"]["action_start_ns"] += 1
        with self.assertRaisesRegex(AssertionError, "coverage action_start_ns mismatch"):
            validate_mixed(root, events)

    def test_transition_outside_named_lifecycle_pair_is_flagged(self):
        root, events, _, _ = mixed_evidence()
        bounds = [e for e in events if e["event"].startswith("transition-")]
        other = [e for e in events if not e["event"].startswith("transition-")]
        with self.assertRaisesRegex(AssertionError, "outside its mixed lifecycle phases"):
            validate_mixed(root, other + bounds)
        phase = next(e for e in events if e["event"] == "mixed-phase"
                     and e["value"]["name"] == "owner-down")
        phase["monotonic_ns"] = next(e["value"] for e in events if e["event"] == "transition-start")
        with self.assertRaisesRegex(AssertionError, "outside its mixed lifecycle phases"):
            validate_mixed(root, events)

    def test_mixed_transition_cannot_borrow_another_phases_stream_slice(self):
        root, events, rows, _ = mixed_evidence()
        cover = next(e["value"] for e in events if e["event"] == "transition-coverage")
        cover["start_index"] -= 1
        cover["first_ns"] = rows[cover["probe"]][cover["start_index"] + 1]["start_ns"]
        cover["samples"] += 1
        with self.assertRaisesRegex(AssertionError, "observations outside their mixed lifecycle phases"):
            validate_mixed(root, events)

    def test_accounting_cannot_precede_its_lifecycle(self):
        root, events, _, _ = mixed_evidence()
        batches = [e for e in events if e["event"] == "mixed-accounting"]
        events = batches + [e for e in events if e["event"] != "mixed-accounting"]
        with self.assertRaisesRegex(AssertionError, "accounting outside lifecycle"):
            validate_mixed(root, events)

    def test_successor_cannot_precede_owner_down(self):
        root, events, _, _ = mixed_evidence()
        successor = [e for e in events if e["event"] == "owner-start"][1]
        events.remove(successor)
        events.insert(1, successor)
        with self.assertRaisesRegex(AssertionError, "owner outside mixed lifecycle"):
            validate_mixed(root, events)

    def test_snapshot_bounds_and_batch_indices_are_checked(self):
        for field in ("before_snapshot_end_ns", "after_snapshot_start_ns", "start_index"):
            with self.subTest(field=field):
                root, events, _, _ = mixed_evidence()
                batch = next(e["value"] for e in events if e["event"] == "mixed-accounting")
                batch[field] += 100000
                with self.assertRaises(AssertionError):
                    validate_mixed(root, events)

    def test_accounting_snapshot_owner_must_remain_exact(self):
        root, events, _, _ = mixed_evidence()
        batch = next(e["value"] for e in events if e["event"] == "mixed-accounting")
        batch["before_incarnation"] += 1
        with self.assertRaisesRegex(AssertionError, "accounting owner changed"):
            validate_mixed(root, events)

    def test_accounting_cannot_splice_probe_batches(self):
        for field, value in (("batch", 0), ("batch", 999999), ("sample", 99)):
            with self.subTest(field=field, value=value):
                root, events, rows, _ = mixed_evidence()
                batch = next(e["value"] for e in events if e["event"] == "mixed-accounting")
                rows[batch["probe"]][batch["start_index"] + 2][field] = value
                with self.assertRaisesRegex(AssertionError, "accounting batch identity"):
                    validate_mixed(root, events)

    def test_audit_cannot_be_off_or_unattributed(self):
        for name in ("owner-down-audit", "owner-down-nested-audit"):
            for field in ("Audit", "OutageAudit", "Lost", "OutageLost", "Denied"):
                with self.subTest(name=name, field=field):
                    root, events, _, _ = mixed_evidence()
                    batch = next(e["value"] for e in events if e["event"] == "mixed-accounting" and e["value"]["name"] == name)
                    batch["after"][field] += 1
                    with self.assertRaisesRegex(AssertionError, "incorrect counter deltas"):
                        validate_mixed(root, events)

    def test_acknowledgment_cannot_follow_its_accounting(self):
        root, events, _, _ = mixed_evidence()
        ack = next(e for e in events if e["event"] == "mixed-accounting-acknowledged")
        events.remove(ack)
        batch = next(e for e in events if e["event"] == "mixed-accounting" and e["value"]["name"] == "acknowledged-fallback-remains-fenced")
        events.insert(events.index(batch)+1, ack)
        with self.assertRaisesRegex(AssertionError, "accounting outside lifecycle"):
            validate_mixed(root, events)

    def test_straddling_or_spanning_interval_is_not_containment(self):
        for interval in ((1000, 1002), (1009, 1011), (1000, 1011), (1005, 1005)):
            with self.subTest(interval=interval):
                rows = [[dict(start_ns=10*i, end_ns=10*i+1) for i in range(1, 401)]]
                rows[0][100].update(start_ns=interval[0], end_ns=interval[1])
                events = [dict(event="transition-start", value=1001),
                          dict(event="transition-coverage", value=dict(
                              transition=0, probe=0, start_index=0, end_index=400,
                              first_ns=10, last_ns=4001, action_start_ns=1001,
                              action_end_ns=1010, samples=400)),
                          dict(event="transition-end", value=1010)]
                with self.assertRaisesRegex(AssertionError, "no raw observation contained"):
                    verify_transition_coverage(events, rows, 1, range(1))

    def test_one_nonoverlapping_probe_invalidates_transition_evidence(self):
        rows = [[dict(start_ns=10 * i, end_ns=10 * i + 1) for i in range(1, 401)] for _ in range(2)]
        start, end = 1001, 1010
        rows[0][100].update(start_ns=1002, end_ns=1003)  # Only probe 0 is contained.
        covers = [dict(event="transition-coverage", value=dict(
            transition=0, probe=i, start_index=0, end_index=400, first_ns=10, last_ns=4001,
            action_start_ns=start, action_end_ns=end, samples=400)) for i in range(2)]
        events = [dict(event="transition-start", value=start), *covers,
                  dict(event="transition-end", value=end)]
        with self.assertRaisesRegex(AssertionError, "no raw observation contained in transition 0 for probe 1"):
            verify_transition_coverage(events, rows, 1, range(2))
        rows[1][100].update(start_ns=1009, end_ns=1009)
        with self.assertRaisesRegex(AssertionError, "no raw observation contained in"):
            verify_transition_coverage(events, rows, 1, range(2))
        rows[1][100].update(start_ns=1009, end_ns=1010)
        self.assertEqual(verify_transition_coverage(events, rows, 1, range(2)), 2)


if __name__ == "__main__":
    unittest.main()
