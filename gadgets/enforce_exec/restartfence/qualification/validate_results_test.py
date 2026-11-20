#!/usr/bin/env python3
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0
"""Pure host tests for archived mixed-mode evidence, with no kernel activity."""
import json
import unittest

from validate_results import validate_mixed


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
    events = [
        dict(event="owner-start", value=dict(incarnation=1)),
        dict(event="owner-start", value=dict(incarnation=2)),
    ]
    for name, probe, incarnation, outage_denied in (
        ("same-owner-unbound", 1, 1, 0),
        ("inherited-unbound", 1, 2, 200),
        ("unreconciled-fallback-after-one-move", 4, 2, 200),
        ("acknowledged-fallback-remains-fenced", 4, 2, 0),
    ):
        events.append(dict(event="mixed-accounting", value=dict(
            name=name, probe=probe, incarnation=incarnation,
            before=dict(Denied=412, OutageDenied=251),
            after=dict(Denied=512 if name == "same-owner-unbound" else 612,
                       OutageDenied=251 + outage_denied))))

    def append_batch(modes, count):
        for i, mode in enumerate(modes):
            for j in range(count):
                target = "denied" if j % 2 == 0 else "allowed"
                errno = int(mode == 1 or (mode == 0 and target == "denied"))
                ts = len(rows[i]) * 10
                rows[i].append(
                    dict(target=target, start_ns=ts, end_ns=ts + 1, signal=0,
                         exit=100 * errno, errno=errno)
                )

    inject_at = None
    for phase, (name, modes) in enumerate(phases):
        if phase == 2:
            inject_at = len(rows[0])
            append_batch([0, 0, 3, 3, 1, 3], 200)
        start = len(rows[0]) - 1
        boundary_probe = {7: 0, 8: 1, 9: 4}.get(phase)
        if boundary_probe is not None:
            events.append(dict(event="mixed-off-boundary", monotonic_ns=start * 10 + 2,
                               value=dict(probe=boundary_probe, observed=start)))
        append_batch(modes, 200)
        events.append(dict(event="mixed-phase", monotonic_ns=(start + 200) * 10 + 2,
                           value=dict(name=name, policies=modes, starts=[start] * 6,
                                      ends=[start + 200] * 6)))

    # Add three 400-sample transition intervals matching the raw probe streams.
    for t in range(3):
        start_idx = len(rows[0]) - 1
        append_batch([0, 0, 3, 3, 1, 3], 400)
        end_idx = len(rows[0]) - 1
        action_start = rows[0][1 + start_idx]["start_ns"] + 1
        action_end = rows[0][end_idx]["end_ns"] - 1
        events.append(dict(event="transition-start", value=action_start))
        events.append(dict(event="transition-end", value=action_end))
        for i in range(6):
            first_ns = rows[i][1 + start_idx]["start_ns"]
            last_ns = rows[i][end_idx]["end_ns"]
            events.append(dict(event="transition-coverage", value=dict(
                transition=t, probe=i, start_index=start_idx, end_index=end_idx,
                first_ns=first_ns, action_start_ns=action_start,
                action_end_ns=action_end, last_ns=last_ns, samples=400)))
    events.append(dict(event="mixed-withdrawal-attested"))
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
        covers[-1]["value"] = dict(covers[0]["value"])
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


if __name__ == "__main__":
    unittest.main()
