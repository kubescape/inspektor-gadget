// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

func TestObservationContract(t *testing.T) {
	tests := []struct {
		name                string
		policy              samplePolicy
		target              string
		errno, exit, signal int
		want                bool
	}{
		{"strict deny EPERM", liveStrict, "denied", 1, 100, 0, true},
		{"strict denied success fails", liveStrict, "denied", 0, 0, 0, false},
		{"strict deny EACCES fails", liveStrict, "denied", 13, 100, 0, false},
		{"live allowed proves recovery", liveStrict, "allowed", 0, 0, 0, true},
		{"never-moved mutant fails", liveStrict, "allowed", 1, 100, 0, false},
		{"fence denies otherwise allowed", fencedStrict, "allowed", 1, 100, 0, true},
		{"fence hole fails", fencedStrict, "allowed", 0, 0, 0, false},
		{"audit denied path allowed", allowAll, "denied", 0, 0, 0, true},
		{"audit blocking fails", allowAll, "denied", 1, 100, 0, false},
		{"transition may fence allowed", transitionStrict, "allowed", 1, 100, 0, true},
		{"transition may permit allowed", transitionStrict, "allowed", 0, 0, 0, true},
		{"transition never permits denied", transitionStrict, "denied", 0, 0, 0, false},
		{"observer failure is not denial", fencedStrict, "denied", 1, 101, 0, false},
		{"signal is not a verdict", fencedStrict, "denied", 0, -1, 9, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := observation{Target: tt.target, Errno: tt.errno, Exit: tt.exit, Signal: tt.signal, Start: 1, End: 2}
			if got := checkObservation(r, tt.policy) == nil; got != tt.want {
				t.Fatalf("accepted=%v want=%v", got, tt.want)
			}
		})
	}
}

func TestObservationRejectsEmptyAndReversedIntervals(t *testing.T) {
	for _, interval := range [][2]uint64{{0, 10}, {10, 10}, {11, 10}} {
		r := observation{Target: "allowed", Start: interval[0], End: interval[1]}
		if checkObservation(r, allowAll) == nil {
			t.Fatalf("accepted invalid interval %v", interval)
		}
	}
}

type probeInput struct{ io.Writer }

func (probeInput) Close() error { return nil }

func TestBatchReportsRawIntervalsAndRejectsTimeRegression(t *testing.T) {
	raw := `{"batch":1,"sample":0,"target":"denied","errno":1,"exit":100,"signal":0,"start_ns":9,"end_ns":11}
{"batch":1,"sample":0,"target":"allowed","errno":1,"exit":100,"signal":0,"start_ns":12,"end_ns":13}
`
	for _, previousEnd := range []uint64{0, 10} {
		t.Run(fmt.Sprint(previousEnd), func(t *testing.T) {
			logfile, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer logfile.Close()
			var input bytes.Buffer
			w := workload{in: probeInput{&input}, out: bufio.NewScanner(strings.NewReader(raw)), logfile: logfile, lastEnd: previousEnd}
			var intervals []observation
			err = w.batchObserved(1, fencedStrict, nil, func(r observation) { intervals = append(intervals, r) })
			if (err != nil) != (previousEnd != 0) {
				t.Fatalf("previousEnd=%d err=%v", previousEnd, err)
			}
			if len(intervals) != 2 || intervals[0].Start != 9 || intervals[0].End != 11 || intervals[1].Start != 12 || intervals[1].End != 13 {
				t.Fatalf("raw intervals not reported: %+v", intervals)
			}
			if w.observed != 2 {
				t.Fatalf("batch not drained: %d", w.observed)
			}
		})
	}
}
