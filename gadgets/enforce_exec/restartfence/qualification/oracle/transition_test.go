// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestTransitionNeedsRawIntervalOverlap(t *testing.T) {
	for _, tt := range []struct {
		name string
		rows []observation
		want bool
	}{
		{"bracket without overlap", []observation{{Start: 1, End: 9}, {Start: 21, End: 30}}, false},
		{"ends at action start", []observation{{Start: 1, End: 10}}, false},
		{"starts at action end", []observation{{Start: 20, End: 30}}, false},
		{"within action", []observation{{Start: 11, End: 12}}, true},
		{"spans action", []observation{{Start: 1, End: 30}}, true},
		{"overlaps start", []observation{{Start: 1, End: 11}}, true},
		{"overlaps end", []observation{{Start: 19, End: 30}}, true},
		{"zero timestamp", []observation{{Start: 0, End: 30}}, false},
		{"empty interval", []observation{{Start: 15, End: 15}}, false},
		{"reversed interval", []observation{{Start: 18, End: 12}}, false},
		{"retains overlap past later observations", []observation{{Start: 11, End: 12}, {Start: 21, End: 30}}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var got transitionObservation
			for _, r := range tt.rows {
				got.observe(r, 10)
			}
			if got.covers(10, 20) != tt.want {
				t.Fatalf("interval=%+v want overlap=%t", got, tt.want)
			}
		})
	}
}

func TestTransitionRejectsInvalidActionAndUnpublishedStart(t *testing.T) {
	var got transitionObservation
	got.observe(observation{Start: 1, End: 30}, 0)
	if got.covers(10, 20) {
		t.Fatal("accepted an interval before action start publication")
	}
	got.observe(observation{Start: 1, End: 30}, 10)
	for _, bounds := range [][2]uint64{{0, 20}, {10, 10}, {20, 10}} {
		if got.covers(bounds[0], bounds[1]) {
			t.Fatalf("accepted invalid action bounds %v", bounds)
		}
	}
}
