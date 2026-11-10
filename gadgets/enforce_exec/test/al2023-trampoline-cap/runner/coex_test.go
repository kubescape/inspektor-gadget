// SPDX-License-Identifier: Apache-2.0

package main

import (
	"slices"
	"testing"
)

func TestCoexFillersAtReserveBoundary(t *testing.T) {
	for _, c := range []struct {
		k, reserve, pre int
		want            []int
	}{
		{3, 8, 0, []int{0, 10, 20, 27, 28}},
		{1, 8, 0, []int{0, 10, 20, 29, 30}},
		{1, 8, 1, []int{0, 10, 20, 28, 29}},
		{1, 8, 20, []int{0, 9, 10}},
	} {
		if got := coexFillers(c.k, c.reserve, c.pre); !slices.Equal(got, c.want) {
			t.Errorf("coexFillers(%d, %d, %d) = %v, want %v", c.k, c.reserve, c.pre, got, c.want)
		}
	}
}
