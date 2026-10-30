//go:build !windows

// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kernel

import "testing"

func TestReleaseContract(t *testing.T) {
	for _, tc := range []struct{ release, want string }{
		{"6.13", "6.13.0"}, {"6.13.0-rc1", "6.13.0-rc1"},
		{"3.12-1-amd64", "3.12.0-1-amd64"}, {"3.12.8tag", "3.12.8tag"},
		{"3.4.54.longterm-1", "3.4.54.longterm-1"}, {"6.13.foo", "6.13.0.foo"},
	} {
		got, err := ParseRelease(tc.release)
		if err != nil || got.String() != tc.want {
			t.Errorf("ParseRelease(%q) = %v, %v; want %s", tc.release, got, err, tc.want)
		}
	}
	for _, release := range []string{"", "6", "garbage", "6.x"} {
		got, err := ParseRelease(release)
		if got != nil || err == nil || err.Error() != "Can't parse kernel version "+release {
			t.Errorf("invalid release %q: %v, %v", release, got, err)
		}
	}
}
func TestComparisonContract(t *testing.T) {
	base := VersionInfo{Kernel: 6, Major: 13}
	for _, tc := range []struct {
		release string
		want    int
	}{
		{"5.99.99", -1}, {"6.12.99", -1}, {"6.13", 0}, {"6.13.0-rc1", 0}, {"6.13.1", 1}, {"6.14", 1}, {"7.0", 1},
	} {
		v, err := ParseRelease(tc.release)
		if err != nil {
			t.Fatal(err)
		}
		if got := CompareKernelVersion(*v, base); got != tc.want {
			t.Errorf("compare %s = %d; want %d", tc.release, got, tc.want)
		}
		if got := CompareKernelVersion(base, *v); got != -tc.want {
			t.Errorf("reverse compare %s = %d", tc.release, got)
		}
	}
}
