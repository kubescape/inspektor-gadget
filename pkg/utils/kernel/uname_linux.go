// Copyright 2012-2017 Docker, Inc.
// SPDX-License-Identifier: Apache-2.0
// Copied from github.com/moby/moby v28.5.2 (pkg/parsers/kernel/uname_linux.go).
// See LICENSE and NOTICE in this directory.

package kernel

import "golang.org/x/sys/unix"

func uname() (*unix.Utsname, error) {
	uts := &unix.Utsname{}

	if err := unix.Uname(uts); err != nil {
		return nil, err
	}
	return uts, nil
}
