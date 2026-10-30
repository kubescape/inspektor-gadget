//go:build linux || freebsd || openbsd

// Copyright 2012-2017 Docker, Inc.
// SPDX-License-Identifier: Apache-2.0
// Copied from github.com/moby/moby v28.5.2 (pkg/parsers/kernel/kernel_unix.go).
// See LICENSE and NOTICE in this directory.

package kernel

import (
	"golang.org/x/sys/unix"
)

// GetKernelVersion gets the current kernel version.
func GetKernelVersion() (*VersionInfo, error) {
	uts, err := uname()
	if err != nil {
		return nil, err
	}

	// Remove the \x00 from the release for Atoi to parse correctly
	return ParseRelease(unix.ByteSliceToString(uts.Release[:]))
}
