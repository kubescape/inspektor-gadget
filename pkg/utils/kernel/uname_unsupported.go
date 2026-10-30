//go:build !linux

// Copyright 2012-2017 Docker, Inc.
// SPDX-License-Identifier: Apache-2.0
// Copied from github.com/moby/moby v28.5.2 (pkg/parsers/kernel/uname_unsupported.go).
// See LICENSE and NOTICE in this directory.

package kernel

import (
	"errors"
)

// utsName represents the system name structure. It is defined here to make it
// portable as it is available on Linux but not on Windows.
type utsName struct {
	Release [65]byte
}

func uname() (*utsName, error) {
	return nil, errors.New("kernel version detection is only available on linux")
}
