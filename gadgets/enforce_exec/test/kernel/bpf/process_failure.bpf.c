// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
// Deliberately fail only the marker transfer, never initial host binding.
#define EXEC_PROCESS_MARKER_CREATE(task, value) ((__u64 *)0)
#include "../../../program.bpf.c"
