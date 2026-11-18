#!/usr/bin/env bash
# Copyright 2026 The Inspektor Gadget authors
# SPDX-License-Identifier: Apache-2.0
#
# Builds the shared product objects g19pkg{64,128,256,512}.bpf.o and, with
# --check, compares each sha256 with
# fullruntime/testdata/shared_product_objects.tsv (sharedProductObjects).
#
# D3: ONE CO-RE object per profile for every kernel. The objects used to be
# built once per pinned kernel BTF; those builds differed only in the
# unrelocated CO-RE placeholders and in the BTF/DWARF copied from each
# kernel's vmlinux.h (measured: identical instructions after relocation). The
# object is now compiled against one vmlinux.h (the 6.18 header below: it
# only supplies type DEFINITIONS; every kernel access is relocated at load
# against the running kernel's BTF) and loads on any kernel whose BTF
# resolves its relocations, kfuncs and attach targets.
#
# Usage: build-product.sh [--check] [OUTDIR]     (default OUTDIR: a temp dir)
#   CLANG   the compiler (default clang-21). It must be the Debian package
#           clang-21 1:21.1.8-3~bpo13+2: its version string is in the
#           object (DW_AT_producer), so any other build changes the bytes.
#
# Run it in the pinned Debian trixie container, as the CI job
# test-enforce-exec-product-objects does (`make enforce-exec-product-objects`
# runs the same image and scripts with docker): install-product-toolchain.sh
# installs clang-21 and libbpf-dev 1:1.5.0-3 from one snapshot.debian.org
# timestamp, checked against product-toolchain-debs.sha256.
#
# The bytes do not depend on the checkout path: every path the compiler
# records (DWARF, BTF line info) is rewritten with -ffile-prefix-map to
# PREFIX below, which must NOT exist. (The BPF backend copies each source
# line's text into .BTF by reading the file at the recorded path; with a
# path that does not exist it copies none, in every checkout. Measured: the
# same sha256 from two different checkout paths and two fresh containers.)
#
# The vmlinux.h (testdata/al2023-vmlinux/6.18/vmlinux.h.xz) is `bpftool btf
# dump file <BTF> format c` of a kernel BTF; the sha256 of the decompressed
# header is checked below.
set -euo pipefail

CLANG_VERSION='Debian clang version 21.1.8 (3~bpo13+2)'
LIBBPF_VERSION='1:1.5.0-3'
PREFIX=/nonexistent/enforce-exec
HEADER_KERNEL=6.18
HEADER_SHA256=a6b003369e04fe8b0382f2704e64e0c0f71c211dd54a5b160f60de21bd00a4e2

check=0
if [[ ${1:-} == --check ]]; then
	check=1
	shift
fi
[[ $# -le 1 ]] || { echo "usage: $0 [--check] [OUTDIR]" >&2; exit 2; }

bpf=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$bpf/../../../.." && pwd)
testdata=$repo/gadgets/enforce_exec/fullruntime/testdata
pins=$testdata/shared_product_objects.tsv
out=${1:-$(mktemp -d)}
mkdir -p -- "$out"
out=$(cd -- "$out" && pwd)

clang=${CLANG:-clang-21}
version=$("$clang" --version | head -n1)
if [[ $version != "$CLANG_VERSION" ]]; then
	echo "$clang reports '$version'; the pinned objects need '$CLANG_VERSION' (install-product-toolchain.sh)" >&2
	exit 1
fi
# The libbpf headers (/usr/include/bpf) are part of the input.
libbpf=$(dpkg-query -W -f='${Version}' libbpf-dev 2>/dev/null) || libbpf=none
if [[ $libbpf != "$LIBBPF_VERSION" ]]; then
	echo "libbpf-dev is '$libbpf'; the pinned objects need the Debian package libbpf-dev $LIBBPF_VERSION headers (install-product-toolchain.sh)" >&2
	exit 1
fi

P=-DENFORCE_EXEC_POOL_OPAQUE_
# compile-pkg.sh: the product base (no REAL_RECOVERY, PRCTL_ARM or
# REAL_LIVE_BOOTSTRAP) and its default profile, overridden below.
BASE=(
	"${P}REAL_POLICY_VERDICT_CANDIDATE=1" "${P}REAL_STAGE_BEGIN_DIAGNOSTIC=1" "${P}REAL_RULE_WINDOW_DIAGNOSTIC=1" "${P}SUCCESSFUL_BIRTH_DIAGNOSTIC=1"
	"${P}FAILURE_SOURCE_COMPLETION_DIAGNOSTIC=1" "${P}SUCCESS_SOURCE_COMPLETION_DIAGNOSTIC=1"
	"${P}REAL_POLICY_BRIDGE_CANDIDATE=1" "${P}TERMINAL_RACE_DIAGNOSTIC=1"
	"${P}READER_BEGIN_PROBE=1" "${P}READER_LIFECYCLE_PROBE=1" "${P}WORK_READER_CATALOGUE_CANDIDATE=1" "${P}WORK_COMPLETION_PROBE=1"
	"${P}FAILURE_FINAL_RETURN_PROBE=1"
	-DSE_PROFILE_BINDINGS=2 -DSE_PROFILE_TASKS=256 -DSE_PROFILE_SCRATCH=64 -DSE_PROFILE_TASK_QUOTA=128 -DSE_PROFILE_SCRATCH_QUOTA=32
	-DSE_PROFILE_ACCEPTED_UIDS=8 -DSE_PROFILE_INODE_FACTS=2 -DSE_PROFILE_INODE_QUOTA=1 -DSE_PROFILE_IMAGES=2 -DSE_PROFILE_IMAGE_QUOTA=1
	-DSE_PROFILE_SLOTS_256=4 -DSE_PROFILE_SLOTS_1024=0 -DSE_PROFILE_SLOTS_4096=0 -DSE_PROFILE_SLOTS_16384=0
)
# build-g19pkg.sh PKG: the product extras (source capsule, eval-WORK
# witness, fail-closed rate, reap events, credit at exit, no TEST_RUN,
# synchronous WORK return, 8192 exit tombstones, product publisher with the
# image geometry, native config gate, interpreter continuation, D1 LSM-only).
PKG=(
	"${P}SOURCE_CAPSULE_CANDIDATE=1" "${P}EVAL_WORK_WITNESS_DIAGNOSTIC=1" "${P}FAIL_CLOSED_RATE_CANDIDATE=1"
	"${P}REAP_EVENTS_CANDIDATE=1" "${P}EXIT_CREDIT_CANDIDATE=1" -DSE_PRODUCT_NO_TEST_RUN=1
	"${P}WORK_SYNC_RETURN_CANDIDATE=1" -DSE_PROFILE_EXIT_TOMBSTONES=8192
	"${P}PRODUCT_PUBLISHER_CANDIDATE=1" -USE_PROFILE_IMAGES -DSE_PROFILE_IMAGES=256 -USE_PROFILE_IMAGE_QUOTA -DSE_PROFILE_IMAGE_QUOTA=128
	"${P}NATIVE_CONFIG_GATE_CANDIDATE=1" "${P}INTERP_CONTINUATION_CANDIDATE=1"
	# Stage 1 (D1): LSM-only exec outcome, no failure-frame kprobe,
	# kretprobe, fentry or fexit; the kernel witness map d1_witness.
	-DENFORCE_EXEC_D1_LSM_ONLY=1
)
# q TASK WORK: the per-binding quota profile.
q() {
	echo "-USE_PROFILE_TASKS -DSE_PROFILE_TASKS=$((2 * $1)) -USE_PROFILE_TASK_QUOTA -DSE_PROFILE_TASK_QUOTA=$1" \
		"-USE_PROFILE_SCRATCH -DSE_PROFILE_SCRATCH=$((2 * $2)) -USE_PROFILE_SCRATCH_QUOTA -DSE_PROFILE_SCRATCH_QUOTA=$2" \
		"-DSE_PROFILE_WORK_RETRIES=$(($2 < 16 ? $2 : 16))"
}
# The product profiles, in pin order: name TASK WORK.
PROFILES=("g19pkg64 64 8" "g19pkg128 128 32" "g19pkg256 256 32" "g19pkg512 512 16")

[[ ! -e $PREFIX ]] || { echo "$PREFIX exists: the recorded source paths must not resolve" >&2; exit 1; }
header=$testdata/al2023-vmlinux/$HEADER_KERNEL/vmlinux.h.xz
btf=$(mktemp -d)
trap 'rm -rf -- "$btf"' EXIT
xz -dc -- "$header" >"$btf/vmlinux.h"
got=$(sha256sum "$btf/vmlinux.h" | cut -d' ' -f1)
[[ $got == "$HEADER_SHA256" ]] || { echo "$header decompresses to sha256 $got, want $HEADER_SHA256" >&2; exit 1; }

cd -- "$repo"
fail=0
for profile in "${PROFILES[@]}"; do
	read -r name task work <<<"$profile"
	want=
	if [[ $check == 1 ]]; then
		want=$(awk -F'\t' -v n="$name" '$1 == n { print $2 }' "$pins")
		[[ -n $want ]] || { echo "no pin for $name in $pins" >&2; exit 1; }
	fi
	obj=$out/$name.bpf.o
	# shellcheck disable=SC2046 # q prints separate flags
	"$clang" -target bpf -O2 -g -D__TARGET_ARCH_x86 \
		"-ffile-prefix-map=$repo=$PREFIX/src" "-ffile-prefix-map=$btf=$PREFIX/btf" \
		"${BASE[@]}" "${PKG[@]}" $(q "$task" "$work") \
		-Wno-missing-declarations -I "$btf" -I "$repo/include" -I "$repo/gadgets/enforce_exec/full" \
		-I "$repo/gadgets/enforce_exec/fullpolicy/bpf" \
		-c "$repo/gadgets/enforce_exec/fullruntime/bpf/opaque_real_owner_child_candidate.bpf.c" -o "$obj" 2>"$obj.log" ||
		{ cat "$obj.log" >&2; echo "BUILD FAIL $name" >&2; exit 1; }
	sum=$(sha256sum "$obj" | cut -d' ' -f1)
	if [[ $check == 0 ]]; then
		echo "$sum  $obj"
	elif [[ $sum == "$want" ]]; then
		echo "OK   $name $sum"
	else
		echo "FAIL $name $sum, pinned $want"
		fail=1
	fi
done
exit $fail
