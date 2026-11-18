#!/bin/sh
# Builds the option C engine objects with the pinned product toolchain
# (clang-21 1:21.1.8-3~bpo13+2): the product object, without test switches,
# and the test object (-DOC_TEST_BUILD: mutants and test knobs). CLANG
# overrides the compiler.
set -eu
cd "$(dirname "$0")"
clang=${CLANG:-clang-21}
for v in product test; do
	f=-DFE_BOUNDED_LOOP_CANDIDATE
	[ $v = test ] && f="$f -DOC_TEST_BUILD"
	"$clang" -target bpf -O2 -g -D__TARGET_ARCH_x86 $f -I../../../../../include/gadget/amd64 \
		-I../../../fullpolicy/bpf -I../../../full -Wall -Wno-unused-function -c bpf/optc.bpf.c -o optc_${v}_bpfel.o
done
sha256sum optc_*_bpfel.o
