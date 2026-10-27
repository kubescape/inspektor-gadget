IG ?= ig
IMAGE ?= enforce-exec-owner:experimental
.PHONY: build
# Keep the actual full fact-acquisition implementation shared. This profile is
# experimental and has no production/native Ready claim until integrated proof.
build:
	@set -eu; context=$$(mktemp -d); trap 'rm -rf "$$context"' EXIT; \
	mkdir -p "$$context/full" "$$context/fullruntime/bpf"; \
	printf '%s\n' '#define ENFORCE_EXEC_PERSISTENT_OWNER 1' '#include "full/program.bpf.c"' > "$$context/program.bpf.c"; \
	cp ../program.bpf.c ../stdio.h ../filesystem.h ../image_origin.h ../owner_types.h ../owner_control.h ../owner_roles.h ../epoch_roles.h "$$context/full/"; \
	cp ../../fullpolicy/bpf/matcher.h ../../fullpolicy/bpf/evaluator.h "$$context/full/"; \
	cp ../../fullruntime/bpf/gate.h "$$context/fullruntime/bpf/"; \
	cp gadget.yaml "$$context/"; \
	$(IG) image build -t "$(IMAGE)" "$$context"

# Explicit supported amd64 path; does not use/upgrade the default IG builder.
# VMLINUX_BTF must be a trusted artifact matching fullruntime.SupportedKernelBTF.
# Requires Clang 21.1.8; does not load BPF or claim arm64/general kernel support.
# Example: make archive VMLINUX_BTF=/trusted/vmlinux.btf \
#   IMAGE=localhost/enforce-exec-owner:abi2 ARCHIVE=/tmp/owner.tar
CLANG ?= clang-21
BPFTOOL ?= bpftool
VMLINUX_BTF ?=
ARCHIVE ?=
export CLANG BPFTOOL VMLINUX_BTF IMAGE ARCHIVE
.PHONY: archive
archive:
	@./build-archive.sh "$$VMLINUX_BTF" "$$CLANG" "$$BPFTOOL" "$$IMAGE" "$$ARCHIVE"
