IG ?= ig
IMAGE ?= enforce-exec-owner:experimental
ABI3_DEVELOPMENT ?= 0
ifeq ($(ABI3_DEVELOPMENT),1)
ifeq ($(filter %:abi3-development,$(IMAGE)),)
$(error ABI3_DEVELOPMENT requires explicit IMAGE ending :abi3-development)
endif
else ifneq ($(ABI3_DEVELOPMENT),0)
$(error ABI3_DEVELOPMENT must be 0 or 1)
endif
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
	if [ "$(ABI3_DEVELOPMENT)" = 1 ]; then \
	    sed -i '1i#define ENFORCE_EXEC_ABI3_DEVELOPMENT 1' "$$context/program.bpf.c"; \
	    sed -i 's/enforce-exec-owner-abi: "2"/enforce-exec-owner-abi: "3"\n  enforce-exec-owner-development: "true"/; s/^description:.*/description: "Stage A ABI3 development only; incomplete lifecycle, not production-ready"/' "$$context/gadget.yaml"; \
	fi; \
	$(IG) image build -t "$(IMAGE)" "$$context"

# Explicit supported amd64 path; does not use/upgrade the default IG builder.
# VMLINUX_BTF must be a trusted artifact matching an exact fullruntime kernel matrix digest.
# Requires Clang 21.1.8; does not load BPF or claim arm64/general kernel support.
# Example: make archive VMLINUX_BTF=/trusted/vmlinux.btf \
#   IMAGE=localhost/enforce-exec-owner:abi2 ARCHIVE=/tmp/owner.tar
CLANG ?= clang-21
BPFTOOL ?= bpftool
VMLINUX_BTF ?=
ARCHIVE ?=
export CLANG BPFTOOL VMLINUX_BTF IMAGE ARCHIVE ABI3_DEVELOPMENT
.PHONY: archive
archive:
	@./build-archive.sh "$$VMLINUX_BTF" "$$CLANG" "$$BPFTOOL" "$$IMAGE" "$$ARCHIVE"
