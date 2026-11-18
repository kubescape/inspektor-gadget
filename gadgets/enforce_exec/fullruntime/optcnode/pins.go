// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package optcnode

import "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime/optcnode/admission"

// QualifiedObjectSHA256 is the product object the pins below qualified.
const QualifiedObjectSHA256 = "7d95ba90419eefdfab3053d05b230164ab1cfb1ccbc705c04237d28439488f23"

// QualifiedPins are the exactly qualified (kernel, object) pairs: G004 run
// d9 ($U/G004/evidence/d9-<distro>/guest), on each kernel with 0 FAIL and 0
// SKIP: the non-mutant oracle (E1, G003, G004, the engine silencers, the
// cliff, the memory measurement) on THIS product object (EE_OPTC_PRODUCT=1;
// scenarios that need a test-only knob are logged NOT-RUN there), the same
// oracle plus every mutant on the test object built from the same source,
// and the node-level late-bind test (C4, N1, R3-C1). Each run records the object's BTF shape
// fingerprint (btfshape.json; the "shape" below is from d5, same kernels).
// Review M6: the 5.15 pin was admitted with one NOT-RUN (the ftrace
// silencer: 5.15 refuses ftrace_enabled=0 with EBUSY while trampolines are
// attached; the detach silencer runs there). Exact pins accept a NOT-RUN
// that is a kernel property; family admission (Qualification.Complete)
// does not. A rebuilt object matches none of them
// (TestQualifiedPinsNameTheEmbeddedObject).
var QualifiedPins = []admission.Pin{
	{Release: "5.15.0-203-generic", BTFSHA256: "36e118be1ee6c3ed13d4813d2e170252fb19d4120cf3940ada382bfe2e38d70c", ObjectSHA256: QualifiedObjectSHA256},               // ubuntu2204 ubuntu 22.04, shape b9a91807eac870b7
	{Release: "5.14.0-687.10.1.el9_8.0.1.x86_64", BTFSHA256: "53545fbcff32c4bb6b095678bc0be20b06a1d7fb0329b4f44142883c290e1198", ObjectSHA256: QualifiedObjectSHA256}, // rocky9 rocky 9.8, shape e4beedd609b6a338
	{Release: "6.1.0-54-amd64", BTFSHA256: "8f4d6b553aecc543afe0b987880b05e16c68169fbd9fcf38cc6dc378667d1f16", ObjectSHA256: QualifiedObjectSHA256},                   // debian12 debian 12, shape 44386aae7c1bcaa8
	{Release: "6.8.0-147-generic", BTFSHA256: "8c10e7e174e89c92f1d2708f12bb5268dc381e57e867397534c4e145348622e0", ObjectSHA256: QualifiedObjectSHA256},                // ubuntu2404 ubuntu 24.04, shape fde6a14d3ecd0886
	{Release: "6.12.117+deb13-amd64", BTFSHA256: "4507cd5912a97650ac1abc7a609a3d535d1cf2dc851f23f9fe9ace42ee51f34b", ObjectSHA256: QualifiedObjectSHA256},             // debian13 debian 13, shape 2cc3a9606492ac8f
	{Release: "6.12.113-138.209.amzn2023.x86_64", BTFSHA256: "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82", ObjectSHA256: QualifiedObjectSHA256}, // al2023-k612 amzn 2023, shape df34e5af791448bc
	{Release: "6.18.56-125.164.amzn2023.x86_64", BTFSHA256: "d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee", ObjectSHA256: QualifiedObjectSHA256},  // al2023-k618 amzn 2023, shape b55f37853b17a44a
}

// DefaultAdmission is exact pinning only: family admission stays off. No
// family has the full record admission requires (005 §8: at least two
// builds including the family's newest); each qualified family has one.
func DefaultAdmission() admission.Policy { return admission.Policy{Pins: QualifiedPins} }
