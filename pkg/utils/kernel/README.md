# Kernel version compatibility helpers

Copied from Moby v28.5.2 `pkg/parsers/kernel` under Apache-2.0 (see LICENSE
and NOTICE). The parser, comparison, version representation, platform build
constraints and getters retain upstream behavior. The unused CheckKernelVersion
convenience function is omitted to avoid its logging dependency.

This is intentionally not a semantic-version parser: two numeric components
are required, the patch component is optional, and comparison ignores the
flavor (including `-rc1`). Pure tests cover parsing and comparisons without
calling the platform getter.

Migration note: exported testing helpers in `pkg/testing/utils` and
`gadgets/testing` now use this package's VersionInfo instead of
`github.com/moby/moby/pkg/parsers/kernel.VersionInfo`. External callers passing
or explicitly naming the type must change their import to
`github.com/inspektor-gadget/inspektor-gadget/pkg/utils/kernel`.
