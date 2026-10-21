---
title: oci
sidebar_position: 0
---

The OCI operator handles Gadgets images. It pulls images from the OCI registries
and invokes the different layer operators according to the
[layers](../oci.md#image-layers-and-media-types) present on the image.

## Priority

-1000

## Global Parameters

### `authfile`

Path of the authentication file. This overrides the `REGISTRY_AUTH_FILE`
environment variable. If the default file doesn't exist,
`$HOME/.docker/config.json` is used as a fallback.

Default: `/var/lib/ig/config.json`

### `pull-secret`

[Kubernetes Secret](https://kubernetes.io/docs/concepts/configuration/secret/)
to use when pulling the gadget image. The Kubernetes namespace for the Secret
is not configurable and is hardcoded to "gadget".

Fully qualified name: `operator.oci.pull-secret`

### `verify-image`

Verify image using the provided public key. Check [Verify image-based
gadgets](../../reference/verify-gadgets.mdx) to learn more.

Default: `true`

### `allow-enforcement`

Allow administrator-approved gadgets declaring `generator` or `mutator` behavior.
The host checks the declaration before instantiating any image operator. The
supported top-level `behavior` values in gadget metadata are:

- `observer`: observes activity.
- `generator`: generates activity.
- `mutator`: changes or blocks activity, including execution enforcement.

Declared generators and mutators require explicit host opt-in. Observers and
legacy gadgets without a declaration keep working with the default setting.
Unknown or malformed declarations are rejected.

Default: `false`

Fully qualified name: `operator.oci.allow-enforcement`

For a local run, use the generated CLI flag `ig run --allow-enforcement=true`.
For a daemon, set the host configuration or start it with
`ig daemon --allow-enforcement=true`. A client request cannot override a daemon's
setting. The Helm value is `config.operator.oci.allow-enforcement`:

```yaml
config:
  operator:
    oci:
      allow-enforcement: true
```

Behavior declarations express the intent of trusted, administrator-approved
code; they are not a sandbox that prevents an incorrectly declared gadget from
changing the system. Continue using image signature verification and a digest
allow list to select approved gadgets. See `verify-image` and `allowed-gadgets`.

### `public-keys`

Public keys used to verify the gadgets. Check [Verify image-based
gadgets](../../reference/verify-gadgets.mdx) to learn more.

Default: [Inspektor Gadget public
key](https://github.com/inspektor-gadget/inspektor-gadget/blob/%IG_BRANCH%/pkg/resources/inspektor-gadget.pub).

### `allowed-gadgets`

List of allowed gadgets. If a gadget is not part of it, execution will be
denied. By default, all digests are allowed. Check [Restricting
Gadgets](../../reference/restricting-gadgets.mdx) to get more details.

### `insecure-registries`

List of registries to access over plain HTTP. Check [Insecure
Registries](../../reference/insecure-registries.mdx) to learn more.

### `disallow-pulling`

Disallow pulling gadgets from registries. Check [Disallow pulling
Gadgets](../../reference/disallow-pulling.mdx) to learn more.

Default: `false`

## Instance Parameters

### `validate-metadata`

Validate the gadget metadata before running the gadget

Fully qualified name: `operator.oci.validate-metadata`

Default: `true`

### `pull`

Specify when the gadget image should be pulled
Possible Values:

- `always`: Always pull the gadget image.
- `missing`: Pull the gadget image only if missing.
- `never`: Never pull the gadget image.

Fully qualified name: `operator.oci.pull`

Default: `missing`

### `annotate`

Add annotations to datasources or fields. Use a comma-separated list in the formats:

- `datasource:annotation=value` to add an annotation to a datasource
- `datasource.field:annotation=value` to add an annotation to the field of a datasource

Fully qualified name: `operator.oci.annotate`
