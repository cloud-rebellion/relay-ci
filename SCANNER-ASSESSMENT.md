# Relay public scanner artifact assessment

Authored candidate; not executed, qualified, published or activated. This is a
separate public `cloud-rebellion/relay-ci` workflow on the exact
`scanner/assessment-20261114` push branch. It has no private source key, app
checkout, Stage credentials, OVH access, provider calls or activation step.

The first executable milestone assesses the exact November 9 Debian build 69
ClamAV manifest `2d901d81…`, its config `65c666ef…` and all six compressed layers.
Anonymous registry authorization remains in memory. OCI descriptor hashes and
sizes, platform/config/layer closure, linked in-toto statement subjects and
predicate types are checked. The image is materialized as a one-image OCI
directory for Trivy; a canonical OCI tar is retained as encrypted custody.
Trivy 0.74.0's own OCI reader consumes a directory, so the driver does not
mislabel a Docker export or assume support for an OCI tar input.

The Trivy tool identity is the existing exact 0.74.0 manifest pin, not an old
scan verdict. Its registry bytes, platform config, pulled image ID and executed
version must match in this run. A newly downloaded vulnerability DB must be at
most 24 hours old, not overdue/future-dated and hashed unchanged through both
scan and SBOM. The Java package index is separately downloaded now and must be
not overdue and at most seven days old. Empty/unsupported/mismatched package
reports, altered or ignored findings, tool warnings/errors and missing data
refuse. Every HIGH/CRITICAL finding, including unfixed findings, fails.

All OCI, Docker images/layers, daemon data, vulnerability DBs and scan temporary
data use a separately allocated 8 GiB ext4 loop filesystem. This is a hard
storage bound rather than a polling threshold. Admission requires 11 GiB free
on the fresh GitHub-hosted Linux x86_64 VM. The dedicated daemon uses its own
socket/data root/unit, a 1 GiB memory cap, two CPUs and bounded tasks/time; it
never contacts the runner's default Docker daemon. Tool containers have a
3 GiB memory cap, two CPUs, 256 PIDs, read-only root, no capabilities and a
128 MiB tmpfs. Only the reviewed Trivy tool uses host networking to fetch DBs;
its actual image scan has network `none`. No ClamAV image executable runs.
Loop/mount/unit/socket identities are verified; cleanup stops only that daemon
and detaches only its own backing file. Ambiguous ownership refuses cleanup.
No existing Hash container, image, volume, scanner network or service is used.

The 32 closed synthetic controls cover digest/size/redirect/subject/trust and
DB/report refusals, unfixed vulnerabilities, early stop, source/event/storage
ownership and separate result semantics. They perform no Docker/network call.
They require an ordinary official local scratch qualification after source
review; the privileged Linux storage backend also needs its actual public CI
execution. A synthetic pass is not a Linux runtime qualification.

Only ciphertext and an allowlisted artifact-only summary can be uploaded, with
one-day retention. Raw diagnostic files have 64 MiB individual/256 MiB aggregate
limits; exact public OCI custody has a separate 1 GiB ceiling. The existing age
1.3.2 pin and recipient are reused without reading a private identity. A report
cannot claim app CI, full scanner qualification, daemon execution, production
authorization or private source use.

Registry-linked unsigned statements do not prove publisher signature trust or
an exact reviewed source revision. That remains an explicit blocker before
full dependency acceptance. A passing artifact-security stage still does not
qualify the original 22 loaded settings, signature freshness/update/reload and
restart, parser/encryption/limit/error/outage/recovery/capacity behavior, or real
Relay app no-persistence journeys. A failed artifact stage stops before those
daemon checks. No source-policy default or held companion digest changes here.

The original six app jobs, their workflow and all original 43 public harness
files remain unchanged in this phase-0 publication set. The separate neutral
Docker extraction in this artifact packet is for later reviewed composition;
it is not required or published by this workflow. Final app S3/private P3 and
the original six job source identities remain pending their normal lifecycle.

Primary implementation references: Trivy v0.74.0
[`pkg/fanal/image/oci.go`](https://github.com/aquasecurity/trivy/blob/v0.74.0/pkg/fanal/image/oci.go),
[`pkg/types/report.go`](https://github.com/aquasecurity/trivy/blob/v0.74.0/pkg/types/report.go),
[`pkg/db/db.go`](https://github.com/aquasecurity/trivy/blob/v0.74.0/pkg/db/db.go),
[`pkg/javadb/client.go`](https://github.com/aquasecurity/trivy/blob/v0.74.0/pkg/javadb/client.go)
and [`pkg/flag/vulnerability_flags.go`](https://github.com/aquasecurity/trivy/blob/v0.74.0/pkg/flag/vulnerability_flags.go).
