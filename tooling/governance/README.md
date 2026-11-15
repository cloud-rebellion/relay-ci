# Relay repository governance partition

`run-governance.py` runs the ten repository assertions selected for an ordinary
durable `brightcrm` subject. It is portable validation tooling, not execution of
Stage's private Go package and not a Stage CI receipt. The adapter must preserve
native platform and other-product checks for a mixed or estate-control change.
This partition never establishes that a whole-estate guard run was completed.

The driver first verifies the independent G/P/S source binding, runs the Python
driver refusal controls and Go race-instrumented positive/refusal controls,
builds this standard-library-only helper, and executes every selected assertion.
It verifies the source binding again before writing terminal success. The public
console contains status/counts only. Raw subprocess output, assertion locations,
intermediate helper results and the terminal `governance-summary.json` stay in
the private results directory for encrypted reporting. The terminal report has
`status: passed`, `selected_guard_count: 10`, ten distinct passed assertions and
real control counts with zero skips. A failed control, missing assertion,
unknown policy digest or nonterminal source check cannot qualify.

`source-origin.json` contains only original Git blob IDs and SHA256 values for
fourteen private Stage inputs at the stated source revision. The closed typed
`native_controller_profile` must be exactly `deployed-native-relay-7-9-10-v1`;
there is no missing-profile, unknown-profile or optional-input fallback. The
helper refuses omitted, extra or changed inputs and trailing provenance data.
It parses reviewed policy declarations with Go's AST
parser as data; it neither compiles nor executes the private Stage source.
`mapping.json` records the native-to-portable semantic correspondence. The
independent Stage adapter must still compare every private P entry with original
S; this helper's digest check does not substitute for that comparison.

The product-owned root is `brightcrm`. Shared `ops` dependencies do not become
owned product roots. The one selected operational credential assertion reads
`ops/scripts/nocodb-to-espocrm-import.py`; the separate source-security gate
scans the entire frozen `ops` execution root, rather than this one file or the
smaller declared-dependency projection. Nested `brightcrm/voip` receives its own
required Go execution job; the original top-level module coverage assertion
does not claim to execute its tests.

Native optional cases are explicit in each result's `applicability` and `checked`
fields. No app publisher or local `scripts/ci.sh` means the native corresponding
subcase is not applicable, while the assertion itself still executes and checks
that condition. Manual Relay deployment is excluded by the native push-deploy
image-discovery loop; the portable assertion additionally requires Relay's
Trivy scan-matrix membership, its root Dockerfile and the reviewed manual
deployment profile. The separate final-image gate performs the actual scan.
These product assertions do not claim to reconstruct unrelated private pipeline
registrations or their estate-wide nonempty checks.

Provider/context-credential rules and exact fixture exclusions are read from
private `security_gate.go`, with the native literal-candidate classification.
The native walker intentionally ignores unreadable/stat-failed files, files
larger than 2 MiB and files containing NUL. Those historical limits are retained
and are not a claim that excluded bytes were inspected. The complete input
binding and the remaining security/vulnerability/image gates are independent.

On hosted CI, run `python3 -B tooling/governance/run-governance.py` through the
trusted outer gate wrapper after configuring fixed `RELAY_PRIVATE_SOURCE_ROOT`
and an absolute `RELAY_CI_RESULTS_DIR` outside both tooling and private source.
The active workflow and helper require the exact Go 1.26.11 SDK. The module has no external Go
dependencies and uses the default Go build cache. Local qualification must copy
only this small helper and the reviewed source inputs into official bounded
scratch; it must not create a persistent runtime export or a second Go cache.

The source pins name exact reviewed controller source
`7f6500863f1f3c0cdcdd162e0cef1f512b87559d`. All fourteen pinned input blobs are
byte-identical to controller source `edde9b7d5d3aaa3e4ac01f231dab25da9b0cf41f`,
used by successful native deployment `run-20261115T091649ef7ca432`. This
is parity of these fourteen source inputs; it does not claim that 7f or its
other files are deployed. The native Relay selector still admits exactly
1.26.7/1.26.9/1.26.10 and refuses 1.26.11. Active public compilation remains
independently fixed to Go 1.26.11.

Final application S, private context P and public workflow G must be bound to
their actual identities and fresh effective policy before qualification. These
source pins alone are not hosted CI, application, merge or deployment approval;
the complete C42, verifier E and full `ops` closure remain required.

The active compiler assertion requires `runtime.Version()` to equal
`go1.26.11`, the root Relay module's sole `toolchain` declaration to equal
`go1.26.11`, and every owned Docker Go builder to equal
`golang:1.26.11-alpine`, including builders under nested VoIP. These active
public checks cannot select the historical profile. The separate isolated
binary inspector also requires actual produced binaries to report Go1.26.11.
The helper's module retains its admitted Go minimum and exact11 toolchain.
Historical 1.26.7, 1.26.9 and 1.26.10
positive/refusal controls use an explicit internal historical profile; no CLI,
environment variable or runtime input can select it during qualification.
The separate source binding and VoIP job require the nested VoIP module's
exact active toolchain. This app partition does not build or qualify Stage's
own module; `stage/sdk` has no separate module manifest.

The deployed native Relay selector is independent provenance. The parser
requires exactly `brightCRMReviewedToolchain(version string) (string, bool)`,
one switch with literal7/9/10 cases returning their exact Alpine images and
`true`, followed by a default literal empty image and `false`. Computed values,
extra/future/11 cases, missing/accepting default, extra statements and duplicate
selectors fail. The private report and driver require the explicit fields
`native_controller_profile: deployed-native-relay-7-9-10-v1`,
`native_go11_admitted: false`, and `public_go11_required: true`.

This deliberately records that the original native selector does not admit the
active app's Go11. It is the approved public compiler-validation profile, not
evidence that the original native Go11 lane passed. The unreleased
`deploy_brightcrm_compiler.go` dependency and its additional floor assertion are
removed from this profile; no deployed admission/default is weakened. All ten
selected guards, fixture/security/ownership rules and required six-job public
proof remain. The full current C42 dependency closure plus verifier E inputs,
complete `ops` execution root and exact policy/Hash/source bindings remain
independent context/verifier requirements; fourteen parser inputs are not a
replacement for that complete source closure.
