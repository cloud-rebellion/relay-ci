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
fourteen private Stage inputs at the stated source revision. The helper refuses
missing or changed inputs. It parses reviewed policy declarations with Go's AST
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
The reviewed workflow supplies Go 1.26.10. The module has no external Go
dependencies and uses the default Go build cache. Local qualification must copy
only this small helper and the reviewed source inputs into official bounded
scratch; it must not create a persistent runtime export or a second Go cache.
