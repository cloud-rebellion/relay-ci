# Relay CI

This public repository contains Relay validation tooling. The application, hosted commercial code, operational source and Stage controller source remain in the private `cloud-rebellion/relay` repository. This is a CI counterpart, not a public edition of the application.

The Sustainable Use License in `LICENSE` applies to this tooling. It permits self-hosted, internal and customer-service use and retains the standard restriction on reselling the software or offering a competing hosted service. It is a fair-code license, not an OSI-approved open-source license.

## Three exact source identities

`profiles/relay.json` is a reviewed, immutable profile for one cohort:

- **G** is the actual public workflow checkout commit and `GITHUB_SHA`.
- **P** is the actual private context checkout HEAD, pinned in the profile. Git compiler exports use P.
- **S** is the deployment-origin commit, pinned separately and verified against the exact private context manifest. Frontend Flare release values and final-image revision labels use S after verification.

The current candidate pins application source S `1fc29087366c7c67d97e3278071ed7cd09177d99` and published private context P `655c87fed16ef6757d563c49e3bdbd400c27da05`, tree `7e72d94b3de1313633f48f30223c150d94dc63b6`. Its `relay-ci-context.json` SHA-256 is `15d5820729b9f900c499a6695178d53a89e7561b6be331dd92182de897c65e87` and binds 2,061 source entries totaling 21,741,416 bytes. The private context has an independent readback; the associated new public G still requires combined tooling qualification and its own exact six-job hosted cohort. Committed S and published P alone are not a successful public run, Stage source push, merge, deployment or live acceptance.

No driver substitutes P or S for `GITHUB_SHA`. The complete private manifest binds every tracked source path, Git mode, type, object ID, byte length and SHA-256, including full `brightcrm` and `ops` inputs and the additional selected guard provenance. Additions, deletions, links, modes and changed bytes refuse. The manifest's own hash and P are pinned in G; P is not embedded in its own manifest. A manifest alone is not proof that bytes were consumed or that a deployment is authorized.

The public tooling working tree is checked against G before and after physical drivers and before sealing. Untracked execution inputs outside the fixed private-source checkout, including Python bytecode, refuse. The trusted workflow, drivers, policy, catalogs, validators and profile are therefore execution inputs, rather than unverified labels attached to a report.

## Workflow and private diagnostics

Only trusted `main` pushes and manual runs on `main` use the repository-scoped read key. Fork pull requests do not receive or invoke it. The private source is fetched at one fixed P into `private-source`; Git output remains private. The temporary deploy-key file is removed before any application-controlled test or build starts. The key grants read access to the private Relay repository only. No production, provider, mail, Stage or broad GitHub credential is passed to test subprocesses.

Every application command's output is captured in a private runner temporary directory. Upload paths allow only an age-encrypted diagnostic archive and a public summary containing statuses, numeric counts and validated fingerprints. Raw test output, source findings, private paths, build diagnostics and failure contexts are never printed or uploaded as plaintext. Archives exclude compiler source exports, source maps, binaries and image archives. Reports are bounded to 64 MiB per file and 256 MiB total; retained encrypted artifacts expire after one day. Encryption failure fails the job and does not enable plaintext fallback.

Encryption uses age 1.3.2, pinned to the official Linux-amd64 release archive SHA-256 recorded in the profile. Only a public age recipient is stored here; its private identity is retained separately by the operator. GitHub's Ed25519 host key is pinned from the official `https://api.github.com/meta` response. Setup actions use full reviewed commit IDs. These keys and pins do not transfer production authority to the public repository.

## Actual qualification jobs

The workflow runs six finite jobs with no retries or skipped-test promotion:

1. **Core:** selected repository governance assertions, the complete registered frontend suite, production build and private source-map/manifest checks, all 97 compiled-browser cases, and complete Go vet/race package tests against real disposable PostgreSQL/Redis fixtures. Required invitation outcomes include new and existing identities, encoded padded tokens, preserved passwords/MFA, membership limits and anti-takeover behavior.
2. **VoIP:** the separate nested Go module, full vet/race package tests and explicit API, SIP and WebRTC builds. The legacy cache-cleaning build script is not used.
3. **Source security:** the existing source/provider-context/private-key/transport policy over both complete private roots, positive controls, full module vet and frozen strict frontend checks. Inherited scanner exclusions and unreadable, binary/NUL and >2 MiB walker limits remain explicit policy limits; this is not exhaustive secret-detection proof.
4. **Go vulnerabilities:** source-free scanner installation, hashed scanner binary, and read-only complete core and VoIP module scans. Findings and scanner errors fail. The inherited `@latest` scanner selection is recorded as an actual per-run identity, not described as an immutable cross-run pin.
5. **Final image:** production final-target build, immutable image ID and archive hash, and both fixed-CRITICAL and fixed-HIGH Trivy scans of the same read-only archive without a Docker socket. Existing `--ignore-unfixed` behavior is retained; no advisory exemption is added. The inherited Trivy reference is recorded as its actual pulled identity.
6. **Migrations:** complete synthetic PostgreSQL Up, ordinary last-three Down and complete replay, checking applied versions and unchanged migration/Goose bytes at each phase. This does not qualify populated-data restore or production downgrade safety.

Compiler/fixture pins are in `tooling/github/pins.json`: exact Go 1.26.11 and Bun 1.4.3, a separately documented PostgreSQL 16.15 fixture, and the existing exact Redis descriptor. Every job measures the actual host SDK and checks both private module toolchains and all owned Docker Go builders against exact 1.26.11. Historical Go 1.26.7/1.26.9/1.26.10 cases exist only in explicit refusal/regression controls; none is an active release compiler. The PostgreSQL fixture choice does not change the production database. Selected governance ports record their exact source provenance and explicit applicability; complete private inputs remain required.

The core server and three existing VoIP build outputs also receive inert embedded-GoVersion readback. The final-image job reads only `/usr/local/bin/brightcrm` from the same immutable image it archives and scans, using Docker-daemon archive copying from a bounded, read-only, network-disabled container that is never started. It checks the fixed single regular member and never invokes image-supplied tools or the application entrypoint. Missing or nonexact Go 1.26.11 binary metadata refuses. Binary bytes and private module metadata are excluded from public diagnostics.

The exact application source S, private context P and public workflow G are independent profile identities. The single explicit deployed-controller profile records native selector capability 1.26.7/1.26.9/1.26.10 and `native_go11_admitted: false`; the independent active public compiler remains Go 1.26.11. Guard provenance uses reviewed source `7f6500863f1f3c0cdcdd162e0cef1f512b87559d`. Its fourteen pinned input blobs are byte-identical to controller source `edde9b7d5d3aaa3e4ac01f231dab25da9b0cf41f`, used by successful native deployment `run-20261115T091649ef7ca432`. That source-input parity does not claim that 7f or its other files are deployed. Unreleased compiler-floor/image callback helpers are not required by this profile. Complete actual declared dependencies, verifier inputs and both execution roots remain mandatory. The earlier G1/G2 profiles and failed runs remain historical evidence. They do not qualify this successor, and the source profile refuses execution until its actual final identities are pinned.

## Release boundary

A successful public run supplies real qualification evidence for its exact G/P/S profile. It is not a Stage check, does not fabricate Stage receipts, and performs no deployment. The operator must independently review the trusted profile/workflow, all required jobs and latest attempt, decrypted original evidence, complete source/policy/execution mapping and image identity before admitting an OVH release. Existing exact-source, manual, database, writer-stop, migration, recovery and live-acceptance guards remain separate requirements.

Current preparation and local helper-control results must not be described as a successful hosted cohort, deployed application or working production invitation. Those claims require their actual run, deployment and authenticated live journey evidence.
