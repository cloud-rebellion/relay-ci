package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root, path, body string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}
func cleanFixture(t *testing.T) (string, policy) {
	t.Helper()
	root := t.TempDir()
	write(t, root, "brightcrm/go.mod", "module github.com/bright-interaction/brightcrm\n\ngo 1.26.3\n\ntoolchain go1.26.11\n")
	write(t, root, "brightcrm/Dockerfile", "FROM golang:1.26.11-alpine AS builder\nRUN go build ./cmd/server\nFROM alpine:3.23\n")
	write(t, root, "ops/scripts/nocodb-to-espocrm-import.py", "import os\nkey = os.environ[\"ESPOCRM_API_KEY\"]\n")
	p := policy{
		services: []string{"brightcrm"}, trivy: []string{"brightcrm"},
		exempt: map[string]string{}, ciExempt: map[string]string{}, raceDebt: map[string]string{},
		provider: `AKIA[0-9A-Z]{16}`, includes: []string{"*.go", "*.sh"},
		credentialIncludes: []string{"*.go", "*.py", "*.md"}, excludeDirs: []string{"tests"}, excludeFiles: []string{"*_test.go"},
		credentials:  []credentialRule{{`(?i)ESPOCRM_API_KEY\s*=\s*["']?([^\s"']+)`, []candidate{{1, 20}}}},
		manualDeploy: true,
	}
	return root, p
}
func assertResult(t *testing.T, r report, name, status string) result {
	t.Helper()
	for _, assertion := range r.Assertions {
		if assertion.Name == name {
			if assertion.Status != status {
				t.Fatalf("%s status %s, want %s", name, assertion.Status, status)
			}
			return assertion
		}
	}
	t.Fatalf("missing assertion %s", name)
	return result{}
}
func TestCleanAndExplicitApplicability(t *testing.T) {
	root, p := cleanFixture(t)
	r := runGuards(root, p)
	if r.Status != "passed" || len(r.Assertions) != 10 || r.NativeControllerProfile != deployedNativeRelay7910Profile || r.NativeGo11Admitted || !r.PublicGo11Required {
		t.Fatalf("clean profile not qualified: %+v", r)
	}
	for _, index := range []int{0, 3, 4, 6} {
		a := r.Assertions[index]
		if a.Checked != 0 || !strings.Contains(a.Applicability, "native") {
			t.Fatalf("native optional case lost explicit applicability: %+v", a)
		}
	}
}
func TestSelectedPolicyRefusals(t *testing.T) {
	t.Run("ungated-module", func(t *testing.T) {
		root, p := cleanFixture(t)
		p.services = nil
		r := runGuards(root, p)
		assertResult(t, r, guardNames[2], "failed")
	})
	t.Run("empty-reason", func(t *testing.T) {
		root, p := cleanFixture(t)
		p.services = nil
		p.exempt["brightcrm"] = ""
		r := runGuards(root, p)
		assertResult(t, r, guardNames[2], "failed")
	})
	t.Run("missing-image-membership", func(t *testing.T) {
		root, p := cleanFixture(t)
		p.trivy = nil
		r := runGuards(root, p)
		assertResult(t, r, guardNames[1], "failed")
	})
	t.Run("trigger-drift", func(t *testing.T) {
		root, p := cleanFixture(t)
		p.manualDeploy = false
		r := runGuards(root, p)
		assertResult(t, r, guardNames[1], "failed")
	})
	t.Run("stale-module-exemption", func(t *testing.T) {
		root, p := cleanFixture(t)
		p.exempt["brightcrm"] = "elsewhere"
		if err := os.Remove(filepath.Join(root, "brightcrm/go.mod")); err != nil {
			t.Fatal(err)
		}
		r := runGuards(root, p)
		assertResult(t, r, guardNames[4], "failed")
	})
	t.Run("absent-owned-root", func(t *testing.T) {
		r := runGuards(t.TempDir(), policy{})
		if r.Status != "failed" || r.Refusal == "" {
			t.Fatal("absent owned root passed")
		}
	})
}
func TestPublishContractAndFalseGreen(t *testing.T) {
	root, p := cleanFixture(t)
	write(t, root, "brightcrm/scripts/split-public-repo.sh", "#!/bin/sh\n")
	r := runGuards(root, p)
	a := assertResult(t, r, guardNames[3], "failed")
	if len(a.Findings) != 2 {
		t.Fatal("publisher missing both CI inputs was not refused")
	}
	write(t, root, "brightcrm/scripts/ci.sh", "#!/bin/sh\nset -e\n( false ) && echo OK\n")
	r = runGuards(root, p)
	assertResult(t, r, guardNames[0], "failed")
	assertResult(t, r, guardNames[3], "failed")
	write(t, root, "brightcrm/.github/workflows/ci.yml", "name: fixture\n")
	write(t, root, "brightcrm/scripts/ci.sh", "#!/bin/sh\nset -e\n# ( false ) && echo OK\nif true; then echo OK; else exit 1; fi\n")
	r = runGuards(root, p)
	assertResult(t, r, guardNames[0], "passed")
	assertResult(t, r, guardNames[3], "passed")
}
func TestRaceParityExactTokens(t *testing.T) {
	cases := []struct {
		name, script string
		count        int
		failed       bool
	}{
		{"missing-race", "go test ./...", 1, true},
		{"false-race", "go test -race=false ./...", 1, true},
		{"comment-race", "go test ./... # -race", 1, true},
		{"correct", "go_release test -race ./...", 1, false},
		{"separate-ee", "go test -race -tags ee ./...", 1, false},
		{"e2e", "go test -tags=e2e ./...", 0, false},
		{"separate-e2e", "go test -tags e2e ./...", 0, false},
		{"nonadjacent", "go env test ./...", 0, false},
		{"wrong-package", "go test ./...extra", 0, false},
		{"comment-only", "# go test ./...", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, p := cleanFixture(t)
			write(t, root, "brightcrm/scripts/ci.sh", tc.script+"\n")
			r := runGuards(root, p)
			status := "passed"
			if tc.failed {
				status = "failed"
			}
			a := assertResult(t, r, guardNames[6], status)
			if a.Checked != tc.count {
				t.Fatalf("matched %d want %d", a.Checked, tc.count)
			}
		})
	}
	t.Run("unreachable-debt", func(t *testing.T) {
		root, p := cleanFixture(t)
		p.raceDebt["brightcrm"] = "reviewed fixture"
		assertResult(t, runGuards(root, p), guardNames[6], "failed")
	})
	t.Run("stale-debt", func(t *testing.T) {
		root, p := cleanFixture(t)
		p.raceDebt["brightcrm"] = "reviewed fixture"
		write(t, root, "brightcrm/scripts/ci.sh", "go test -race ./...\n")
		assertResult(t, runGuards(root, p), guardNames[6], "failed")
	})
}
func TestCompilerRefusals(t *testing.T) {
	cases := []struct{ name, path, body string }{
		{"older-builder", "brightcrm/Dockerfile", "FROM golang:1.26.7-alpine AS builder\nFROM alpine:3.23\n"},
		{"newer-builder", "brightcrm/Dockerfile", "FROM golang:1.26.12-alpine AS builder\nFROM alpine:3.23\n"},
		{"nested-builder", "brightcrm/tools/helper.Dockerfile", "FROM golang:1.26.9-alpine\n"},
		{"floating-builder", "brightcrm/Dockerfile", "FROM golang:1.26-alpine\n"},
		{"variable-builder", "brightcrm/Dockerfile", "ARG GO_VERSION\nFROM golang:${GO_VERSION}-alpine\n"},
		{"fake-from-under-run", "brightcrm/Dockerfile", "FROM alpine:3.23\nRUN echo safe \\\nFROM golang:1.26.11-alpine\n"},
		{"heredoc", "brightcrm/Dockerfile", "FROM golang:1.26.11-alpine\nRUN <<EOF\necho test\nEOF\n"},
		{"unsupported-base", "brightcrm/Dockerfile", "FROM golang:1.26.11-alpine\nFROM private/runtime:latest\n"},
		{"duplicate-alias", "brightcrm/Dockerfile", "FROM golang:1.26.11-alpine AS build\nFROM alpine:3.23 AS build\n"},
		{"missing-from", "brightcrm/Dockerfile", "RUN true\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, p := cleanFixture(t)
			write(t, root, tc.path, tc.body)
			assertResult(t, runGuards(root, p), guardNames[5], "failed")
		})
	}
	for _, mod := range []string{
		"module github.com/bright-interaction/brightcrm\ngo 1.27.0\ntoolchain go1.26.11\n",
		"module github.com/bright-interaction/brightcrm\ngo 1.26.3\ntoolchain go1.26.12\n",
		"module wrong\ngo 1.26.3\ntoolchain go1.26.11\n",
		"module github.com/bright-interaction/brightcrm\ngo 1.26.3\ntoolchain go1.26.11\ntoolchain go1.26.11\n",
	} {
		if _, err := toolchainFromModule([]byte(mod)); err == nil {
			t.Fatal("unreviewed module compiler passed")
		}
	}
	t.Run("symlink-input", func(t *testing.T) {
		root, p := cleanFixture(t)
		target := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(target, []byte("FROM golang:1.26.11-alpine\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(root, "brightcrm/Dockerfile")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, "brightcrm/Dockerfile")); err != nil {
			t.Fatal(err)
		}
		assertResult(t, runGuards(root, p), guardNames[5], "failed")
	})
}
func nativePolicyFixture() string {
	return `package fixture
func brightCRMReviewedToolchain(version string) (string, bool) {
 switch version {
 case "1.26.7": return "golang:1.26.7-alpine", true
 case "1.26.9": return "golang:1.26.9-alpine", true
 case "1.26.10": return "golang:1.26.10-alpine", true
 default: return "", false
 }
}`
}
func TestDeployedNativeCompilerProfile(t *testing.T) {
	clean := nativePolicyFixture()
	file, err := parse([]byte(clean))
	if err != nil || deployedNativeCompilerPolicy(file) != nil {
		t.Fatal("exact deployed native7/9/10 selector refused")
	}
	cases := map[string]string{
		"native11-is-not-deployed": strings.Replace(clean, "default:", `case "1.26.11": return "golang:1.26.11-alpine", true; default:`, 1),
		"future12":                 strings.Replace(clean, "1.26.10", "1.26.12", 1),
		"wrong-image":              strings.Replace(clean, "golang:1.26.10-alpine", "golang:1.26.11-alpine", 1),
		"computed-image":           strings.Replace(clean, `"golang:1.26.10-alpine", true`, `imageFor(version), true`, 1),
		"default-acceptance":       strings.Replace(clean, `"", false`, `"", true`, 1),
		"default-computed":         strings.Replace(clean, `"", false`, `fallback(version), false`, 1),
		"missing-default":          strings.Replace(clean, `default: return "", false`, `case "1.26.8": return "", false`, 1),
		"duplicate-case":           strings.Replace(clean, `case "1.26.9":`, `case "1.26.7":`, 1),
		"hidden-statement":         strings.Replace(clean, `case "1.26.9": return`, `case "1.26.9": sideEffect(); return`, 1),
		"duplicate-selector":       clean + strings.TrimPrefix(clean, "package fixture"),
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			file, err := parse([]byte(source))
			if err != nil {
				t.Fatal(err)
			}
			if deployedNativeCompilerPolicy(file) == nil {
				t.Fatal("unreviewed native selector admitted")
			}
		})
	}
}

func TestActiveCompilerFloor(t *testing.T) {
	for _, version := range []string{"go1.26.7", "go1.26.9", "go1.26.10", "go1.26.12", "go1.26", "devel go1.26.11", "go1.26.11 X:boringcrypto"} {
		t.Run("host-"+version, func(t *testing.T) {
			if requireActiveHostCompiler(version) == nil {
				t.Fatal("nonexact host SDK passed active profile")
			}
		})
	}
	if err := requireActiveHostCompiler("go1.26.11"); err != nil {
		t.Fatal("exact active host SDK refused")
	}
	root, _ := cleanFixture(t)
	write(t, root, "brightcrm/voip/go.mod", "module github.com/bright-interaction/brightcrm-voip\ngo 1.26.3\ntoolchain go1.26.11\n")
	write(t, root, "brightcrm/voip/Dockerfile", "FROM golang:1.26.11-alpine AS builder\nFROM alpine:3.23\n")
	if builders, findings, err := compilerParity(root); err != nil || builders != 2 || len(findings) != 0 {
		t.Fatalf("complete active compiler fixture refused: builders=%d findings=%v err=%v", builders, findings, err)
	}
	for _, version := range []string{"1.26.7", "1.26.9", "1.26.10", "1.26.12"} {
		t.Run("module-"+version, func(t *testing.T) {
			raw := []byte("module github.com/bright-interaction/brightcrm\ngo 1.26.3\ntoolchain go" + version + "\n")
			if _, err := toolchainFromModule(raw); err == nil {
				t.Fatal("nonexact module compiler passed active profile")
			}
		})
		t.Run("nested-builder-"+version, func(t *testing.T) {
			write(t, root, "brightcrm/voip/Dockerfile", "FROM golang:"+version+"-alpine\n")
			_, findings, err := compilerParity(root)
			if err == nil && len(findings) == 0 {
				t.Fatal("nonexact nested builder passed active profile")
			}
		})
	}
}
func TestHistoricalCompilerProfile(t *testing.T) {
	for _, version := range []string{"1.26.7", "1.26.9", "1.26.10"} {
		t.Run(version, func(t *testing.T) {
			root, _ := cleanFixture(t)
			module := "module github.com/bright-interaction/brightcrm\ngo 1.26.3\ntoolchain go" + version + "\n"
			write(t, root, "brightcrm/go.mod", module)
			write(t, root, "brightcrm/Dockerfile", "FROM golang:"+version+"-alpine AS build\nFROM build AS verify\nFROM alpine:3.23\n")
			if _, findings, err := compilerParityFor(root, historicalCompilerProfile); err != nil || len(findings) != 0 {
				t.Fatalf("explicit historical fixture refused: %v %v", findings, err)
			}
			if _, err := toolchainFromModule([]byte(module)); err == nil {
				t.Fatal("historical fixture qualified active release")
			}
			write(t, root, "brightcrm/nested/helper.Dockerfile", "FROM golang:1.26.11-alpine\n")
			if _, findings, err := compilerParityFor(root, historicalCompilerProfile); err == nil && len(findings) == 0 {
				t.Fatal("historical compiler mismatch passed")
			}
		})
	}
	active := []byte("module github.com/bright-interaction/brightcrm\ngo 1.26.3\ntoolchain go1.26.11\n")
	if _, err := toolchainFromModuleFor(active, historicalCompilerProfile); err == nil {
		t.Fatal("active cohort silently became historical")
	}
	if _, err := toolchainFromModuleFor(active, compilerProfile(99)); err == nil {
		t.Fatal("unknown profile passed")
	}
}

func TestProviderAndContextCredentialControls(t *testing.T) {
	root, p := cleanFixture(t)
	provider := "AKIA" + "IOSFODNN7EXAMPLE"
	credential := "Op7" + strings.Repeat("K", 29)
	write(t, root, "brightcrm/live.go", "package fixture\nvar key = \""+provider+"\"\n")
	write(t, root, "brightcrm/import.py", "ESPOCRM_API_KEY = \""+credential+"\"\n")
	r := runGuards(root, p)
	assertResult(t, r, guardNames[7], "failed")
	assertResult(t, r, guardNames[8], "failed")
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), provider) || strings.Contains(string(raw), credential) {
		t.Fatal("raw planted credential escaped into governance report")
	}
	write(t, root, "brightcrm/live.go", "package fixture\n")
	write(t, root, "brightcrm/import.py", "ESPOCRM_API_KEY = os.environ[\"ESPOCRM_API_KEY\"]\n")
	write(t, root, "brightcrm/fixture_test.go", "package fixture\nvar key = \""+provider+"\"\n")
	write(t, root, "brightcrm/tests/fixture.go", "package fixture\nvar key = \""+provider+"\"\n")
	r = runGuards(root, p)
	assertResult(t, r, guardNames[7], "passed")
	assertResult(t, r, guardNames[8], "passed")
}
func TestCredentialCandidateClassification(t *testing.T) {
	for _, value := range []string{"${ESPOCRM_API_KEY:?required}", "<YOUR_API_KEY>", "placeholder_123456789012345678901234", strings.Repeat("A", 32), strings.Repeat("1", 32), "https://example.test/Op712345678901234567890"} {
		if literalCredential(value, 20) {
			t.Fatal("reference or placeholder became a credential")
		}
	}
	if !literalCredential("Op7"+strings.Repeat("K", 29), 20) {
		t.Fatal("literal credential was missed")
	}
}
func TestOperationalExternalCredentialMarker(t *testing.T) {
	root, p := cleanFixture(t)
	write(t, root, "ops/scripts/nocodb-to-espocrm-import.py", "import os\nkey = os.getenv(\"ESPOCRM_API_KEY\", \"\")\n")
	assertResult(t, runGuards(root, p), guardNames[9], "failed")
	if err := os.Remove(filepath.Join(root, "ops/scripts/nocodb-to-espocrm-import.py")); err != nil {
		t.Fatal(err)
	}
	assertResult(t, runGuards(root, p), guardNames[9], "failed")
}
func registrySource(extra string) string {
	var b strings.Builder
	b.WriteString("package fixture\nvar repoCoverageGuardTests=[]string{\n")
	for _, name := range guardNames {
		fmt.Fprintf(&b, "%q,\n", name)
	}
	if extra != "" {
		fmt.Fprintf(&b, "%q,\n", extra)
	}
	b.WriteString("}\nvar repoCoverageGuardOwners=map[string][]string{\n")
	for _, name := range guardNames {
		fmt.Fprintf(&b, "%q:{\"@subjects\"},\n", name)
	}
	if extra != "" {
		fmt.Fprintf(&b, "%q:{\"brightcrm\"},\n", extra)
	}
	b.WriteString("}\n")
	return b.String()
}
func TestRegistryCannotOmitDuplicateOrAddSelectedGuard(t *testing.T) {
	clean := registrySource("")
	f, err := parse([]byte(clean))
	if err != nil {
		t.Fatal(err)
	}
	selected, err := selectedGuards(f)
	if err != nil || len(selected) != 10 {
		t.Fatal("reviewed selection rejected")
	}
	cases := []string{
		strings.Replace(clean, fmt.Sprintf("%q,", guardNames[0]), "", 1),
		strings.Replace(clean, fmt.Sprintf("%q,", guardNames[0]), fmt.Sprintf("%q,%q,", guardNames[0], guardNames[0]), 1),
		registrySource("TestNewRelayGuard"),
		strings.Replace(clean, "{\"@subjects\"}", "{\"@unknown\"}", 1),
		strings.Replace(clean, "{\"@subjects\"}", "{\"@estate\"}", 1),
	}
	for i, source := range cases {
		f, err := parse([]byte(source))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := selectedGuards(f); err == nil {
			t.Fatalf("registry mutation %d passed", i)
		}
	}
	t.Run("private-policy-declarations-are-data", func(t *testing.T) {
		inputs := policyASTFixture(t)
		p, err := readPolicy(inputs)
		if err != nil {
			t.Fatalf("closed AST profile failed: %v", err)
		}
		if !p.manualDeploy || !contains(p.services, "brightcrm") || len(p.credentials) != 1 || len(p.credentialIncludes) != 3 {
			t.Fatal("policy data extraction lost required facts")
		}
		root, _ := cleanFixture(t)
		write(t, root, "brightcrm/import.py", "ESPOCRM_API_KEY=Op7"+strings.Repeat("K", 29)+"\n")
		assertResult(t, runGuards(root, p), guardNames[8], "failed")
	})
	for _, tc := range []struct{ name, file, source string }{
		{"different-owned-root", "component_impact.go", `package fixture; var componentDefinitions=[]T{{program:"brightcrm",root:"other",goTarget:"brightcrm"}}`},
		{"changed-trigger", "deploy_brightcrm.go", `package fixture; func brightcrmDeploySpec()T{return T{Trigger:sdk.Push{}}}`},
		{"missing-rules", "security_gate.go", `package fixture; var secretScanFileGlobs=[]string{"*.go"}`},
		{"native-selector-widened", "ci_brightcrm_toolchain.go", strings.Replace(nativePolicyFixture(), "1.26.10", "1.26.11", 1)},
		{"native-selector-missing", "ci_brightcrm_toolchain.go", `package fixture; func different() {}`},
		{"native-selector-default-allows", "ci_brightcrm_toolchain.go", strings.Replace(nativePolicyFixture(), `"", false`, `"", true`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inputs := policyASTFixture(t)
			f, err := parse([]byte(tc.source))
			if err != nil {
				t.Fatal(err)
			}
			inputs[tc.file] = f
			if _, err := readPolicy(inputs); err == nil {
				t.Fatal("malformed or widened policy profile passed")
			}
		})
	}
}

func policyASTFixture(t *testing.T) map[string]*ast.File {
	t.Helper()
	sources := map[string]string{
		"ci_go.go":                  registrySource("") + `var ciGoServices=[]string{"brightcrm"};var ciGoExempt=map[string]string{}`,
		"ci_contract_test.go":       `package fixture;var ciExempt=map[string]string{};var ciRaceParityDebt=map[string]string{}`,
		"component_impact.go":       `package fixture;var componentDefinitions=[]T{{program:"brightcrm",root:"brightcrm",goTarget:"brightcrm"}}`,
		"security_trivy.go":         `package fixture;var securityTrivyServices=[]string{"brightcrm"}`,
		"deploy_brightcrm.go":       `package fixture;func brightcrmDeploySpec()T{return T{Trigger:sdk.Manual{}}}`,
		"ci_brightcrm_toolchain.go": nativePolicyFixture(),
		"security_gate.go": `package fixture
const hardcodedAPIKeyPattern="AKIA[0-9A-Z]{16}"
var secretScanFileGlobs=[]string{"*.go"}
var secretScanExcludeDirs=[]string{"tests"}
var secretScanExcludeFiles=[]string{"*_test.go"}
var serviceCredentialScanFileGlobs=append(append([]string(nil),secretScanFileGlobs...),"*.py","*.txt")
var hardcodedServiceCredentialRules=[]T{{pattern:"ESPOCRM_API_KEY=([^ ]+)",candidates:[]C{{group:1,minLength:20}}}}
`,
	}
	for _, name := range guardNames {
		sources["ci_contract_test.go"] += ";func " + name + "(t *testing.T){}"
	}
	inputs := map[string]*ast.File{}
	for name, source := range sources {
		f, err := parse([]byte(source))
		if err != nil {
			t.Fatal(err)
		}
		inputs[name] = f
	}
	return inputs
}
func TestProvenanceMissingTamperedAndUnboundedInput(t *testing.T) {
	root := t.TempDir()
	origin := filepath.Join(t.TempDir(), "source-origin.json")
	if _, err := loadInputs(root, origin); err == nil {
		t.Fatal("missing provenance passed")
	}
	names := append([]string{}, requiredNativeInputNames...)
	pins := provenance{Schema: 1, NativeControllerProfile: deployedNativeRelay7910Profile, SourceCommit: strings.Repeat("a", 40)}
	for _, name := range names {
		path := "stage/userworkflows/" + name
		raw := []byte("package fixture\n")
		digest := sha256.Sum256(raw)
		write(t, root, path, string(raw))
		pins.Inputs = append(pins.Inputs, sourcePin{path, strings.Repeat("b", 40), hex.EncodeToString(digest[:])})
	}
	raw, err := json.Marshal(pins)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(origin, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInputs(root, origin); err != nil {
		t.Fatalf("bounded exact source rejected: %v", err)
	}
	for name, mutate := range map[string]func(*provenance){
		"missing-profile":                          func(p *provenance) { p.NativeControllerProfile = "" },
		"unknown-profile":                          func(p *provenance) { p.NativeControllerProfile = "native11-or-auto" },
		"omitted-required-pin":                     func(p *provenance) { p.Inputs = p.Inputs[1:] },
		"unreleased-helper-in-place-of-native-pin": func(p *provenance) { p.Inputs[0].Path = "stage/userworkflows/deploy_brightcrm_compiler.go" },
		"legacy-fifteen-input-closure": func(p *provenance) {
			p.Inputs = append(p.Inputs, sourcePin{"stage/userworkflows/deploy_brightcrm_compiler.go", p.Inputs[0].Blob, p.Inputs[0].SHA256})
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := pins
			candidate.Inputs = append([]sourcePin{}, pins.Inputs...)
			mutate(&candidate)
			body, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(origin, body, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadInputs(root, origin); err == nil {
				t.Fatal("unknown/partial native profile passed")
			}
		})
	}
	if err := os.WriteFile(origin, append(append([]byte{}, raw...), []byte(" {}")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInputs(root, origin); err == nil {
		t.Fatal("trailing provenance passed")
	}
	if err := os.WriteFile(origin, raw, 0600); err != nil {
		t.Fatal(err)
	}
	write(t, root, pins.Inputs[0].Path, "package changed\n")
	if _, err := loadInputs(root, origin); err == nil {
		t.Fatal("same-path payload tamper passed")
	}
	write(t, root, pins.Inputs[0].Path, "package fixture\n")
	if err := os.Remove(filepath.Join(root, pins.Inputs[0].Path)); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInputs(root, origin); err == nil {
		t.Fatal("missing private source passed")
	}
	write(t, root, pins.Inputs[0].Path, strings.Repeat("x", (1<<20)+1))
	if _, err := loadInputs(root, origin); err == nil {
		t.Fatal("oversize private source passed")
	}
	write(t, root, pins.Inputs[0].Path, "package fixture\n")
	pins.Inputs = pins.Inputs[:13]
	raw, err = json.Marshal(pins)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(origin, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInputs(root, origin); err == nil {
		t.Fatal("truncated source closure passed")
	}
}
