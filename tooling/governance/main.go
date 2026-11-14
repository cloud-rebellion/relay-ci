// Relay-only portable equivalents of the ten selected repository guards.
// Private policy declarations are parsed as data; no Stage source is executed.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

var guardNames = []string{
	"TestCIScriptsCannotSilentlyPass",
	"TestEveryDeployedImageIsTrivyScanned",
	"TestEveryGoModuleIsGatedOrExempt",
	"TestEveryPublishableProductHasCI",
	"TestCIGoExemptOnlyNamesRealModules",
	"TestServiceDockerfilesMatchScanToolchain",
	"TestCIScriptsRunRaceWhereCIGoDoes",
	"TestSecurityGateProductionRootsHaveNoHardcodedProviderCredentialShapes",
	"TestSecurityGateRepositoryHasNoHardcodedServiceCredentials",
	"TestOperationalScriptsRequireExternalCredentials",
}

type sourcePin struct {
	Path   string `json:"path"`
	Blob   string `json:"blob"`
	SHA256 string `json:"sha256"`
}
type provenance struct {
	Schema       int         `json:"schema"`
	SourceCommit string      `json:"source_commit"`
	Inputs       []sourcePin `json:"inputs"`
}
type result struct {
	Name          string   `json:"name"`
	Status        string   `json:"status"`
	Checked       int      `json:"checked"`
	Applicability string   `json:"applicability"`
	Findings      []string `json:"findings"`
}
type report struct {
	Schema             int      `json:"schema"`
	Status             string   `json:"status"`
	Scope              string   `json:"scope"`
	SelectedGuardCount int      `json:"selected_guard_count"`
	Assertions         []result `json:"assertions"`
	Refusal            string   `json:"refusal,omitempty"`
}
type candidate struct{ group, minimum int }
type credentialRule struct {
	pattern    string
	candidates []candidate
}
type policy struct {
	services, trivy, includes, credentialIncludes, excludeDirs, excludeFiles []string
	exempt, ciExempt, raceDebt                                               map[string]string
	provider                                                                 string
	credentials                                                              []credentialRule
	manualDeploy                                                             bool
}

func fail(message string) error { return errors.New(message) }
func literal(e ast.Expr) (string, error) {
	v, ok := e.(*ast.BasicLit)
	if !ok || v.Kind != token.STRING {
		return "", fail("policy value is not a string literal")
	}
	return strconv.Unquote(v.Value)
}
func integer(e ast.Expr) (int, error) {
	v, ok := e.(*ast.BasicLit)
	if !ok || v.Kind != token.INT {
		return 0, fail("policy value is not an integer")
	}
	return strconv.Atoi(v.Value)
}
func composite(e ast.Expr) (*ast.CompositeLit, error) {
	v, ok := e.(*ast.CompositeLit)
	if !ok {
		return nil, fail("policy declaration is not a literal collection")
	}
	return v, nil
}
func stringList(e ast.Expr) ([]string, error) {
	c, err := composite(e)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, item := range c.Elts {
		value, e := literal(item)
		if e != nil {
			return nil, e
		}
		out = append(out, value)
	}
	return out, nil
}
func stringMap(e ast.Expr) (map[string]string, error) {
	c, err := composite(e)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, item := range c.Elts {
		kv, ok := item.(*ast.KeyValueExpr)
		if !ok {
			return nil, fail("policy map entry is not keyed")
		}
		key, err := literal(kv.Key)
		if err != nil {
			return nil, err
		}
		value, err := literal(kv.Value)
		if err != nil {
			return nil, err
		}
		if _, duplicate := out[key]; duplicate {
			return nil, fail("duplicate policy map key")
		}
		out[key] = value
	}
	return out, nil
}
func fields(e ast.Expr) (map[string]ast.Expr, error) {
	c, err := composite(e)
	if err != nil {
		return nil, err
	}
	out := map[string]ast.Expr{}
	for _, item := range c.Elts {
		kv, ok := item.(*ast.KeyValueExpr)
		if !ok {
			return nil, fail("policy struct is not keyed")
		}
		id, ok := kv.Key.(*ast.Ident)
		if !ok {
			return nil, fail("policy struct key is not an identifier")
		}
		if _, exists := out[id.Name]; exists {
			return nil, fail("duplicate policy struct field")
		}
		out[id.Name] = kv.Value
	}
	return out, nil
}
func declarations(f *ast.File) map[string]ast.Expr {
	out := map[string]ast.Expr{}
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, s := range g.Specs {
			v, ok := s.(*ast.ValueSpec)
			if !ok || len(v.Names) != len(v.Values) {
				continue
			}
			for i, name := range v.Names {
				out[name.Name] = v.Values[i]
			}
		}
	}
	return out
}
func parse(raw []byte) (*ast.File, error) {
	return parser.ParseFile(token.NewFileSet(), "private-policy.go", raw, 0)
}
func contains(values []string, value string) bool {
	for _, x := range values {
		if x == value {
			return true
		}
	}
	return false
}
func canonicalPath(path string) bool {
	return path != "" && !filepath.IsAbs(path) && filepath.ToSlash(filepath.Clean(path)) == path && !strings.HasPrefix(path, "../") && !strings.Contains(path, "\\")
}
func regularRead(root, path string, limit int64) ([]byte, error) {
	if !canonicalPath(path) {
		return nil, fail("noncanonical private input")
	}
	current := root
	for _, part := range strings.Split(path, "/") {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, fail("private input is missing or symbolic")
		}
	}
	info, err := os.Stat(current)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, fail("private input is not a bounded regular file")
	}
	raw, err := os.ReadFile(current)
	if err != nil || len(raw) == 0 || int64(len(raw)) > limit {
		return nil, fail("private input read failed")
	}
	return raw, nil
}
func loadInputs(root, origin string) (map[string]*ast.File, error) {
	raw, err := os.ReadFile(origin)
	if err != nil {
		return nil, fail("governance provenance missing")
	}
	var pins provenance
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	// Additional descriptive provenance fields belong to mapping.json, not this closed input manifest.
	if dec.Decode(&pins) != nil || pins.Schema != 1 || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(pins.SourceCommit) || len(pins.Inputs) != 14 {
		return nil, fail("governance provenance malformed")
	}
	out := map[string]*ast.File{}
	previous := ""
	for _, pin := range pins.Inputs {
		if !strings.HasPrefix(pin.Path, "stage/userworkflows/") || !strings.HasSuffix(pin.Path, ".go") || pin.Path <= previous || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(pin.Blob) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(pin.SHA256) {
			return nil, fail("governance provenance is not canonical")
		}
		previous = pin.Path
		body, err := regularRead(root, pin.Path, 1<<20)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(body)
		if hex.EncodeToString(digest[:]) != pin.SHA256 {
			return nil, fail("unreviewed governance source bytes")
		}
		file, err := parse(body)
		if err != nil {
			return nil, fail("private governance source does not parse")
		}
		out[filepath.Base(pin.Path)] = file
	}
	for _, name := range []string{"ci_go.go", "ci_coverage_test.go", "ci_contract_test.go", "ci_go_toolchain_parity_test.go", "security_coverage_test.go", "security_gate_scan_test.go", "security_trivy.go", "repo_coverage_scope.go", "repo_coverage_registry.go", "component_impact.go", "product_policy.go", "security_gate.go", "ci_brightcrm_toolchain.go", "deploy_brightcrm.go"} {
		if out[name] == nil {
			return nil, fail("required governance source omitted")
		}
	}
	return out, nil
}

func selectedGuards(f *ast.File) ([]string, error) {
	d := declarations(f)
	tests, err := stringList(d["repoCoverageGuardTests"])
	if err != nil || len(tests) == 0 {
		return nil, fail("guard registry missing")
	}
	owners, err := composite(d["repoCoverageGuardOwners"])
	if err != nil {
		return nil, err
	}
	policies := map[string][]string{}
	for _, entry := range owners.Elts {
		kv, ok := entry.(*ast.KeyValueExpr)
		if !ok {
			return nil, fail("guard ownership malformed")
		}
		name, err := literal(kv.Key)
		if err != nil {
			return nil, err
		}
		values, err := stringList(kv.Value)
		if err != nil || len(values) == 0 || !sort.StringsAreSorted(values) {
			return nil, fail("guard ownership malformed")
		}
		if _, exists := policies[name]; exists {
			return nil, fail("duplicate guard ownership")
		}
		seen := map[string]bool{}
		for _, value := range values {
			if value == "" || strings.TrimSpace(value) != value || seen[value] {
				return nil, fail("noncanonical guard owner")
			}
			seen[value] = true
			if strings.HasPrefix(value, "@") && (len(values) != 1 || (value != "@subjects" && value != "@estate" && value != "@product")) {
				return nil, fail("unknown or mixed guard owner")
			}
		}
		policies[name] = values
	}
	seen := map[string]bool{}
	var selected []string
	for _, name := range tests {
		if seen[name] || len(policies[name]) == 0 {
			return nil, fail("duplicate or unowned registered guard")
		}
		seen[name] = true
		for _, owner := range policies[name] {
			if owner == "brightcrm" || owner == "@subjects" || owner == "@product" {
				selected = append(selected, name)
				break
			}
		}
	}
	if len(seen) != len(policies) {
		return nil, fail("unregistered guard ownership")
	}
	if len(selected) != len(guardNames) {
		return nil, fail("Relay guard selection changed")
	}
	for _, name := range guardNames {
		if !contains(selected, name) {
			return nil, fail("required Relay guard omitted")
		}
	}
	return selected, nil
}
func readPolicy(inputs map[string]*ast.File) (policy, error) {
	p := policy{}
	if _, err := selectedGuards(inputs["ci_go.go"]); err != nil {
		return p, err
	}
	// The pinned scope implementation defines owned-root rather than dependency-root selection.
	components := declarations(inputs["component_impact.go"])
	list, err := composite(components["componentDefinitions"])
	if err != nil {
		return p, err
	}
	count := 0
	for _, item := range list.Elts {
		f, err := fields(item)
		if err != nil {
			return p, err
		}
		program, _ := literal(f["program"])
		if program != "brightcrm" {
			continue
		}
		root, _ := literal(f["root"])
		target, _ := literal(f["goTarget"])
		if root != "brightcrm" || target != "brightcrm" {
			return p, fail("Relay owned roots or Go facet changed")
		}
		count++
	}
	if count != 1 {
		return p, fail("Relay component ownership is ambiguous")
	}
	goDecl := declarations(inputs["ci_go.go"])
	if p.services, err = stringList(goDecl["ciGoServices"]); err != nil {
		return p, err
	}
	if p.exempt, err = stringMap(goDecl["ciGoExempt"]); err != nil {
		return p, err
	}
	contract := declarations(inputs["ci_contract_test.go"])
	if p.ciExempt, err = stringMap(contract["ciExempt"]); err != nil {
		return p, err
	}
	if p.raceDebt, err = stringMap(contract["ciRaceParityDebt"]); err != nil {
		return p, err
	}
	if p.trivy, err = stringList(declarations(inputs["security_trivy.go"])["securityTrivyServices"]); err != nil {
		return p, err
	}
	security := declarations(inputs["security_gate.go"])
	if p.provider, err = literal(security["hardcodedAPIKeyPattern"]); err != nil {
		return p, err
	}
	if p.includes, err = stringList(security["secretScanFileGlobs"]); err != nil {
		return p, err
	}
	if p.excludeDirs, err = stringList(security["secretScanExcludeDirs"]); err != nil {
		return p, err
	}
	if p.excludeFiles, err = stringList(security["secretScanExcludeFiles"]); err != nil {
		return p, err
	}
	// The source policy's only accepted appended includes are *.py and *.txt.
	appendExpr, ok := security["serviceCredentialScanFileGlobs"].(*ast.CallExpr)
	if !ok || len(appendExpr.Args) != 3 {
		return p, fail("service credential includes changed")
	}
	outer, ok := appendExpr.Fun.(*ast.Ident)
	if !ok || outer.Name != "append" {
		return p, fail("service credential includes changed")
	}
	inner, ok := appendExpr.Args[0].(*ast.CallExpr)
	if !ok || len(inner.Args) != 2 || !inner.Ellipsis.IsValid() {
		return p, fail("service credential includes changed")
	}
	id, ok := inner.Args[1].(*ast.Ident)
	if !ok || id.Name != "secretScanFileGlobs" {
		return p, fail("service credential includes changed")
	}
	p.credentialIncludes = append([]string{}, p.includes...)
	for i, want := range []string{"*.py", "*.txt"} {
		got, err := literal(appendExpr.Args[i+1])
		if err != nil || got != want {
			return p, fail("service credential includes changed")
		}
		p.credentialIncludes = append(p.credentialIncludes, got)
	}
	rules, err := composite(security["hardcodedServiceCredentialRules"])
	if err != nil || len(rules.Elts) == 0 {
		return p, fail("credential rule registry missing")
	}
	for _, entry := range rules.Elts {
		f, err := fields(entry)
		if err != nil {
			return p, err
		}
		pattern, err := literal(f["pattern"])
		if err != nil {
			return p, err
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return p, fail("credential expression invalid")
		}
		candidates, err := composite(f["candidates"])
		if err != nil || len(candidates.Elts) == 0 {
			return p, fail("credential candidate registry missing")
		}
		rule := credentialRule{pattern: pattern}
		for _, entry := range candidates.Elts {
			values, err := fields(entry)
			if err != nil {
				return p, err
			}
			group, err := integer(values["group"])
			if err != nil {
				return p, err
			}
			minimum, err := integer(values["minLength"])
			if err != nil || group < 1 || minimum < 1 {
				return p, fail("credential candidate malformed")
			}
			rule.candidates = append(rule.candidates, candidate{group, minimum})
		}
		p.credentials = append(p.credentials, rule)
	}
	// Derive the deployed Relay trigger from the reviewed DeploySpec function, without executing registration.
	for _, d := range inputs["deploy_brightcrm.go"].Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "brightcrmDeploySpec" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			kv, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "Trigger" {
				return true
			}
			value, ok := kv.Value.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := value.Type.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			p.manualDeploy = ok && pkg.Name == "sdk" && sel.Sel.Name == "Manual"
			return true
		})
	}
	if !p.manualDeploy {
		return p, fail("Relay deploy trigger is no longer the reviewed manual profile")
	}
	// Every selected name must still have its original private assertion implementation.
	for _, name := range guardNames {
		found := 0
		for _, input := range inputs {
			for _, d := range input.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if ok && fn.Name.Name == name {
					found++
				}
			}
		}
		if found != 1 {
			return p, fail("selected native assertion missing or duplicated")
		}
	}
	return p, nil
}

func glob(name string, patterns []string) bool {
	for _, pattern := range patterns {
		matched, err := filepath.Match(pattern, name)
		if err == nil && matched {
			return true
		}
	}
	return false
}

type scanHit struct{ location, line string }

// Preserve native scanTree's historical read/size/NUL exclusions. Source binding
// verifies the complete immutable input tree separately; this scanner is not a
// claim that every binary/oversized/unreadable byte was inspected.
func scan(root, pattern string, includes, excludeDirs, excludeFiles []string) ([]scanHit, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fail("invalid source scan expression")
	}
	var hits []scanHit
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" || contains(excludeDirs, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if len(includes) > 0 && !glob(d.Name(), includes) || glob(d.Name(), excludeFiles) {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 2<<20 {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil || bytes.IndexByte(raw, 0) >= 0 {
			return nil
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if re.MatchString(line) {
				rel, _ := filepath.Rel(root, path)
				hits = append(hits, scanHit{filepath.ToSlash(rel) + ":" + strconv.Itoa(i+1), strings.TrimSpace(line)})
			}
		}
		return nil
	})
	return hits, err
}
func literalCredential(value string, minimum int) bool {
	value = strings.Trim(value, "\\\"'`,;")
	if len(value) < minimum || strings.ContainsAny(value, "$<>{}[]().") {
		return false
	}
	first := value[0]
	if !((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') || (first >= '0' && first <= '9')) {
		return false
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"redacted", "placeholder", "changeme", "replace", "your_", "your-", "example", "dummy", "test_only", "test-only", "minioadmin"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	letter, digit := false, false
	for _, c := range value {
		letter = letter || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		digit = digit || c >= '0' && c <= '9'
	}
	return letter && digit
}
func credentialHits(root string, p policy) ([]string, error) {
	seen := map[string]bool{}
	var locations []string
	for _, rule := range p.credentials {
		re, err := regexp.Compile(rule.pattern)
		if err != nil {
			return nil, err
		}
		hits, err := scan(root, rule.pattern, p.credentialIncludes, p.excludeDirs, p.excludeFiles)
		if err != nil {
			return nil, err
		}
		for _, hit := range hits {
			found := false
			for _, match := range re.FindAllStringSubmatch(hit.line, -1) {
				for _, c := range rule.candidates {
					if c.group < len(match) && literalCredential(match[c.group], c.minimum) {
						found = true
					}
				}
			}
			if found && !seen[hit.location] {
				seen[hit.location] = true
				locations = append(locations, hit.location)
			}
		}
	}
	sort.Strings(locations)
	return locations, nil
}

type instruction struct {
	text      string
	continued bool
}

func dockerInstructions(raw []byte) ([]instruction, error) {
	var out []instruction
	pending := ""
	continued := false
	escape := regexp.MustCompile(`(?i)^#\s*escape\s*=\s*(.*)$`)
	for _, physical := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(physical)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if match := escape.FindStringSubmatch(line); match != nil && strings.TrimSpace(match[1]) != `\` {
				return nil, fail("unsupported Docker escape")
			}
			continue
		}
		if strings.Contains(line, "<<") {
			return nil, fail("Docker heredoc not admitted")
		}
		more := strings.HasSuffix(line, `\`)
		if more {
			if strings.HasSuffix(line, `\\`) {
				return nil, fail("ambiguous Docker continuation")
			}
			line = strings.TrimSpace(strings.TrimSuffix(line, `\`))
			continued = true
		}
		if pending != "" {
			pending += " "
		}
		pending += line
		if len(pending) > 256<<10 {
			return nil, fail("Docker instruction exceeds bound")
		}
		if more {
			continue
		}
		words := strings.Fields(pending)
		if len(words) == 0 {
			return nil, fail("empty Docker instruction")
		}
		if !contains(strings.Fields("FROM RUN CMD LABEL MAINTAINER EXPOSE ENV ADD COPY ENTRYPOINT VOLUME USER WORKDIR ARG ONBUILD STOPSIGNAL HEALTHCHECK SHELL"), strings.ToUpper(words[0])) {
			return nil, fail("unsupported Docker instruction")
		}
		out = append(out, instruction{pending, continued})
		pending = ""
		continued = false
	}
	if pending != "" || continued {
		return nil, fail("unfinished Docker continuation")
	}
	return out, nil
}
func versionParts(value string) ([3]int, bool) {
	var out [3]int
	if !regexp.MustCompile(`^[1-9][0-9]*\.(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))?$`).MatchString(value) {
		return out, false
	}
	for i, value := range strings.Split(value, ".") {
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return out, false
		}
		out[i] = int(n)
	}
	return out, true
}
func toolchainFromModule(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > 256<<10 || !utf8.Valid(raw) {
		return "", fail("module is not bounded UTF-8")
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line, _, _ = strings.Cut(line, "//")
		fields := strings.Fields(line)
		if len(fields) == 0 || !contains([]string{"module", "go", "toolchain"}, fields[0]) {
			continue
		}
		if len(fields) != 2 || values[fields[0]] != "" {
			return "", fail("noncanonical compiler declarations")
		}
		values[fields[0]] = fields[1]
	}
	version, ok := strings.CutPrefix(values["toolchain"], "go")
	if !ok || values["module"] != "github.com/bright-interaction/brightcrm" || !contains([]string{"1.26.7", "1.26.9", "1.26.10"}, version) {
		return "", fail("unreviewed Relay compiler")
	}
	minimum, ok := versionParts(values["go"])
	chosen, chosenOK := versionParts(version)
	if !ok || !chosenOK {
		return "", fail("invalid compiler minimum")
	}
	for i := range minimum {
		if minimum[i] < chosen[i] {
			break
		}
		if minimum[i] > chosen[i] {
			return "", fail("compiler minimum exceeds chosen compiler")
		}
	}
	return "golang:" + version + "-alpine", nil
}
func compilerParity(root string) (int, []string, error) {
	mod, err := regularRead(root, "brightcrm/go.mod", 256<<10)
	if err != nil {
		return 0, nil, err
	}
	image, err := toolchainFromModule(mod)
	if err != nil {
		return 0, nil, err
	}
	var paths []string
	entries := 0
	total := 0
	err = filepath.WalkDir(filepath.Join(root, "brightcrm"), func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > 20000 {
			return fail("compiler inventory exceeds entry bound")
		}
		if d.IsDir() {
			if contains([]string{"node_modules", "vendor", ".git"}, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(d.Name(), "Dockerfile") || strings.HasSuffix(d.Name(), ".Dockerfile") {
			rel, _ := filepath.Rel(root, path)
			paths = append(paths, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil || !contains(paths, "brightcrm/Dockerfile") || len(paths) > 32 {
		return 0, nil, fail("compiler builder inventory refused")
	}
	var findings []string
	goBuilders := 0
	rootGo := false
	for _, path := range paths {
		raw, err := regularRead(root, path, 256<<10)
		if err != nil || !utf8.Valid(raw) {
			return 0, nil, fail("invalid compiler input")
		}
		total += len(raw)
		if total > 4<<20 {
			return 0, nil, fail("compiler inventory exceeds byte bound")
		}
		instructions, err := dockerInstructions(raw)
		if err != nil {
			return 0, nil, err
		}
		stages := map[string]bool{}
		froms := 0
		for _, instruction := range instructions {
			words := strings.Fields(instruction.text)
			if !strings.EqualFold(words[0], "FROM") {
				continue
			}
			froms++
			i := 1
			for i < len(words) && strings.HasPrefix(words[i], "--") {
				if !strings.HasPrefix(words[i], "--platform=") {
					return 0, nil, fail("unreviewed FROM option")
				}
				i++
			}
			if i >= len(words) || instruction.continued || strings.ContainsAny(words[i], "$\\") || strings.Contains(instruction.text, "\\") {
				return 0, nil, fail("nonliteral FROM")
			}
			base := words[i]
			suffix := words[i+1:]
			if len(suffix) != 0 && (len(suffix) != 2 || !strings.EqualFold(suffix[0], "AS")) {
				return 0, nil, fail("unsupported FROM form")
			}
			ref, digest, pinned := strings.Cut(base, "@")
			if pinned && !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(digest) {
				return 0, nil, fail("noncanonical builder digest")
			}
			family := ref
			if colon := strings.LastIndexByte(family, ':'); colon > strings.LastIndexByte(family, '/') {
				family = family[:colon]
			}
			isGo := false
			if prior, inherited := stages[strings.ToLower(ref)]; inherited && !pinned {
				isGo = prior
			} else {
				switch family {
				case "golang":
					isGo = true
					if ref != image {
						findings = append(findings, path+":compiler-mismatch")
					}
				case "alpine", "oven/bun", "clamav/clamav":
				default:
					return 0, nil, fail("unreviewed builder base family")
				}
			}
			if len(suffix) == 2 {
				alias := strings.ToLower(suffix[1])
				if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`).MatchString(suffix[1]) {
					return 0, nil, fail("invalid Docker stage")
				}
				if _, exists := stages[alias]; exists {
					return 0, nil, fail("duplicate Docker stage")
				}
				stages[alias] = isGo
			}
			if isGo {
				goBuilders++
				if path == "brightcrm/Dockerfile" {
					rootGo = true
				}
			}
		}
		if froms == 0 {
			return 0, nil, fail("builder has no literal FROM")
		}
	}
	if !rootGo {
		return 0, nil, fail("root builder has no admitted Go compiler")
	}
	sort.Strings(findings)
	return goBuilders, findings, nil
}

func fileExists(path string) bool     { _, err := os.Stat(path); return err == nil }
func stripComment(line string) string { code, _, _ := strings.Cut(line, "#"); return code }
func runGuards(root string, p policy) report {
	r := report{Schema: 1, Status: "passed", Scope: "product-partition:brightcrm;owned-root:brightcrm", SelectedGuardCount: len(guardNames), Assertions: []result{}}
	add := func(index, checked int, applicability string, findings []string) {
		if findings == nil {
			findings = []string{}
		}
		status := "passed"
		if len(findings) != 0 {
			status = "failed"
			r.Status = "failed"
		}
		r.Assertions = append(r.Assertions, result{guardNames[index], status, checked, applicability, findings})
	}
	product := filepath.Join(root, "brightcrm")
	if info, err := os.Stat(product); err != nil || !info.IsDir() {
		r.Status = "failed"
		r.Refusal = "required owned product root missing"
		return r
	}
	ciRaw, ciErr := os.ReadFile(filepath.Join(product, "scripts/ci.sh"))
	var falseGreen []string
	lines := 0
	if ciErr == nil {
		for i, line := range strings.Split(string(ciRaw), "\n") {
			lines++
			code := stripComment(line)
			if strings.Contains(code, "&&") && (strings.Contains(code, ") && echo") || strings.Contains(code, "} && echo")) {
				falseGreen = append(falseGreen, "brightcrm/scripts/ci.sh:"+strconv.Itoa(i+1))
			}
		}
	}
	ciApplicable := "owned local ci.sh inspected"
	if ciErr != nil {
		ciApplicable = "native optional local ci.sh absent; hosted core checks run independently"
	}
	add(0, lines, ciApplicable, falseGreen)
	var imageFindings []string
	if !contains(p.trivy, "brightcrm") {
		imageFindings = append(imageFindings, "Relay missing from image scan matrix")
	}
	if !p.manualDeploy || !fileExists(filepath.Join(product, "Dockerfile")) {
		imageFindings = append(imageFindings, "reviewed manual image deployment profile missing")
	}
	add(1, 1, "native push-deploy discovery excludes manual Relay deployment; portable check additionally requires Relay image scan membership; final-image gate performs actual scan", imageFindings)
	var moduleFindings []string
	modules := 0
	if fileExists(filepath.Join(product, "go.mod")) {
		modules = 1
		if !contains(p.services, "brightcrm") {
			if reason, ok := p.exempt["brightcrm"]; !ok || reason == "" {
				moduleFindings = append(moduleFindings, "owned Go module lacks gate or reason")
			}
		}
	}
	add(2, modules, "top-level owned Go module; nested VoIP receives a separate required execution job", moduleFindings)
	var publication []string
	publishCount := 0
	if _, exempt := p.ciExempt["brightcrm"]; !exempt && fileExists(filepath.Join(product, "scripts/split-public-repo.sh")) {
		publishCount = 1
		for _, path := range []string{"scripts/ci.sh", ".github/workflows/ci.yml"} {
			if !fileExists(filepath.Join(product, path)) {
				publication = append(publication, "brightcrm/"+path+":missing")
			}
		}
	}
	applicability := "publisher script present; required local script/workflow inspected"
	if publishCount == 0 {
		applicability = "native owned root has no public app publisher; public tooling workflow qualified separately"
	}
	add(3, publishCount, applicability, publication)
	var exemptions []string
	exemptCount := 0
	if _, exists := p.exempt["brightcrm"]; exists {
		exemptCount = 1
		if !fileExists(filepath.Join(product, "go.mod")) {
			exemptions = append(exemptions, "owned ci-go exemption has no module")
		}
	}
	applicability = "owned ci-go exemption inspected"
	if exemptCount == 0 {
		applicability = "native owned root has no ci-go exemption"
	}
	add(4, exemptCount, applicability, exemptions)
	builders, compilerFindings, compilerErr := compilerParity(root)
	if compilerErr != nil {
		compilerFindings = []string{"compiler policy refused input"}
	}
	add(5, builders, "all owned Dockerfile-prefix and .Dockerfile-suffix inputs under bounded reviewed Relay compiler grammar", compilerFindings)
	matched := 0
	var unraced []string
	if ciErr == nil {
		for i, line := range strings.Split(string(ciRaw), "\n") {
			fields := strings.Fields(stripComment(line))
			command := false
			for j := 0; j+1 < len(fields); j++ {
				if (fields[j] == "go" || fields[j] == "go_release") && fields[j+1] == "test" {
					command = true
				}
			}
			e2e := contains(fields, "-tags=e2e")
			for j := 0; j+1 < len(fields); j++ {
				e2e = e2e || fields[j] == "-tags" && fields[j+1] == "e2e"
			}
			if command && contains(fields, "./...") && !e2e {
				matched++
				if !contains(fields, "-race") {
					unraced = append(unraced, "brightcrm/scripts/ci.sh:"+strconv.Itoa(i+1))
				}
			}
		}
	}
	_, debt := p.raceDebt["brightcrm"]
	if debt {
		if ciErr != nil {
			unraced = append(unraced, "unreachable race debt")
		} else if len(unraced) == 0 {
			unraced = append(unraced, "stale race debt")
		} else {
			unraced = nil
		}
	}
	add(6, matched, ciApplicable, unraced)
	provider, scanErr := scan(product, p.provider, p.includes, p.excludeDirs, p.excludeFiles)
	var providerLocations []string
	if scanErr != nil {
		providerLocations = append(providerLocations, "provider scan refused")
	}
	for _, h := range provider {
		providerLocations = append(providerLocations, "brightcrm/"+h.location)
	}
	add(7, 1, "provider shapes on exact owned production root; native test/generated/binary/size exclusions retained", providerLocations)
	credentials, credentialErr := credentialHits(product, p)
	if credentialErr != nil {
		credentials = append(credentials, "credential scan refused")
	}
	for i := range credentials {
		credentials[i] = "brightcrm/" + credentials[i]
	}
	add(8, 1, "contextual credentials on owned root; candidate classification and exact exclusions from private Stage policy", credentials)
	operational, err := regularRead(root, "ops/scripts/nocodb-to-espocrm-import.py", 2<<20)
	var operationFindings []string
	if err != nil || !bytes.Contains(operational, []byte(`os.environ["ESPOCRM_API_KEY"]`)) {
		operationFindings = append(operationFindings, "ops/scripts/nocodb-to-espocrm-import.py:required-external-credential-marker-missing")
	}
	add(9, 1, "the exact operational credential case selected for durable Relay subject", operationFindings)
	return r
}

func qualify(root, origin string) report {
	inputs, err := loadInputs(root, origin)
	if err != nil {
		return report{Schema: 1, Status: "failed", Scope: "durable-subject:brightcrm", Assertions: []result{}, Refusal: err.Error()}
	}
	p, err := readPolicy(inputs)
	if err != nil {
		return report{Schema: 1, Status: "failed", Scope: "durable-subject:brightcrm", Assertions: []result{}, Refusal: err.Error()}
	}
	return runGuards(root, p)
}
func main() {
	root := flag.String("root", "", "fixed private context repository root")
	origin := flag.String("provenance", "", "public reviewed policy input hashes")
	output := flag.String("report", "", "private owned JSON output")
	flag.Parse()
	if *root == "" || *origin == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "Relay governance refused: required paths missing")
		os.Exit(2)
	}
	r := qualify(filepath.Clean(*root), *origin)
	raw, err := json.MarshalIndent(r, "", "  ")
	if err == nil {
		err = os.WriteFile(*output, append(raw, '\n'), 0600)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Relay governance refused: private report unavailable")
		os.Exit(2)
	}
	passed := 0
	for _, assertion := range r.Assertions {
		if assertion.Status == "passed" {
			passed++
		}
	}
	fmt.Printf("Relay governance: %s; %d/%d assertions passed; private diagnostics withheld.\n", r.Status, passed, len(guardNames))
	if r.Status != "passed" || passed != len(guardNames) {
		os.Exit(1)
	}
}
