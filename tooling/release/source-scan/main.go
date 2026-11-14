package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type finding struct {
	Rule     string `json:"rule"`
	Location string `json:"location"`
}
type report struct {
	Status   string    `json:"status"`
	Blocking []finding `json:"blocking"`
	Advisory []finding `json:"advisory"`
}

// collect keeps Stage's blocking/advisory distinctions. The only scanner-source
// exception is this exact app-owned rule-definition file, which contains the
// unsafe strings by definition. It is not a basename or general path exemption.
func collect(root string) (report, error) {
	r := report{Status: "passed", Blocking: []finding{}, Advisory: []finding{}}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return r, fmt.Errorf("source scan requires an existing product directory")
	}
	add := func(rule, pattern string, includes, dirs, files, sanitized []string, blocking bool) error {
		hits, err := scanTree(root, pattern, includes, dirs, files, sanitized)
		if err != nil {
			return err
		}
		for _, h := range hits {
			location := hitLocation(h)
			if filepath.Clean(strings.Split(location, ":")[0]) == filepath.Join(root, "ci/release/source-scan/source_policy.go") && (rule == "unsafe-tls" || rule == "unsafe-ssh") {
				continue
			}
			f := finding{rule, location}
			if blocking {
				r.Blocking = append(r.Blocking, f)
			} else {
				r.Advisory = append(r.Advisory, f)
			}
		}
		return nil
	}
	if err := add("hardcoded-provider-token", hardcodedAPIKeyPattern, secretScanFileGlobs, secretScanExcludeDirs, secretScanExcludeFiles, nil, true); err != nil {
		return r, err
	}
	credentials, err := scanHardcodedServiceCredentials(root)
	if err != nil {
		return r, err
	}
	for _, h := range credentials {
		r.Blocking = append(r.Blocking, finding{"contextual-service-credential", hitLocation(h)})
	}
	if err := add("private-key", `-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`, []string{"*.go", "*.ts", "*.tsx", "*.js", "*.jsx", "*.json"}, secretScanExcludeDirs, secretScanExcludeFiles, nil, true); err != nil {
		return r, err
	}
	for _, rule := range unsafeTransportRules {
		if err := add(rule.name, rule.pattern, []string{"*.go"}, nil, []string{"*_test.go"}, nil, true); err != nil {
			return r, err
		}
	}
	if err := add("sql-format-review", `fmt\.Sprintf.*\b(SELECT|INSERT|UPDATE|DELETE|ALTER|DROP)\b`, []string{"*.go"}, []string{"vendor"}, []string{"*_test.go"}, nil, false); err != nil {
		return r, err
	}
	if err := add("dynamic-html-review", `{@html`, []string{"*.svelte"}, []string{"node_modules", ".git"}, nil, []string{"escapeHtml", "DOMPurify", "sanitize", "JSON.stringify", "set:html"}, false); err != nil {
		return r, err
	}
	if err := add("inner-html-review", `\.innerHTML\s*=`, []string{"*.ts", "*.tsx", "*.js", "*.jsx"}, []string{"node_modules", ".git"}, nil, []string{"escapeHtml", "btEscapeHtml", "DOMPurify", "sanitize", "textContent"}, false); err != nil {
		return r, err
	}
	for _, path := range findEnvFiles(root, 5) {
		r.Advisory = append(r.Advisory, finding{"tracked-env-review", path})
	}
	if len(r.Blocking) != 0 {
		r.Status = "failed"
	}
	return r, nil
}

func main() {
	root := flag.String("root", "", "required product source directory")
	output := flag.String("report", "", "required owned JSON report path")
	flag.Parse()
	if *root == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "source scan refused: required paths missing")
		os.Exit(2)
	}
	r, err := collect(filepath.Clean(*root))
	if err != nil {
		fmt.Fprintln(os.Stderr, "source scan refused: missing input or source root")
		os.Exit(2)
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err == nil {
		err = os.WriteFile(*output, append(raw, '\n'), 0o600)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "source scan report could not be written")
		os.Exit(2)
	}
	fmt.Printf("Source scan: %d blocking findings, %d advisory findings; locations only in report\n", len(r.Blocking), len(r.Advisory))
	if r.Status != "passed" {
		os.Exit(1)
	}
}
