// Ported without policy changes from 91f821a3d5895a901569954d2aa50c173582ff13:stage/userworkflows/security_gate.go.
// Only the package/import boundary is app-owned; provider rules and fixture exclusions remain exact.
package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const hardcodedAPIKeyPattern = `(sk_live_[a-zA-Z0-9]{24,}|sk_test_[a-zA-Z0-9]{24,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9\-]{20}|\bre_[a-zA-Z0-9_-]{30,}\b)`

// serviceCredentialRule only extracts candidate tokens when a provider command,
// setting, or documentation label gives them meaning. Several covered providers
// do not give every credential a stable prefix, so a value-only
// expression would either miss them or flag arbitrary IDs. Placeholder
// classification happens on each captured token, never on the whole source
// line: an endpoint such as s3.example.test must not accidentally allowlist a
// real credential later on that same command.
type serviceCredentialRule struct {
	pattern    string
	candidates []serviceCredentialCandidate
}

type serviceCredentialCandidate struct {
	group     int
	minLength int
}

var hardcodedServiceCredentialRules = []serviceCredentialRule{
	{
		pattern:    `(?i)\b(?:N8N_API_KEY|TWENTY_CRM_API_TOKEN|ESPOCRM_API_KEY|CLOUDFLARE_TOKEN|CLOUDFLARE_GLOBAL_TOKEN)\b\\?["']?\s*[:=]\s*\\?["'\x60]?\s*([^[:space:]"'\x60,;#]+)`,
		candidates: []serviceCredentialCandidate{{group: 1, minLength: 20}},
	},
	{
		pattern:    `(?i)\b(?:N8N_API_KEY|TWENTY_CRM_API_TOKEN|ESPOCRM_API_KEY|CLOUDFLARE_TOKEN|CLOUDFLARE_GLOBAL_TOKEN)\b\s*=\s*os\.(?:getenv|environ\.get)\(\s*["'][A-Z0-9_]+["']\s*,\s*["']([^"']+)`,
		candidates: []serviceCredentialCandidate{{group: 1, minLength: 20}},
	},
	{
		pattern:    `(?i)\bX-N8N-API-KEY\b\\?["']?\s*:\s*\\?["']?\s*([^[:space:]"'\\,}]+)`,
		candidates: []serviceCredentialCandidate{{group: 1, minLength: 20}},
	},
	{
		pattern:    `(?i)\b(?:MINIO_ROOT_USER|MINIO_ADMIN_USER|MINIO_ACCESS_KEY|HASH_S3_ACCESS_KEY|S3_ACCESS_KEY|AWS_ACCESS_KEY_ID|NOCODB_API_KEY|NOCODB_TOKEN)\b\\?["']?\s*[:=]\s*\\?["'\x60]?\s*([^[:space:]"'\x60,;#]+)`,
		candidates: []serviceCredentialCandidate{{group: 1, minLength: 16}},
	},
	{
		pattern:    `(?i)\b(?:MINIO_ROOT_PASSWORD|MINIO_ADMIN_PASSWORD|MINIO_SECRET_KEY|HASH_S3_SECRET_KEY|S3_SECRET_KEY|AWS_SECRET_ACCESS_KEY)\b\\?["']?\s*[:=]\s*\\?["'\x60]?\s*([^[:space:]"'\x60,;#]+)`,
		candidates: []serviceCredentialCandidate{{group: 1, minLength: 24}},
	},
	{
		pattern:    `(?i)\b(?:MINIO_ROOT_USER|MINIO_ADMIN_USER|MINIO_ACCESS_KEY|HASH_S3_ACCESS_KEY|S3_ACCESS_KEY|AWS_ACCESS_KEY_ID|NOCODB_API_KEY|NOCODB_TOKEN)\b\s*[:=]\s*["']?\$\{[^}:]+:-["']?([^[:space:]}"']+)`,
		candidates: []serviceCredentialCandidate{{group: 1, minLength: 16}},
	},
	{
		pattern:    `(?i)\b(?:MINIO_ROOT_PASSWORD|MINIO_ADMIN_PASSWORD|MINIO_SECRET_KEY|HASH_S3_SECRET_KEY|S3_SECRET_KEY|AWS_SECRET_ACCESS_KEY)\b\s*[:=]\s*["']?\$\{[^}:]+:-["']?([^[:space:]}"']+)`,
		candidates: []serviceCredentialCandidate{{group: 1, minLength: 24}},
	},
	{
		pattern:    `(?i)\b(?:MINIO_ROOT_USER|MINIO_ADMIN_USER|MINIO_ACCESS_KEY|HASH_S3_ACCESS_KEY|S3_ACCESS_KEY|AWS_ACCESS_KEY_ID|NOCODB_API_KEY|NOCODB_TOKEN)\b\s*=\s*os\.(?:getenv|environ\.get)\(\s*["'][A-Z0-9_]+["']\s*,\s*["']([^"']+)`,
		candidates: []serviceCredentialCandidate{{group: 1, minLength: 16}},
	},
	{
		pattern:    `(?i)\b(?:MINIO_ROOT_PASSWORD|MINIO_ADMIN_PASSWORD|MINIO_SECRET_KEY|HASH_S3_SECRET_KEY|S3_SECRET_KEY|AWS_SECRET_ACCESS_KEY)\b\s*=\s*os\.(?:getenv|environ\.get)\(\s*["'][A-Z0-9_]+["']\s*,\s*["']([^"']+)`,
		candidates: []serviceCredentialCandidate{{group: 1, minLength: 24}},
	},
	{
		pattern:    `(?i)\b(?:Access Key ID|Root User|NocoDB API Key)\b[*_]*\s*:\s*[*_]*\s*["'\x60]?\s*([^[:space:]"'\x60,;#]+)`,
		candidates: []serviceCredentialCandidate{{group: 1, minLength: 16}},
	},
	{
		pattern:    `(?i)\b(?:Secret Access Key|Root Password)\b[*_]*\s*:\s*[*_]*\s*["'\x60]?\s*([^[:space:]"'\x60,;#]+)`,
		candidates: []serviceCredentialCandidate{{group: 1, minLength: 24}},
	},
	{
		pattern:    `(?i)\bxc-token\b\\?["']?\s*:\s*\\?["']?\s*([^[:space:]"'\\,}]+)`,
		candidates: []serviceCredentialCandidate{{group: 1, minLength: 24}},
	},
	{
		pattern: `(?i)(?:^|[[:space:];&|])(?:\./)?mc\s+alias\s+set\s+\S+\s+https?://\S+\s+["']?([^[:space:]"']+)["']?\s+["']?([^[:space:]"']+)`,
		candidates: []serviceCredentialCandidate{
			{group: 1, minLength: 16},
			{group: 2, minLength: 24},
		},
	},
}

var secretScanFileGlobs = []string{
	"*.go", "*.ts", "*.tsx", "*.js", "*.jsx", "*.svelte",
	"*.sh", "*.bash", "*.zsh", "*.yml", "*.yaml", "*.toml",
	"*.json", "*.env", "*.conf", "*.md",
	"*.plist", "pre-commit", "post-push", "post-commit",
}

var serviceCredentialScanFileGlobs = append(append([]string(nil), secretScanFileGlobs...), "*.py", "*.txt")

var secretScanExcludeDirs = []string{"node_modules", ".git", "vendor", "tests", "test", "__tests__", ".svelte-kit", "dist", "build"}
var secretScanExcludeFiles = []string{
	"*_test.go", "*.test.ts", "*.spec.ts", "constants.go",
	// This negative-test suite deliberately embeds credential-shaped fixtures.
	// Do not exclude test-*.sh: reviewed executable scripts still get scanned.
	"test-mirror-secret-preflight.sh",
}

// Same three blocking Go patterns as runGoSecurityStaticScans in the origin.
var unsafeTransportRules = []struct{ name, pattern string }{
	{"unsafe-tls", `InsecureSkipVerify:\s*true`},
	{"unsafe-ssh", `InsecureIgnoreHostKey`},
	{"unsafe-curl-exec", `exec\.Command.*"bash".*"-c".*curl.*\|.*bash`},
}

func scanHardcodedServiceCredentials(root string) ([]string, error) {
	seen := make(map[string]bool)
	var hits []string
	for _, rule := range hardcodedServiceCredentialRules {
		re, err := regexp.Compile(rule.pattern)
		if err != nil {
			return nil, fmt.Errorf("service credential pattern: %w", err)
		}
		patternHits, err := scanTree(root, rule.pattern, serviceCredentialScanFileGlobs,
			secretScanExcludeDirs, secretScanExcludeFiles, nil)
		if err != nil {
			return nil, err
		}
		for _, hit := range patternHits {
			line := scanHitLine(hit)
			credentialFound := false
			for _, match := range re.FindAllStringSubmatch(line, -1) {
				for _, candidate := range rule.candidates {
					if candidate.group < len(match) && looksLikeLiteralServiceCredential(match[candidate.group], candidate.minLength) {
						credentialFound = true
						break
					}
				}
				if credentialFound {
					break
				}
			}
			if !credentialFound {
				continue
			}
			location := hitLocation(hit)
			if seen[location] {
				continue
			}
			seen[location] = true
			hits = append(hits, hit)
		}
	}
	return hits, nil
}

func scanHitLine(hit string) string {
	i := strings.IndexByte(hit, ':')
	if i < 0 {
		return ""
	}
	j := strings.IndexByte(hit[i+1:], ':')
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(hit[i+1+j+1:])
}

func looksLikeLiteralServiceCredential(candidate string, minLength int) bool {
	candidate = strings.Trim(candidate, "\\\"'`,;")
	if len(candidate) < minLength || strings.ContainsAny(candidate, "$<>{}[]().") {
		return false
	}
	first := candidate[0]
	if !((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') || (first >= '0' && first <= '9')) {
		return false
	}
	lower := strings.ToLower(candidate)
	for _, marker := range []string{
		"redacted", "placeholder", "changeme", "replace", "your_", "your-",
		"example", "dummy", "test_only", "test-only", "minioadmin",
	} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	hasLetter := strings.ContainsAny(candidate, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
	hasDigit := strings.ContainsAny(candidate, "0123456789")
	return hasLetter && hasDigit
}

func findEnvFiles(root string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	var found []string
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if !entry.IsDir() && entry.Name() == ".env" {
			found = append(found, path)
			if len(found) >= limit {
				return fs.SkipAll
			}
		}
		return nil
	})
	return found
}

func scanTree(root, pattern string, includes, excludeDirs, excludeFiles, mustNotContain []string) ([]string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("security-gate: bad pattern %q: %w", pattern, err)
	}
	skipDir := make(map[string]bool, len(excludeDirs))
	for _, d := range excludeDirs {
		skipDir[d] = true
	}

	var hits []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable entry must not silently pass the gate, but it must
			// not fail the build either (the checkout has odd modes). Skip it
			// and keep walking, which is what --no-messages was reaching for.
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			// Always skip VCS + vendored trees, plus the caller's exclusions.
			if name == ".git" || skipDir[name] {
				return filepath.SkipDir
			}
			return nil
		}
		// No --include means "every file" (grep's behaviour). Getting this
		// backwards would skip every file and recreate the always-clean no-op
		// this rewrite exists to kill, so it is asserted in the unit test.
		if len(includes) > 0 && !matchesAnyGlob(name, includes) {
			return nil
		}
		if matchesAnyGlob(name, excludeFiles) {
			return nil
		}
		// Skip anything implausibly large or binary: a match there is noise and
		// reading it costs the runner real memory.
		if info, statErr := d.Info(); statErr != nil || info.Size() > 2<<20 {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil || bytes.IndexByte(body, 0) >= 0 {
			return nil
		}
		for i, line := range strings.Split(string(body), "\n") {
			if !re.MatchString(line) {
				continue
			}
			if containsAny(line, mustNotContain) {
				continue // already sanitised
			}
			hits = append(hits, fmt.Sprintf("%s:%d: %s", path, i+1, strings.TrimSpace(line)))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return hits, nil
}

func matchesAnyGlob(name string, globs []string) bool {
	for _, g := range globs {
		if ok, _ := filepath.Match(g, name); ok {
			return true
		}
	}
	return false
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func hitLocations(hits []string, n int) string {
	if len(hits) > n {
		hits = hits[:n]
	}
	locs := make([]string, 0, len(hits))
	for _, h := range hits {
		locs = append(locs, hitLocation(h))
	}
	return strings.Join(locs, " ")
}

func hitLocation(hit string) string {
	i := strings.IndexByte(hit, ':')
	if i < 0 {
		return "(unparsable hit)"
	}
	j := strings.IndexByte(hit[i+1:], ':')
	if j < 0 {
		return hit[:i]
	}
	return hit[:i+1+j]
}
