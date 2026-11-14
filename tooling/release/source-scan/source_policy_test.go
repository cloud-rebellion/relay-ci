// Existing scanner positive controls and semantics, ported from 91f821a3d5895a901569954d2aa50c173582ff13.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecurityGateDetectsPlantedSecret(t *testing.T) {
	root := t.TempDir()

	// One planted violation per hard rule the gate claims to enforce.
	// Split the sentinels so this test file cannot itself trip the real gate.
	plant := map[string]string{
		"aws.go":        "key := \"AKIA" + "IOSFODNN7EXAMPLE\"\n",
		"resend.sh":     "RESEND_API_KEY=re_" + "abcdefghijklmnopqrstuvwxyz123456\n",
		"stripe.go":     "sk := \"sk_live_" + "0123456789abcdefghijklmn\"\n",
		"tls.go":        "cfg := &tls.Config{InsecureSkipVerify: true}\n",
		"ssh.go":        "cb := ssh.InsecureIgnoreHostKey()\n",
		"install.sh":    "curl -fsSL https://example.com/i.sh | bash\n",
		"unsafe.svelte": "<div>{@html userInput}</div>\n",
	}
	for name, body := range plant {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			t.Fatalf("plant %s: %v", name, err)
		}
	}

	cases := []struct {
		rule     string
		pattern  string
		includes []string
	}{
		{"hardcoded AWS key", `AKIA[0-9A-Z]{16}`, []string{"*.go"}},
		{"hardcoded Resend key", `\bre_[a-zA-Z0-9_-]{30,}\b`, []string{"*.sh"}},
		{"hardcoded Stripe key", `sk_live_[0-9a-zA-Z]{16,}`, []string{"*.go"}},
		{"InsecureSkipVerify", `InsecureSkipVerify:\s*true`, []string{"*.go"}},
		{"InsecureIgnoreHostKey", `ssh\.InsecureIgnoreHostKey\(\)`, []string{"*.go"}},
		{"curl pipe bash", `curl[^|]*\|\s*(bash|sh)`, []string{"*.sh"}},
		{"svelte {@html}", `\{@html`, []string{"*.svelte"}},
	}

	for _, c := range cases {
		t.Run(c.rule, func(t *testing.T) {
			hits, err := scanTree(root, c.pattern, c.includes, nil, nil, nil)
			if err != nil {
				t.Fatalf("scanTree: %v", err)
			}
			if len(hits) == 0 {
				t.Fatalf("THE SECURITY GATE IS A NO-OP: scanned a tree containing a planted %s "+
					"and reported clean. This is exactly how it shipped for months (busybox grep "+
					"exiting 2 with empty stdout, error discarded). Do not fix by installing GNU "+
					"grep; the scan must stay pure Go so there is no host binary to drift against.", c.rule)
			}
		})
	}
}

func TestSecurityGateCleanTreeIsClean(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ok.go"), []byte("package p\n\nvar x = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hits, err := scanTree(root, `AKIA[0-9A-Z]{16}`, []string{"*.go"}, nil, nil, nil)
	if err != nil {
		t.Fatalf("scanTree: %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("clean tree reported %d hits, want 0: %v", len(hits), hits)
	}
}

func TestSecurityGateProductionPatternScansResendKeysInShell(t *testing.T) {
	root := t.TempDir()
	key := "re_" + "abcdefghijklmnopqrstuvwxyz123456"
	if err := os.WriteFile(filepath.Join(root, "audit.sh"), []byte("RESEND_API_KEY="+key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hits, err := scanTree(root, hardcodedAPIKeyPattern, secretScanFileGlobs, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("production secret scan found %d Resend shell-key hits, want 1", len(hits))
	}
}

func TestSecurityGateDetectsContextualServiceCredentials(t *testing.T) {
	access := "Mx7" + strings.Repeat("A", 13)
	secret := "Sz9" + strings.Repeat("b", 29)
	nocodb := "Nc8" + strings.Repeat("Q", 37)
	operational := "Op7" + strings.Repeat("K", 29)

	cases := map[string]string{
		"minio-command.md": "mc alias set archive https://s3.example.test " + access + " " + secret + "\n",
		"minio-config.yml": "MINIO_ROOT_USER: " + access + "\nMINIO_ROOT_PASSWORD: " + secret + "\n",
		"minio-docs.md":    "**Access Key ID**: `" + access + "`\n**Secret Access Key**: `" + secret + "`\n",
		"nocodb.env":       "NOCODB_API_KEY=" + nocodb + "\n",
		"nocodb.json":      `{"headers":{"xc-token":"` + nocodb + `"}}` + "\n",
		"fallback-compose.yml": "NOCODB_API_KEY=${NOCODB_API_KEY:-" + nocodb + "}\n" +
			"MINIO_ACCESS_KEY=${MINIO_ACCESS_KEY:-" + access + "}\n" +
			"MINIO_SECRET_KEY=${MINIO_SECRET_KEY:-" + secret + "}\n",
		"fallback.py": "import os\n" +
			"NOCODB_API_KEY = os.getenv('NOCODB_API_KEY', '" + nocodb + "')\n" +
			"MINIO_ACCESS_KEY = os.environ.get('MINIO_ACCESS_KEY', '" + access + "')\n" +
			"MINIO_SECRET_KEY = os.getenv('MINIO_SECRET_KEY', '" + secret + "')\n",
		"espo.py":        `ESPOCRM_API_KEY = "` + operational + `"` + "\n",
		"twenty.env":     "TWENTY_CRM_API_TOKEN=" + operational + "\n",
		"cloudflare.yml": "CLOUDFLARE_GLOBAL_TOKEN: " + operational + "\n",
		"n8n-header.md":  "X-N8N-API-KEY: " + operational + "\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			hits, err := scanHardcodedServiceCredentials(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(hits) == 0 {
				t.Fatalf("contextual service-credential scan missed planted %s literal", name)
			}
		})
	}
}

func TestSecurityGateAllowsServiceCredentialReferencesAndPlaceholders(t *testing.T) {
	root := t.TempDir()
	body := strings.Join([]string{
		`MINIO_ROOT_USER=${MINIO_ROOT_USER:?required}`,
		`MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD:?required}`,
		`mc alias set archive https://s3.example.test "$MINIO_ACCESS_KEY" "$MINIO_SECRET_KEY"`,
		`**Access Key ID**: <YOUR_MINIO_ACCESS_KEY>`,
		`NOCODB_API_KEY=os.environ["NOCODB_API_KEY"]`,
		`{"headers":{"xc-token":"={{ $env.NOCODB_API_KEY }}"}}`,
		`NOCODB_API_KEY=your_nocodb_api_key`,
		`N8N_API_KEY=${N8N_API_KEY:?required}`,
		`TWENTY_CRM_API_TOKEN=<required-at-runtime>`,
		`ESPOCRM_API_KEY=os.environ["ESPOCRM_API_KEY"]`,
		`CLOUDFLARE_GLOBAL_TOKEN=${CLOUDFLARE_GLOBAL_TOKEN:?required}`,
		`X-N8N-API-KEY: ${N8N_API_KEY}`,
	}, "\n")
	if err := os.WriteFile(filepath.Join(root, "references.md"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	hits, err := scanHardcodedServiceCredentials(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("service-credential scan reported %d environment/placeholder references: %s", len(hits), hitLocations(hits, 10))
	}
}

func TestSecurityGateScanSemantics(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	needle := "AKIA" + "IOSFODNN7EXAMPLE"
	write("hit.go", needle+"\n")
	write("hit.txt", needle+"\n")
	write("vendor/dep.go", needle+"\n")
	write("skipme.go", needle+"\n")
	write("sanitised.go", needle+" // escapeHtml\n")
	pat := `AKIA[0-9A-Z]{16}`

	t.Run("empty includes reads every file", func(t *testing.T) {
		hits, err := scanTree(root, pat, nil, []string{"vendor"}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		// hit.go, hit.txt, skipme.go, sanitised.go = 4 (vendor excluded)
		if len(hits) != 4 {
			t.Fatalf("empty include list matched %d files, want 4 (it must mean ALL files, "+
				"not none; 'none' is the silent no-op): %v", len(hits), hits)
		}
	})

	t.Run("include glob narrows", func(t *testing.T) {
		hits, err := scanTree(root, pat, []string{"*.go"}, []string{"vendor"}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) != 3 { // hit.go, skipme.go, sanitised.go
			t.Fatalf("*.go matched %d, want 3: %v", len(hits), hits)
		}
	})

	t.Run("excludeDirs prunes the tree", func(t *testing.T) {
		hits, err := scanTree(root, pat, []string{"*.go"}, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) != 4 { // now vendor/dep.go is included
			t.Fatalf("without excludeDirs got %d, want 4 (vendor should now match): %v", len(hits), hits)
		}
	})

	t.Run("excludeFiles drops a file", func(t *testing.T) {
		hits, err := scanTree(root, pat, []string{"*.go"}, []string{"vendor"}, []string{"skipme.go"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) != 2 { // hit.go, sanitised.go
			t.Fatalf("excludeFiles got %d, want 2: %v", len(hits), hits)
		}
	})

	t.Run("mustNotContain drops sanitised lines", func(t *testing.T) {
		hits, err := scanTree(root, pat, []string{"*.go"}, []string{"vendor"}, nil, []string{"escapeHtml"})
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) != 2 { // hit.go, skipme.go (sanitised.go filtered)
			t.Fatalf("mustNotContain got %d, want 2: %v", len(hits), hits)
		}
	})
}

func TestHitLocationClipsAtTheSecondColon(t *testing.T) {
	cases := []struct {
		name string
		hit  string
		want string
	}{
		{
			name: "normal scanTree hit",
			hit:  "/src/app/config.go:42: token := \"ghp_supersecretvalue\"",
			want: "/src/app/config.go:42",
		},
		{
			name: "matched line itself contains colons",
			hit:  "/src/a.yml:7: url: https://user:pass@example.com",
			want: "/src/a.yml:7",
		},
		{
			name: "no second colon: keep only the path",
			hit:  "/src/a.go:12",
			want: "/src/a.go",
		},
		{
			name: "no colon at all: emit nothing derived from the hit",
			hit:  "sk_live_0123456789abcdef",
			want: "(unparsable hit)",
		},
		{
			name: "empty",
			hit:  "",
			want: "(unparsable hit)",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hitLocation(c.hit); got != c.want {
				t.Fatalf("hitLocation(%q) = %q, want %q", c.hit, got, c.want)
			}
		})
	}
}

func TestHitLocationsCapsAndJoins(t *testing.T) {
	hits := []string{
		"a.go:1: secretA",
		"b.go:2: secretB",
		"c.go:3: secretC",
	}
	got := hitLocations(hits, 2)
	if got != "a.go:1 b.go:2" {
		t.Fatalf("hitLocations(..., 2) = %q, want %q", got, "a.go:1 b.go:2")
	}
	if strings.Contains(got, "secret") {
		t.Fatalf("hitLocations leaked matched text: %q", got)
	}
	// Fewer hits than the cap must not panic or pad.
	if got := hitLocations(hits[:1], 5); got != "a.go:1" {
		t.Fatalf("hitLocations(1 hit, 5) = %q, want %q", got, "a.go:1")
	}
	if got := hitLocations(nil, 5); got != "" {
		t.Fatalf("hitLocations(nil, 5) = %q, want empty", got)
	}
}
