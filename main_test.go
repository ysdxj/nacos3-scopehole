package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExitError(t *testing.T) {
	if got := (&exitError{code: 2}).Error(); got != "exit status 2" {
		t.Fatalf("Error = %q", got)
	}
}

func TestRootRejectsPositionalArguments(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"http://127.0.0.1:8848/nacos"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected positional argument error")
	}
}

func TestRootRejectsInvalidBaseURL(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"--base-url", "not-a-url", "--check-only"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "absolute http(s) URL") {
		t.Fatalf("Execute error = %v", err)
	}
}

func TestRootRejectsIgnoredBatchFlags(t *testing.T) {
	targets := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(targets, []byte("127.0.0.1:8848\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newRootCmd()
	cmd.SetArgs([]string{"--batch", targets, "--no-cleanup"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("Execute error = %v", err)
	}
}
