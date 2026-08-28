// nacos3-scopehole verifies QVD-2026-59388 (Nacos 3.0.0 through 3.2.3): the
// admin/user/role/permission management endpoints fall into the disabled
// OPEN_API auth scope. For authorized security testing and isolated lab
// reproduction only; ensure you have permission to test the target.
package main

import (
	"errors"
	"fmt"
	"os"

	"nacos3-scopehole/internal/httpx"
	"nacos3-scopehole/internal/nacos"

	"github.com/spf13/cobra"
)

type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

func main() {
	cmd := newRootCmd()
	if err := cmd.Execute(); err != nil {
		var ee *exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		_ = cmd.Usage()
		os.Exit(2)
	}
}

func newRootCmd() *cobra.Command {
	var (
		baseURL    string
		consoleURL string
		checkOnly  bool
		noCleanup  bool
		batchFile  string
		workers    int
	)
	cmd := &cobra.Command{
		Use:   "nacos3-scopehole",
		Short: "Nacos 3.x auth-scope misassignment (QVD-2026-59388): single-target exploit, zero-write detection, batch scan",
		Args:  cobra.NoArgs,
		// For authorized security testing and isolated lab reproduction only.
		Version:       "1.0.0",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			hc := httpx.New()
			if batchFile != "" {
				if cmd.Flags().Changed("base-url") || cmd.Flags().Changed("console-url") ||
					cmd.Flags().Changed("no-cleanup") {
					return fmt.Errorf("--batch cannot be combined with --base-url, --console-url, or --no-cleanup")
				}
				if workers < 1 {
					return fmt.Errorf("--workers must be >= 1")
				}
				entries, err := nacos.LoadTargets(batchFile)
				if err != nil {
					return fmt.Errorf("cannot read targets file: %w", err)
				}
				if len(entries) == 0 {
					return fmt.Errorf("targets file contains no targets")
				}
				return &exitError{nacos.RunBatch(hc, entries, workers, os.Stdout)}
			}
			base, err := httpx.NormalizeBaseURL(baseURL)
			if err != nil {
				return err
			}
			console := base
			if consoleURL != "" {
				if console, err = httpx.NormalizeBaseURL(consoleURL); err != nil {
					return err
				}
			}
			return &exitError{nacos.RunSingle(hc, base, console, checkOnly, noCleanup, os.Stdout, os.Stderr)}
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&baseURL, "base-url", "http://127.0.0.1:8848/nacos", "Nacos API context root")
	fs.StringVar(&consoleURL, "console-url", "", "console root for login when deployed on a separate port (e.g. http://host:8080/nacos)")
	fs.BoolVar(&checkOnly, "check-only", false, "stop after the zero-write unauthenticated user-list detection")
	fs.BoolVar(&noCleanup, "no-cleanup", false, "keep the injected account, role, permission, and marker config")
	fs.StringVar(&batchFile, "batch", "", "verify many targets from a file (one per line; detection only)")
	fs.IntVar(&workers, "workers", 8, "concurrency for --batch")
	return cmd
}
