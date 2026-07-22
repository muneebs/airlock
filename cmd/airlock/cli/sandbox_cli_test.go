package cli

import (
	"bytes"
	"context"
	"testing"

	"github.com/muneebs/airlock/internal/api"
)

// spySandboxManager records the CreateOptions the sandbox command hands to the
// manager. Only CreateWithOptions is implemented; every other SandboxManager
// method is inherited from the embedded nil interface, so an unexpected call
// panics loudly instead of silently passing.
type spySandboxManager struct {
	api.SandboxManager
	calls   int
	gotSpec api.SandboxSpec
	gotOpts api.CreateOptions
}

func (s *spySandboxManager) CreateWithOptions(_ context.Context, spec api.SandboxSpec, opts api.CreateOptions) (api.SandboxInfo, error) {
	s.calls++
	s.gotSpec = spec
	s.gotOpts = opts
	return api.SandboxInfo{Name: spec.Name, Profile: spec.Profile, Runtime: spec.Runtime}, nil
}

// TestSandboxCommandRequestsProvisioning guards the exact locus of the
// original sandbox-provisioning defect: newSandboxCmd must call
// CreateWithOptions with Provision:true in BOTH the --json and spinner
// branches. The manager-level unit tests all pass Provision:true explicitly,
// so reverting the CLI wiring leaves them green — only this test (and live QA)
// would catch it. See .drydock/airlock-sandbox-provisioning (S1).
func TestSandboxCommandRequestsProvisioning(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"json branch", []string{"sandbox", "--json", "--name", "guard", "gh:example/repo"}},
		{"spinner branch", []string{"sandbox", "--name", "guard", "gh:example/repo"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Empty cwd => no airlock config file => config.Defaults(). With
			// nil Profiles/Detector, loadAndValidateConfig skips dynamic
			// validation, keeping the test hermetic and backend-free.
			t.Chdir(t.TempDir())

			spy := &spySandboxManager{}
			deps := &Dependencies{Manager: spy}

			var stdout, stderr bytes.Buffer
			root := newRootCmd(&stdout, &stderr, deps)
			root.SetArgs(tc.args)

			if err := root.ExecuteContext(context.Background()); err != nil {
				t.Fatalf("sandbox command failed: %v (stderr: %s)", err, stderr.String())
			}

			if spy.calls != 1 {
				t.Fatalf("CreateWithOptions called %d times, want exactly 1", spy.calls)
			}
			if !spy.gotOpts.Provision {
				t.Fatal("sandbox command must pass CreateOptions{Provision: true} so the per-ticket VM " +
					"gets the airlock user + runtime; got Provision=false (CLI provisioning wiring regressed)")
			}
		})
	}
}
