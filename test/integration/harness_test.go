package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/muneebs/airlock/internal/api"
	"github.com/muneebs/airlock/internal/detect"
	"github.com/muneebs/airlock/internal/mount"
	"github.com/muneebs/airlock/internal/network"
	"github.com/muneebs/airlock/internal/profile"
	"github.com/muneebs/airlock/internal/sandbox"
	"github.com/muneebs/airlock/internal/sysutil"
	"github.com/muneebs/airlock/internal/vm/lima"
)

type harness struct {
	tmpDir      string
	fakeLimactl string
	callLog     string
	limaDir     string
	stateDir    string

	Manager  *sandbox.Manager
	Provider *lima.LimaProvider
	Network  *network.LimaController
	Mounts   *mount.JSONStore
	Profiles *profile.Registry
	Detector *detect.CompositeDetector
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	dir := t.TempDir()
	callLog := filepath.Join(dir, "calls.log")
	limaDir := filepath.Join(dir, "lima")
	stateDir := filepath.Join(dir, "vmstate")
	fakeLimactl := filepath.Join(dir, "bin", "limactl")

	for _, d := range []string{filepath.Join(dir, "bin"), limaDir, stateDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	script := "#!/bin/sh\n" +
		"echo \"$@\" >> " + shellQuote(callLog) + "\n" +
		"SDIR=" + shellQuote(stateDir) + "\n" +
		`case "$1" in
  list)
    if [ "$2" = "--json" ]; then
      for f in "$SDIR"/*.json; do
        [ -f "$f" ] && cat "$f"
      done
      exit 0
    fi
    ;;
  create)
    name=""
    for arg in "$@"; do
      case "$arg" in --name=*) name="${arg#--name=}" ;; esac
    done
    if [ -z "$name" ]; then
      last="$#"
      eval "lastarg=\\$$last"
      name="$(basename "${lastarg%.yaml}")"
    fi
    printf '{"name":"%s","status":"Stopped"}\n' "$name" > "$SDIR/$name.json"
    ;;
  start)
    shift
    for arg in "$@"; do case "$arg" in --*) ;; *) name="$arg" ;; esac; done
    printf '{"name":"%s","status":"Running"}\n' "$name" > "$SDIR/$name.json"
    ;;
  stop)
    shift
    for arg in "$@"; do case "$arg" in --*) ;; *) name="$arg" ;; esac; done
    printf '{"name":"%s","status":"Stopped"}\n' "$name" > "$SDIR/$name.json"
    ;;
  delete)
    shift
    for arg in "$@"; do case "$arg" in --*) ;; *) name="$arg" ;; esac; done
    rm -f "$SDIR/$name.json"
    ;;
  shell)
    name="$2"
    shift 2
    if [ "$1" = "--workdir" ]; then shift 2; fi
    if [ "$1" = "--" ]; then shift; fi
    if [ $# -gt 0 ]; then
      printf "ok\n"
    fi
    ;;
  copy)
    ;;
esac
exit 0
`

	if err := os.WriteFile(fakeLimactl, []byte(script), 0755); err != nil {
		t.Fatalf("write fake limactl: %v", err)
	}

	provider := lima.NewLimaProviderWithPaths(fakeLimactl, limaDir)

	detector := detect.NewCompositeDetector()
	profiles := profile.NewRegistry()

	mountPath := filepath.Join(dir, "mounts.json")
	mountStore, err := mount.NewJSONStore(mountPath)
	if err != nil {
		t.Fatalf("new mount store: %v", err)
	}

	storePath := filepath.Join(dir, "sandboxes.json")

	networkCtrl := network.NewLimaControllerWithRunners(
		fakeRunCmd(t, callLog),
		fakeRunOutput(),
	)

	mgr, err := sandbox.NewManager(
		provider,
		provider,
		detector,
		profiles,
		mountStore,
		networkCtrl,
		storePath,
	)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	mgr.SetCheckResources(func(_ api.SandboxSpec) []sysutil.Insufficiency { return nil })

	return &harness{
		tmpDir:      dir,
		fakeLimactl: fakeLimactl,
		callLog:     callLog,
		limaDir:     limaDir,
		stateDir:    stateDir,
		Manager:     mgr,
		Provider:    provider,
		Network:     networkCtrl,
		Mounts:      mountStore,
		Profiles:    profiles,
		Detector:    detector,
	}
}

func (h *harness) calls() []string {
	data, err := os.ReadFile(h.callLog)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return nil
	}
	raw := strings.TrimSpace(string(data))
	if raw == "" {
		return nil
	}

	var result []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func (h *harness) resetCalls() {
	_ = os.WriteFile(h.callLog, []byte{}, 0644)
}

func (h *harness) ctx() context.Context {
	return context.Background()
}

func (h *harness) createVMFiles(t *testing.T, name string) {
	t.Helper()
	vmDir := filepath.Join(h.limaDir, name)
	if err := os.MkdirAll(vmDir, 0755); err != nil {
		t.Fatalf("mkdir vm dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(vmDir, "lima.yaml"), []byte("vm: true\n"), 0600); err != nil {
		t.Fatalf("write lima.yaml: %v", err)
	}
}

func intPtr(i int) *int {
	return &i
}

func fakeRunCmd(t *testing.T, callLog string) network.CommandRunner {
	t.Helper()
	return func(_ context.Context, vmName, cmd string) error {
		f, err := os.OpenFile(callLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		fmt.Fprintf(f, "exec:%s:%s\n", vmName, cmd)
		f.Close()
		return nil
	}
}

func fakeRunOutput() network.OutputRunner {
	return func(_ context.Context, _, cmd string) (string, error) {
		if strings.Contains(cmd, "iptables") {
			return "Chain OUTPUT (policy ACCEPT)\n", nil
		}
		return "", nil
	}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
