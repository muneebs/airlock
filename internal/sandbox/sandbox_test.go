package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/muneebs/airlock/internal/api"
	"github.com/muneebs/airlock/internal/detect"
	"github.com/muneebs/airlock/internal/profile"
	"github.com/muneebs/airlock/internal/sysutil"
)

type fakeProvider struct {
	vms      map[string]bool
	execOut  string
	execErr  error
	startErr error
	stopErr  error
	delErr   error
}

func newFakeProvider() *fakeProvider {
	return &fakeProvider{vms: make(map[string]bool)}
}

func (f *fakeProvider) Create(_ context.Context, spec api.VMSpec) error {
	if _, exists := f.vms[spec.Name]; exists {
		return fmt.Errorf("vm %s already exists", spec.Name)
	}
	f.vms[spec.Name] = false
	return nil
}

func (f *fakeProvider) Start(_ context.Context, name string) error {
	if f.startErr != nil {
		return f.startErr
	}
	if _, ok := f.vms[name]; !ok {
		return fmt.Errorf("vm %s not found", name)
	}
	f.vms[name] = true
	return nil
}

func (f *fakeProvider) Stop(_ context.Context, name string) error {
	if f.stopErr != nil {
		return f.stopErr
	}
	if _, ok := f.vms[name]; !ok {
		return fmt.Errorf("vm %s not found", name)
	}
	f.vms[name] = false
	return nil
}

func (f *fakeProvider) Delete(_ context.Context, name string) error {
	if f.delErr != nil {
		return f.delErr
	}
	delete(f.vms, name)
	return nil
}

func (f *fakeProvider) Exists(_ context.Context, name string) (bool, error) {
	_, ok := f.vms[name]
	return ok, nil
}

func (f *fakeProvider) IsRunning(_ context.Context, name string) (bool, error) {
	running, ok := f.vms[name]
	if !ok {
		return false, nil
	}
	return running, nil
}

func (f *fakeProvider) Exec(_ context.Context, name string, cmd []string) (string, error) {
	return f.execOut, f.execErr
}

func (f *fakeProvider) ExecAsUser(_ context.Context, name, user string, cmd []string) (string, error) {
	return f.execOut, f.execErr
}

func (f *fakeProvider) CopyToVM(_ context.Context, name, src, dst string) error {
	return nil
}

type fakeResetter struct {
	hasSnapshot bool
	restoreErr  error
}

func (f *fakeResetter) RestoreClean(_ context.Context, name string) error {
	return f.restoreErr
}

func (f *fakeResetter) HasCleanSnapshot(_ context.Context, name string) (bool, error) {
	return f.hasSnapshot, nil
}

type fakeMountManager struct {
	mounts []api.Mount
}

func (f *fakeMountManager) Register(_ context.Context, sandboxName string, m api.Mount) error {
	f.mounts = append(f.mounts, m)
	return nil
}

func (f *fakeMountManager) Unregister(_ context.Context, sandboxName string, name string) error {
	filtered := f.mounts[:0]
	for _, m := range f.mounts {
		if m.Name != name {
			filtered = append(filtered, m)
		}
	}
	f.mounts = filtered
	return nil
}

func (f *fakeMountManager) List(_ context.Context, sandboxName string) ([]api.Mount, error) {
	result := make([]api.Mount, len(f.mounts))
	copy(result, f.mounts)
	return result, nil
}

func (f *fakeMountManager) Apply(_ context.Context, sandboxName string) error {
	return nil
}

type fakeNetworkController struct {
	policies []api.NetworkPolicy
	locked   []string
	unlocked []string
	removed  []string
}

func (f *fakeNetworkController) Lock(_ context.Context, sandboxName string) error {
	f.locked = append(f.locked, sandboxName)
	return nil
}

func (f *fakeNetworkController) Unlock(_ context.Context, sandboxName string) error {
	f.unlocked = append(f.unlocked, sandboxName)
	return nil
}

func (f *fakeNetworkController) ApplyPolicy(_ context.Context, sandboxName string, policy api.NetworkPolicy) error {
	f.policies = append(f.policies, policy)
	return nil
}

func (f *fakeNetworkController) IsLocked(_ context.Context, sandboxName string) (bool, error) {
	return len(f.locked) > len(f.unlocked), nil
}

func (f *fakeNetworkController) RemovePolicy(_ context.Context, sandboxName string) error {
	f.removed = append(f.removed, sandboxName)
	return nil
}

func newTestManager(t *testing.T) (*Manager, *fakeProvider, *fakeResetter, *fakeMountManager, *fakeNetworkController) {
	t.Helper()
	dir := t.TempDir()
	storePath := filepath.Join(dir, "sandbox_store.json")

	provider := newFakeProvider()
	resetter := &fakeResetter{hasSnapshot: true}
	detector := detect.NewCompositeDetector()
	profiles := profile.NewRegistry()
	mounts := &fakeMountManager{}
	network := &fakeNetworkController{}

	mgr, err := NewManager(provider, resetter, detector, profiles, mounts, network, storePath)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	mgr.checkRes = func(_ api.SandboxSpec) []sysutil.Insufficiency { return nil }
	return mgr, provider, resetter, mounts, network
}

func intPtr(i int) *int {
	return &i
}

func TestCreateBasicSandbox(t *testing.T) {
	mgr, provider, _, _, network := newTestManager(t)

	spec := api.SandboxSpec{
		Name:    "test-sandbox",
		Profile: "cautious",
		CPU:     intPtr(2),
		Memory:  "4GiB",
		Disk:    "20GiB",
	}

	info, err := mgr.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if info.Name != "test-sandbox" {
		t.Errorf("expected name test-sandbox, got %s", info.Name)
	}
	if info.State != api.StateRunning {
		t.Errorf("expected state running, got %s", info.State)
	}
	if info.Profile != "cautious" {
		t.Errorf("expected profile cautious, got %s", info.Profile)
	}
	if info.CPU != 2 {
		t.Errorf("expected 2 CPU, got %d", info.CPU)
	}

	if _, ok := provider.vms["test-sandbox"]; !ok {
		t.Error("expected VM to be created")
	}

	if len(network.policies) == 0 {
		t.Error("expected network policy to be applied")
	}
}

func TestCreateDefaultProfile(t *testing.T) {
	mgr, _, _, _, _ := newTestManager(t)

	spec := api.SandboxSpec{
		Name: "default-profile",
		CPU:  intPtr(2),
	}

	info, err := mgr.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if info.Profile != "cautious" {
		t.Errorf("expected default profile cautious, got %s", info.Profile)
	}
	if info.Memory != "4GiB" {
		t.Errorf("expected default memory 4GiB, got %s", info.Memory)
	}
	if info.Disk != "20GiB" {
		t.Errorf("expected default disk 20GiB, got %s", info.Disk)
	}
}

func TestCreateAlreadyExists(t *testing.T) {
	mgr, _, _, _, _ := newTestManager(t)

	spec := api.SandboxSpec{Name: "existing", CPU: intPtr(2)}
	_, err := mgr.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("first Create() error: %v", err)
	}

	_, err = mgr.Create(context.Background(), spec)
	if err == nil {
		t.Error("expected error creating duplicate sandbox")
	}
	if _, ok := err.(ErrAlreadyExists); !ok {
		t.Errorf("expected ErrAlreadyExists, got %T: %v", err, err)
	}
}

func TestCreateEmptyName(t *testing.T) {
	mgr, _, _, _, _ := newTestManager(t)

	spec := api.SandboxSpec{CPU: intPtr(2)}
	_, err := mgr.Create(context.Background(), spec)
	if err == nil {
		t.Error("expected error for empty name")
	}
	if _, ok := err.(ErrInvalidSpec); !ok {
		t.Errorf("expected ErrInvalidSpec, got %T: %v", err, err)
	}
}

func TestCreateVMError(t *testing.T) {
	mgr, provider, _, _, _ := newTestManager(t)

	provider.vms["fail-vm"] = false

	spec := api.SandboxSpec{
		Name:    "fail-vm",
		Profile: "cautious",
		CPU:     intPtr(2),
	}

	_, err := mgr.Create(context.Background(), spec)
	if err == nil {
		t.Error("expected error when VM already exists in provider")
	}
}

func TestCreateMountRegistered(t *testing.T) {
	mgr, _, _, mounts, _ := newTestManager(t)

	dir := t.TempDir()
	spec := api.SandboxSpec{
		Name:    "with-mount",
		Source:  dir,
		Runtime: "node",
		Profile: "dev",
		CPU:     intPtr(2),
	}

	_, err := mgr.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if len(mounts.mounts) == 0 {
		t.Error("expected mount to be registered")
	}
	if mounts.mounts[0].HostPath != dir {
		t.Errorf("expected host path %s, got %s", dir, mounts.mounts[0].HostPath)
	}
}

func TestCreateCautiousLocksNetwork(t *testing.T) {
	mgr, _, _, _, network := newTestManager(t)

	spec := api.SandboxSpec{
		Name:    "cautious-test",
		Profile: "cautious",
		CPU:     intPtr(2),
	}

	_, err := mgr.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	found := false
	for _, p := range network.policies {
		if p.LockAfterSetup {
			found = true
		}
	}
	if !found {
		t.Error("cautious profile should trigger LockAfterSetup")
	}

	hasLock := false
	for _, name := range network.locked {
		if name == "cautious-test" {
			hasLock = true
		}
	}
	if !hasLock {
		t.Error("cautious profile should lock network after setup")
	}
}

func TestCreateDevDoesNotLockNetwork(t *testing.T) {
	mgr, _, _, _, network := newTestManager(t)

	spec := api.SandboxSpec{
		Name:    "dev-test",
		Profile: "dev",
		CPU:     intPtr(2),
	}

	_, err := mgr.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	for _, name := range network.locked {
		if name == "dev-test" {
			t.Error("dev profile should not lock network")
		}
	}
}

func TestStopSandbox(t *testing.T) {
	mgr, _, _, _, _ := newTestManager(t)

	spec := api.SandboxSpec{
		Name:    "stop-test",
		Profile: "cautious",
		CPU:     intPtr(2),
	}
	_, err := mgr.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	err = mgr.Stop(context.Background(), "stop-test")
	if err != nil {
		t.Fatalf("Stop() error: %v", err)
	}

	info, err := mgr.Status(context.Background(), "stop-test")
	if err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if info.State != api.StateStopped {
		t.Errorf("expected state stopped, got %s", info.State)
	}
}

func TestStopNonexistentSandbox(t *testing.T) {
	mgr, _, _, _, _ := newTestManager(t)

	err := mgr.Stop(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error stopping nonexistent sandbox")
	}
	if _, ok := err.(ErrNotFound); !ok {
		t.Errorf("expected ErrNotFound, got %T: %v", err, err)
	}
}

func TestDeleteSandbox(t *testing.T) {
	mgr, provider, _, mounts, network := newTestManager(t)

	spec := api.SandboxSpec{
		Name:    "delete-test",
		Profile: "cautious",
		CPU:     intPtr(2),
	}
	_, err := mgr.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	_ = mounts.Register(context.Background(), "delete-test", api.Mount{
		Name:     "delete-test",
		HostPath: "/tmp/test",
	})

	err = mgr.Destroy(context.Background(), "delete-test")
	if err != nil {
		t.Fatalf("Destroy() error: %v", err)
	}

	if _, ok := provider.vms["delete-test"]; ok {
		t.Error("expected VM to be deleted")
	}

	if len(network.removed) != 1 || network.removed[0] != "delete-test" {
		t.Errorf("expected RemovePolicy called with 'delete-test', got %v", network.removed)
	}

	_, err = mgr.Status(context.Background(), "delete-test")
	if err == nil {
		t.Error("expected error querying deleted sandbox")
	}
}

func TestDeleteNonexistentSandbox(t *testing.T) {
	mgr, _, _, _, _ := newTestManager(t)

	err := mgr.Destroy(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error deleting nonexistent sandbox")
	}
}

func TestResetSandbox(t *testing.T) {
	mgr, _, resetter, _, _ := newTestManager(t)

	spec := api.SandboxSpec{
		Name:    "reset-test",
		Profile: "cautious",
		CPU:     intPtr(2),
	}
	_, err := mgr.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	err = mgr.Reset(context.Background(), "reset-test")
	if err != nil {
		t.Fatalf("Reset() error: %v", err)
	}

	info, err := mgr.Status(context.Background(), "reset-test")
	if err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if info.State != api.StateRunning {
		t.Errorf("expected state running after reset, got %s", info.State)
	}

	_ = resetter
}

func TestResetNoSnapshot(t *testing.T) {
	mgr, _, resetter, _, _ := newTestManager(t)

	spec := api.SandboxSpec{
		Name:    "no-snap",
		Profile: "cautious",
		CPU:     intPtr(2),
	}
	_, err := mgr.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	resetter.hasSnapshot = false

	err = mgr.Reset(context.Background(), "no-snap")
	if err == nil {
		t.Error("expected error resetting without snapshot")
	}
}

func TestResetNonexistentSandbox(t *testing.T) {
	mgr, _, _, _, _ := newTestManager(t)

	err := mgr.Reset(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error resetting nonexistent sandbox")
	}
}

func TestListSandboxes(t *testing.T) {
	mgr, _, _, _, _ := newTestManager(t)

	spec1 := api.SandboxSpec{Name: "sandbox-1", Profile: "cautious", CPU: intPtr(2)}
	spec2 := api.SandboxSpec{Name: "sandbox-2", Profile: "dev", CPU: intPtr(4)}

	_, err := mgr.Create(context.Background(), spec1)
	if err != nil {
		t.Fatalf("Create sandbox-1 error: %v", err)
	}
	_, err = mgr.Create(context.Background(), spec2)
	if err != nil {
		t.Fatalf("Create sandbox-2 error: %v", err)
	}

	sandboxes, err := mgr.List(context.Background())
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(sandboxes) != 2 {
		t.Errorf("expected 2 sandboxes, got %d", len(sandboxes))
	}

	names := map[string]bool{}
	for _, sb := range sandboxes {
		names[sb.Name] = true
	}
	if !names["sandbox-1"] || !names["sandbox-2"] {
		t.Errorf("expected sandbox-1 and sandbox-2 in list, got %v", names)
	}
}

func TestStatusSandbox(t *testing.T) {
	mgr, _, _, _, _ := newTestManager(t)

	spec := api.SandboxSpec{
		Name:    "status-test",
		Profile: "cautious",
		CPU:     intPtr(2),
	}
	_, err := mgr.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	info, err := mgr.Status(context.Background(), "status-test")
	if err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if info.Name != "status-test" {
		t.Errorf("expected name status-test, got %s", info.Name)
	}
	if info.State != api.StateRunning {
		t.Errorf("expected state running, got %s", info.State)
	}
}

func TestStatusNonexistentSandbox(t *testing.T) {
	mgr, _, _, _, _ := newTestManager(t)

	_, err := mgr.Status(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent sandbox")
	}
}

func TestRunCommand(t *testing.T) {
	mgr, provider, _, _, _ := newTestManager(t)

	spec := api.SandboxSpec{
		Name:    "run-test",
		Profile: "dev",
		CPU:     intPtr(2),
	}
	_, err := mgr.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	provider.execOut = "hello world"

	output, err := mgr.Run(context.Background(), "run-test", []string{"echo", "hello"})
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if output != "hello world" {
		t.Errorf("expected output 'hello world', got %q", output)
	}
}

func TestRunEmptyCommand(t *testing.T) {
	mgr, _, _, _, _ := newTestManager(t)

	spec := api.SandboxSpec{
		Name:    "run-empty",
		Profile: "dev",
		CPU:     intPtr(2),
	}
	_, err := mgr.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	_, err = mgr.Run(context.Background(), "run-empty", []string{})
	if err == nil {
		t.Error("expected error for empty command")
	}
}

func TestStartAlreadyRunning(t *testing.T) {
	mgr, _, _, _, _ := newTestManager(t)

	spec := api.SandboxSpec{
		Name:    "start-test",
		Profile: "cautious",
		CPU:     intPtr(2),
	}
	_, err := mgr.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	err = mgr.Start(context.Background(), "start-test")
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
}

func TestStopAlreadyStopped(t *testing.T) {
	mgr, _, _, _, _ := newTestManager(t)

	spec := api.SandboxSpec{
		Name:    "stop-test",
		Profile: "cautious",
		CPU:     intPtr(2),
	}
	_, err := mgr.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	err = mgr.Stop(context.Background(), "stop-test")
	if err != nil {
		t.Fatalf("first Stop() error: %v", err)
	}

	err = mgr.Stop(context.Background(), "stop-test")
	if err != nil {
		t.Fatalf("second Stop() error: %v", err)
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "sandbox_store.json")

	provider := newFakeProvider()
	resetter := &fakeResetter{hasSnapshot: true}
	detector := detect.NewCompositeDetector()
	profiles := profile.NewRegistry()
	mounts := &fakeMountManager{}
	network := &fakeNetworkController{}

	mgr, err := NewManager(provider, resetter, detector, profiles, mounts, network, storePath)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	mgr.checkRes = func(_ api.SandboxSpec) []sysutil.Insufficiency { return nil }

	spec := api.SandboxSpec{
		Name:    "persist-test",
		Profile: "cautious",
		CPU:     intPtr(2),
	}
	_, err = mgr.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	mgr2, err := NewManager(provider, resetter, detector, profiles, mounts, network, storePath)
	if err != nil {
		t.Fatalf("NewManager() for reload: %v", err)
	}
	mgr2.checkRes = func(_ api.SandboxSpec) []sysutil.Insufficiency { return nil }

	info, err := mgr2.Status(context.Background(), "persist-test")
	if err != nil {
		t.Fatalf("Status() after reload error: %v", err)
	}
	if info.Name != "persist-test" {
		t.Errorf("expected name persist-test after reload, got %s", info.Name)
	}
}

func TestResolveRuntimeExplicit(t *testing.T) {
	mgr, _, _, _, _ := newTestManager(t)

	spec := api.SandboxSpec{
		Name:    "runtime-test",
		Runtime: "go",
		Profile: "cautious",
		CPU:     intPtr(2),
	}

	info, err := mgr.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	if info.Runtime != "go" {
		t.Errorf("expected runtime go, got %s", info.Runtime)
	}
}

func TestSandboxStateFromVM(t *testing.T) {
	tests := []struct {
		running  bool
		errored  bool
		expected api.SandboxState
	}{
		{true, false, api.StateRunning},
		{false, false, api.StateStopped},
		{false, true, api.StateErrored},
		{true, true, api.StateErrored},
	}
	for _, tt := range tests {
		got := SandboxStateFromVM(tt.running, tt.errored)
		if got != tt.expected {
			t.Errorf("SandboxStateFromVM(%v, %v) = %s, want %s", tt.running, tt.errored, got, tt.expected)
		}
	}
}

func TestCheckResourcesForSpec(t *testing.T) {
	excessiveSpec := api.SandboxSpec{
		Name:   "resource-test",
		CPU:    intPtr(9999),
		Memory: "9999GiB",
		Disk:   "9999GiB",
	}

	issues := CheckResourcesForSpec(excessiveSpec)
	if len(issues) == 0 {
		t.Error("expected resource issues for excessive spec, got none")
	}
}

func TestErrNotFound(t *testing.T) {
	e := ErrNotFound{Name: "test"}
	if e.Error() != "sandbox not found: test" {
		t.Errorf("unexpected error string: %s", e.Error())
	}
}

func TestErrAlreadyExists(t *testing.T) {
	e := ErrAlreadyExists{Name: "test"}
	if e.Error() != "sandbox already exists: test" {
		t.Errorf("unexpected error string: %s", e.Error())
	}
}

func TestErrInvalidSpec(t *testing.T) {
	e := ErrInvalidSpec{Reason: "name is required"}
	if e.Error() != "invalid spec: name is required" {
		t.Errorf("unexpected error string: %s", e.Error())
	}
}

func TestNewSandboxInfo(t *testing.T) {
	spec := api.SandboxSpec{
		Name:    "info-test",
		Profile: "dev",
		CPU:     intPtr(4),
		Memory:  "8GiB",
		Disk:    "40GiB",
		Source:  "/path/to/project",
	}

	info := newSandboxInfo(spec, "node", "dev")
	if info.Name != "info-test" {
		t.Errorf("expected name info-test, got %s", info.Name)
	}
	if info.State != api.StateCreating {
		t.Errorf("expected state creating, got %s", info.State)
	}
	if info.Profile != "dev" {
		t.Errorf("expected profile dev, got %s", info.Profile)
	}
	if info.Runtime != "node" {
		t.Errorf("expected runtime node, got %s", info.Runtime)
	}
	if info.CPU != 4 {
		t.Errorf("expected 4 CPU, got %d", info.CPU)
	}
	if info.Memory != "8GiB" {
		t.Errorf("expected 8GiB memory, got %s", info.Memory)
	}
	if info.Ephemeral {
		t.Error("expected ephemeral false by default")
	}
}

func TestNewSandboxInfoDefaults(t *testing.T) {
	spec := api.SandboxSpec{
		Name:    "defaults-test",
		Profile: "cautious",
	}

	info := newSandboxInfo(spec, "", "cautious")
	if info.CPU != 2 {
		t.Errorf("expected default 2 CPU, got %d", info.CPU)
	}
	if info.Memory != "4GiB" {
		t.Errorf("expected default 4GiB memory, got %s", info.Memory)
	}
	if info.Disk != "20GiB" {
		t.Errorf("expected default 20GiB disk, got %s", info.Disk)
	}
}

func TestSandboxInfoCreatedAt(t *testing.T) {
	spec := api.SandboxSpec{Name: "time-test", Profile: "cautious"}
	info := newSandboxInfo(spec, "", "cautious")
	if info.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
	if info.CreatedAt.After(time.Now()) {
		t.Error("expected CreatedAt to be in the past")
	}
}

func TestCreateStartError(t *testing.T) {
	mgr, provider, _, _, _ := newTestManager(t)
	provider.startErr = fmt.Errorf("start failed")

	spec := api.SandboxSpec{
		Name:    "start-fail",
		Profile: "cautious",
		CPU:     intPtr(2),
	}

	_, err := mgr.Create(context.Background(), spec)
	if err == nil {
		t.Error("expected error when VM start fails")
	}
}

func TestStopError(t *testing.T) {
	mgr, provider, _, _, _ := newTestManager(t)
	provider.stopErr = fmt.Errorf("stop failed")

	spec := api.SandboxSpec{
		Name:    "stop-fail",
		Profile: "cautious",
		CPU:     intPtr(2),
	}
	_, err := mgr.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	err = mgr.Stop(context.Background(), "stop-fail")
	if err == nil {
		t.Error("expected error when VM stop fails")
	}

	info, _ := mgr.Status(context.Background(), "stop-fail")
	if info.State != api.StateErrored {
		t.Errorf("expected errored state after stop failure, got %s", info.State)
	}
}

func TestDeleteStopsRunningVM(t *testing.T) {
	mgr, provider, _, _, _ := newTestManager(t)

	spec := api.SandboxSpec{
		Name:    "delete-running",
		Profile: "cautious",
		CPU:     intPtr(2),
	}
	_, err := mgr.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	running, _ := provider.IsRunning(context.Background(), "delete-running")
	if !running {
		t.Error("expected VM to be running after create")
	}

	err = mgr.Destroy(context.Background(), "delete-running")
	if err != nil {
		t.Fatalf("Destroy() error: %v", err)
	}
}

func TestManagerLoadEmptyStore(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "sandbox_store.json")

	provider := newFakeProvider()
	resetter := &fakeResetter{hasSnapshot: true}
	detector := detect.NewCompositeDetector()
	profiles := profile.NewRegistry()
	mounts := &fakeMountManager{}
	network := &fakeNetworkController{}

	mgr, err := NewManager(provider, resetter, detector, profiles, mounts, network, storePath)
	if err != nil {
		t.Fatalf("NewManager() with empty store: %v", err)
	}

	sandboxes, err := mgr.List(context.Background())
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(sandboxes) != 0 {
		t.Errorf("expected empty list, got %d", len(sandboxes))
	}
}

func TestManagerLoadCorruptStore(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "sandbox_store.json")

	if err := os.WriteFile(storePath, []byte("{invalid json"), 0644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	provider := newFakeProvider()
	resetter := &fakeResetter{hasSnapshot: true}
	detector := detect.NewCompositeDetector()
	profiles := profile.NewRegistry()
	mounts := &fakeMountManager{}
	network := &fakeNetworkController{}

	_, err := NewManager(provider, resetter, detector, profiles, mounts, network, storePath)
	if err == nil {
		t.Error("expected error loading corrupt store")
	}
}

func TestResetRestoreError(t *testing.T) {
	mgr, _, resetter, _, _ := newTestManager(t)
	resetter.restoreErr = fmt.Errorf("restore failed")

	spec := api.SandboxSpec{
		Name:    "reset-fail",
		Profile: "cautious",
		CPU:     intPtr(2),
	}
	_, err := mgr.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	err = mgr.Stop(context.Background(), "reset-fail")
	if err != nil {
		t.Fatalf("Stop() error: %v", err)
	}

	err = mgr.Reset(context.Background(), "reset-fail")
	if err == nil {
		t.Error("expected error when restore fails")
	}

	info, _ := mgr.Status(context.Background(), "reset-fail")
	if info.State != api.StateErrored {
		t.Errorf("expected errored state after reset failure, got %s", info.State)
	}
}

func TestCreateConcurrentDuplicate(t *testing.T) {
	mgr, _, _, _, _ := newTestManager(t)

	spec := api.SandboxSpec{
		Name:    "concurrent-dupe",
		Profile: "cautious",
		CPU:     intPtr(2),
	}

	errCh := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := mgr.Create(context.Background(), spec)
			errCh <- err
		}()
	}

	errs := []error{}
	for i := 0; i < 2; i++ {
		err := <-errCh
		if err != nil {
			errs = append(errs, err)
		}
	}

	foundAlreadyExists := false
	for _, err := range errs {
		if _, ok := err.(ErrAlreadyExists); ok {
			foundAlreadyExists = true
		}
	}
	if !foundAlreadyExists {
		t.Error("expected at least one ErrAlreadyExists from concurrent creation")
	}

	sandboxes, err := mgr.List(context.Background())
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	count := 0
	for _, sb := range sandboxes {
		if sb.Name == "concurrent-dupe" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 sandbox named 'concurrent-dupe', got %d", count)
	}
}
