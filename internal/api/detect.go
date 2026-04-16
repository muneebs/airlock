package api

// DetectedRuntime holds the result of auto-detecting a project's runtime.
type DetectedRuntime struct {
	Type        RuntimeType `json:"type" yaml:"type"`
	InstallCmd  string      `json:"install_cmd" yaml:"install_cmd"`
	RunCmd      string      `json:"run_cmd" yaml:"run_cmd"`
	NeedsDocker bool        `json:"needs_docker" yaml:"needs_docker"`
	Confidence  float64     `json:"confidence" yaml:"confidence"`
}

// RuntimeType enumerates supported runtime environments.
type RuntimeType string

const (
	RuntimeNode    RuntimeType = "node"
	RuntimeGo      RuntimeType = "go"
	RuntimeRust    RuntimeType = "rust"
	RuntimePython  RuntimeType = "python"
	RuntimeDocker  RuntimeType = "docker"
	RuntimeCompose RuntimeType = "compose"
	RuntimeMake    RuntimeType = "make"
	RuntimeDotNet  RuntimeType = "dotnet"
	RuntimeUnknown RuntimeType = "unknown"
)

// RuntimeDetector inspects a directory and determines what runtime it needs.
type RuntimeDetector interface {
	Detect(dir string) (DetectedRuntime, error)
	SupportedTypes() []RuntimeType
}

// RuntimeDetectorFunc is a convenience adapter for single-function detectors.
type RuntimeDetectorFunc func(dir string) (DetectedRuntime, error)

func (f RuntimeDetectorFunc) Detect(dir string) (DetectedRuntime, error) {
	return f(dir)
}

func (f RuntimeDetectorFunc) SupportedTypes() []RuntimeType {
	return nil
}
