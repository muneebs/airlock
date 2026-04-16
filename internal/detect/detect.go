// Package detect auto-detects the runtime environment of a project directory.
// It examines file markers (go.mod, package.json, Cargo.toml, etc.) to determine
// what runtime, install command, and run command a project needs.
// Detectors are registered at init time and can be extended by third-party packages.
package detect

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/muneebs/airlock/internal/api"
)

// Detector checks for a specific runtime's markers and returns a DetectedRuntime.
type Detector interface {
	// Detect inspects the directory and returns a DetectedRuntime if the project
	// matches this detector's runtime type. Returns ErrNotDetected if no match.
	Detect(dir string) (api.DetectedRuntime, error)
	// Type returns the RuntimeType this detector handles.
	Type() api.RuntimeType
	// Priority determines detection order. Lower numbers run first.
	Priority() int
}

// ErrNotDetected is returned when a detector finds no matches in a directory.
type ErrNotDetected struct {
	Dir string
}

func (e ErrNotDetected) Error() string {
	return "runtime not detected in " + e.Dir
}

// CompositeDetector runs all registered detectors in priority order
// and returns the first match. It implements RuntimeDetector from the api package.
type CompositeDetector struct {
	detectors []Detector
}

// NewCompositeDetector creates a detector with all built-in detectors registered.
func NewCompositeDetector() *CompositeDetector {
	d := &CompositeDetector{}
	d.register(defaultDetectors()...)
	return d
}

func (c *CompositeDetector) register(detectors ...Detector) {
	c.detectors = append(c.detectors, detectors...)
	sortByPriority(c.detectors)
}

// Register adds a custom detector. Detectors are re-sorted by priority after insertion.
func (c *CompositeDetector) Register(d Detector) {
	c.detectors = append(c.detectors, d)
	sortByPriority(c.detectors)
}

// Detect runs all detectors in priority order and returns the first match.
// ErrNotDetected causes the loop to continue to the next detector.
// Any other error causes an immediate return (fail fast).
func (c *CompositeDetector) Detect(dir string) (api.DetectedRuntime, error) {
	for _, d := range c.detectors {
		result, err := d.Detect(dir)
		if err == nil {
			return result, nil
		}
		var notDetected ErrNotDetected
		if !errors.As(err, &notDetected) {
			return api.DetectedRuntime{}, err
		}
	}
	return api.DetectedRuntime{}, ErrNotDetected{Dir: dir}
}

// SupportedTypes returns all registered runtime types.
func (c *CompositeDetector) SupportedTypes() []api.RuntimeType {
	types := make([]api.RuntimeType, len(c.detectors))
	for i, d := range c.detectors {
		types[i] = d.Type()
	}
	return types
}

func sortByPriority(detectors []Detector) {
	for i := 1; i < len(detectors); i++ {
		for j := i; j > 0 && detectors[j].Priority() < detectors[j-1].Priority(); j-- {
			detectors[j], detectors[j-1] = detectors[j-1], detectors[j]
		}
	}
}

func defaultDetectors() []Detector {
	return []Detector{
		&dockerComposeDetector{},
		&dockerfileDetector{},
		&nodeDetector{},
		&goDetector{},
		&rustDetector{},
		&pythonDetector{},
		&dotnetDetector{},
		&makeDetector{},
	}
}

// --- Individual detectors ---

type nodeDetector struct{}

func (n *nodeDetector) Type() api.RuntimeType { return api.RuntimeNode }
func (n *nodeDetector) Priority() int         { return 30 }
func (n *nodeDetector) Detect(dir string) (api.DetectedRuntime, error) {
	exists, err := fileExists(dir, "package.json")
	if err != nil {
		return api.DetectedRuntime{}, err
	}
	if !exists {
		return api.DetectedRuntime{}, ErrNotDetected{Dir: dir}
	}

	runtime := api.DetectedRuntime{
		Type:       api.RuntimeNode,
		Confidence: 0.95,
	}

	if exists, _ := fileExists(dir, "pnpm-lock.yaml"); exists {
		runtime.InstallCmd = "pnpm install --frozen-lockfile"
		runtime.RunCmd = "pnpm dev"
	} else if exists, _ := fileExists(dir, "bun.lockb"); exists {
		runtime.InstallCmd = "bun install --frozen-lockfile"
		runtime.RunCmd = "bun run dev"
	} else if exists, _ := fileExists(dir, "bun.lock"); exists {
		runtime.InstallCmd = "bun install --frozen-lockfile"
		runtime.RunCmd = "bun run dev"
	} else if exists, _ := fileExists(dir, "package-lock.json"); exists {
		runtime.InstallCmd = "npm ci"
		runtime.RunCmd = "npm run dev"
	} else {
		runtime.InstallCmd = "npm install"
		runtime.RunCmd = "npm run dev"
	}

	return runtime, nil
}

type goDetector struct{}

func (g *goDetector) Type() api.RuntimeType { return api.RuntimeGo }
func (g *goDetector) Priority() int         { return 20 }
func (g *goDetector) Detect(dir string) (api.DetectedRuntime, error) {
	exists, err := fileExists(dir, "go.mod")
	if err != nil {
		return api.DetectedRuntime{}, err
	}
	if !exists {
		return api.DetectedRuntime{}, ErrNotDetected{Dir: dir}
	}
	return api.DetectedRuntime{
		Type:       api.RuntimeGo,
		InstallCmd: "go mod download",
		RunCmd:     "go run .",
		Confidence: 0.95,
	}, nil
}

type rustDetector struct{}

func (r *rustDetector) Type() api.RuntimeType { return api.RuntimeRust }
func (r *rustDetector) Priority() int         { return 25 }
func (r *rustDetector) Detect(dir string) (api.DetectedRuntime, error) {
	exists, err := fileExists(dir, "Cargo.toml")
	if err != nil {
		return api.DetectedRuntime{}, err
	}
	if !exists {
		return api.DetectedRuntime{}, ErrNotDetected{Dir: dir}
	}
	return api.DetectedRuntime{
		Type:       api.RuntimeRust,
		InstallCmd: "cargo build",
		RunCmd:     "cargo run",
		Confidence: 0.95,
	}, nil
}

type pythonDetector struct{}

func (p *pythonDetector) Type() api.RuntimeType { return api.RuntimePython }
func (p *pythonDetector) Priority() int         { return 35 }
func (p *pythonDetector) Detect(dir string) (api.DetectedRuntime, error) {
	hasReq, err := fileExists(dir, "requirements.txt")
	if err != nil {
		return api.DetectedRuntime{}, err
	}
	hasPyproject, err := fileExists(dir, "pyproject.toml")
	if err != nil {
		return api.DetectedRuntime{}, err
	}
	hasSetup, err := fileExists(dir, "setup.py")
	if err != nil {
		return api.DetectedRuntime{}, err
	}

	if !hasReq && !hasPyproject && !hasSetup {
		return api.DetectedRuntime{}, ErrNotDetected{Dir: dir}
	}

	runtime := api.DetectedRuntime{
		Type:       api.RuntimePython,
		Confidence: 0.85,
	}

	if hasPyproject {
		runtime.InstallCmd = "pip install -e ."
	} else if hasReq {
		runtime.InstallCmd = "pip install -r requirements.txt"
	} else {
		runtime.InstallCmd = "pip install -e ."
	}

	if hasPyproject {
		runtime.RunCmd = ""
	} else {
		mainPy := filepath.Join(dir, "main.py")
		appPy := filepath.Join(dir, "app.py")
		if _, err := os.Stat(mainPy); err == nil {
			runtime.RunCmd = "python main.py"
		} else if _, err := os.Stat(appPy); err == nil {
			runtime.RunCmd = "python app.py"
		} else {
			runtime.RunCmd = ""
		}
	}

	return runtime, nil
}

func hasComposeFile(dir string) (bool, error) {
	for _, name := range []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"} {
		exists, err := fileExists(dir, name)
		if err != nil {
			return false, err
		}
		if exists {
			return true, nil
		}
	}
	return false, nil
}

type dockerfileDetector struct{}

func (d *dockerfileDetector) Type() api.RuntimeType { return api.RuntimeDocker }
func (d *dockerfileDetector) Priority() int         { return 10 }
func (d *dockerfileDetector) Detect(dir string) (api.DetectedRuntime, error) {
	hasCompose, err := hasComposeFile(dir)
	if err != nil {
		return api.DetectedRuntime{}, err
	}
	if hasCompose {
		return api.DetectedRuntime{}, ErrNotDetected{Dir: dir}
	}
	exists, err := fileExists(dir, "Dockerfile")
	if err != nil {
		return api.DetectedRuntime{}, err
	}
	if !exists {
		return api.DetectedRuntime{}, ErrNotDetected{Dir: dir}
	}
	return api.DetectedRuntime{
		Type:        api.RuntimeDocker,
		InstallCmd:  "docker build -t app .",
		RunCmd:      "docker run --rm -it app",
		NeedsDocker: true,
		Confidence:  0.9,
	}, nil
}

type dockerComposeDetector struct{}

func (d *dockerComposeDetector) Type() api.RuntimeType { return api.RuntimeCompose }
func (d *dockerComposeDetector) Priority() int         { return 5 }
func (d *dockerComposeDetector) Detect(dir string) (api.DetectedRuntime, error) {
	hasCompose, err := hasComposeFile(dir)
	if err != nil {
		return api.DetectedRuntime{}, err
	}
	if !hasCompose {
		return api.DetectedRuntime{}, ErrNotDetected{Dir: dir}
	}
	return api.DetectedRuntime{
		Type:        api.RuntimeCompose,
		InstallCmd:  "docker compose pull",
		RunCmd:      "docker compose up",
		NeedsDocker: true,
		Confidence:  0.95,
	}, nil
}

type makeDetector struct{}

func (m *makeDetector) Type() api.RuntimeType { return api.RuntimeMake }
func (m *makeDetector) Priority() int         { return 50 }
func (m *makeDetector) Detect(dir string) (api.DetectedRuntime, error) {
	hasMakefile, err := fileExists(dir, "Makefile")
	if err != nil {
		return api.DetectedRuntime{}, err
	}
	hasMakefileLower, err := fileExists(dir, "makefile")
	if err != nil {
		return api.DetectedRuntime{}, err
	}
	if !hasMakefile && !hasMakefileLower {
		return api.DetectedRuntime{}, ErrNotDetected{Dir: dir}
	}

	// Makefile is a fallback — other detectors should take priority.
	// Only return this if no higher-priority detector matched.
	return api.DetectedRuntime{
		Type:       api.RuntimeMake,
		InstallCmd: "make",
		RunCmd:     "make run",
		Confidence: 0.5,
	}, nil
}

type dotnetDetector struct{}

func (d *dotnetDetector) Type() api.RuntimeType { return api.RuntimeDotNet }
func (d *dotnetDetector) Priority() int         { return 40 }
func (d *dotnetDetector) Detect(dir string) (api.DetectedRuntime, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.csproj"))
	if err != nil || len(matches) == 0 {
		matches, err = filepath.Glob(filepath.Join(dir, "*.sln"))
		if err != nil || len(matches) == 0 {
			return api.DetectedRuntime{}, ErrNotDetected{Dir: dir}
		}
	}
	return api.DetectedRuntime{
		Type:       api.RuntimeDotNet,
		InstallCmd: "dotnet restore",
		RunCmd:     "dotnet run",
		Confidence: 0.9,
	}, nil
}

// ResolveRuntimeType converts a string runtime type to the api.RuntimeType enum.
// Returns an error for unknown types.
func ResolveRuntimeType(s string) (api.RuntimeType, error) {
	mapping := map[string]api.RuntimeType{
		"node":    api.RuntimeNode,
		"go":      api.RuntimeGo,
		"rust":    api.RuntimeRust,
		"python":  api.RuntimePython,
		"docker":  api.RuntimeDocker,
		"compose": api.RuntimeCompose,
		"make":    api.RuntimeMake,
		"dotnet":  api.RuntimeDotNet,
	}
	rt, ok := mapping[strings.ToLower(s)]
	if !ok {
		return "", fmt.Errorf("unknown runtime type: %q (valid: node, go, rust, python, docker, compose, make, dotnet)", s)
	}
	return rt, nil
}

func fileExists(dir, name string) (bool, error) {
	_, err := os.Stat(filepath.Join(dir, name))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("stat %s: %w", filepath.Join(dir, name), err)
}
