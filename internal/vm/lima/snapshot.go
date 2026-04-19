package lima

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/muneebs/airlock/internal/api"
)

// copyFileStreaming copies a regular file without loading it into memory.
// Lima disk images are multi-GB (often sparse); os.ReadFile would allocate
// a buffer of the apparent size and either OOM or thrash swap, appearing to
// the user as a hang during the snapshot phase.
func copyFileStreaming(src, dst string, perm fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, perm.Perm())
}

// safeFilePerm masks file permissions to strips SUID, SGID, and world-write bits,
// preventing privilege escalation via snapshot restore.
func safeFilePerm(m fs.FileMode) fs.FileMode {
	return m.Perm() & 0755
}

// cleanSnapshotPath returns the current snapshot path for a VM.
// Snapshots live outside limaDir so Lima does not list them as VMs.
func (p *LimaProvider) cleanSnapshotPath(name string) string {
	return filepath.Join(p.snapshotDir, name)
}

// legacyCleanSnapshotPath returns the pre-migration snapshot path
// (<limaDir>/<name>-clean). Still read by RestoreClean/HasCleanSnapshot so
// users with existing snapshots don't have to re-run setup.
func (p *LimaProvider) legacyCleanSnapshotPath(name string) string {
	return filepath.Join(p.limaDir, name+"-clean")
}

// SnapshotClean copies the VM's Lima directory to a clean baseline stored
// outside Lima's state dir (so Lima does not list the snapshot as a second VM).
// Runtime files like sockets are excluded. Any legacy in-Lima snapshot for the
// same VM is deleted so `limactl list` stops surfacing it.
func (p *LimaProvider) SnapshotClean(ctx context.Context, name string) error {
	if err := validateName(name); err != nil {
		return fmt.Errorf("invalid vm name: %w", err)
	}
	vmDir := filepath.Join(p.limaDir, name)
	cleanDir := p.cleanSnapshotPath(name)

	if _, err := os.Stat(vmDir); err != nil {
		return fmt.Errorf("vm dir %s not found: %w", vmDir, err)
	}

	if err := os.MkdirAll(filepath.Dir(cleanDir), 0755); err != nil {
		return fmt.Errorf("create snapshot dir: %w", err)
	}
	// Write into a sibling tmp dir and swap on success so a mid-walk failure
	// does not destroy the previous snapshot.
	tmpDir := cleanDir + ".tmp"
	if err := os.RemoveAll(tmpDir); err != nil {
		return fmt.Errorf("remove stale tmp dir: %w", err)
	}
	// Legacy snapshot (inside limaDir) is removed on success only: if the
	// new snapshot below fails we'd rather keep the old one as fallback.
	legacyDir := p.legacyCleanSnapshotPath(name)

	if err := filepath.WalkDir(vmDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(vmDir, path)
		if err != nil {
			return err
		}

		// Skip sockets and other runtime files
		if strings.HasSuffix(relPath, ".sock") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		targetPath := filepath.Join(tmpDir, relPath)

		if d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			return os.MkdirAll(targetPath, safeFilePerm(info.Mode()))
		}

		if !d.Type().IsRegular() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}

		return copyFileStreaming(path, targetPath, safeFilePerm(info.Mode()))
	}); err != nil {
		_ = os.RemoveAll(tmpDir)
		return err
	}

	// Swap: remove old snapshot only after the new one is fully written.
	// os.Rename over an existing directory fails on Linux/macOS, so clear
	// the target first. Failure between these two lines is the narrow window
	// where a snapshot can be lost; acceptable since tmpDir stays on disk
	// for manual recovery.
	if err := os.RemoveAll(cleanDir); err != nil {
		return fmt.Errorf("remove old clean dir: %w", err)
	}
	if err := os.Rename(tmpDir, cleanDir); err != nil {
		return fmt.Errorf("promote snapshot: %w", err)
	}

	if _, err := os.Stat(legacyDir); err == nil {
		if err := os.RemoveAll(legacyDir); err != nil {
			return fmt.Errorf("remove legacy clean dir: %w", err)
		}
	}
	return nil
}

// RestoreClean copies the clean baseline back over the VM directory,
// restoring it to a freshly-provisioned state. The VM must be stopped.
// Falls back to the legacy in-Lima snapshot location if the new one is absent
// (so users with pre-migration snapshots don't break on reset).
func (p *LimaProvider) RestoreClean(ctx context.Context, name string) error {
	if err := validateName(name); err != nil {
		return fmt.Errorf("invalid vm name: %w", err)
	}
	vmDir := filepath.Join(p.limaDir, name)

	cleanDir := p.cleanSnapshotPath(name)
	if _, err := os.Stat(cleanDir); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("stat clean baseline: %w", err)
		}
		// Fall back to legacy path.
		legacy := p.legacyCleanSnapshotPath(name)
		if _, lerr := os.Stat(legacy); lerr != nil {
			return fmt.Errorf("clean baseline not found (checked %s and %s)", cleanDir, legacy)
		}
		cleanDir = legacy
	}

	if err := os.RemoveAll(vmDir); err != nil {
		return fmt.Errorf("remove vm dir: %w", err)
	}

	return copyDir(cleanDir, vmDir)
}

// HasCleanSnapshot reports whether a clean baseline exists for the VM at
// either the current or legacy location.
func (p *LimaProvider) HasCleanSnapshot(ctx context.Context, name string) (bool, error) {
	if err := validateName(name); err != nil {
		return false, fmt.Errorf("invalid vm name: %w", err)
	}
	for _, dir := range []string{p.cleanSnapshotPath(name), p.legacyCleanSnapshotPath(name)} {
		if _, err := os.Stat(dir); err == nil {
			return true, nil
		} else if !os.IsNotExist(err) {
			return false, fmt.Errorf("stat clean snapshot dir: %w", err)
		}
	}
	return false, nil
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if strings.HasSuffix(relPath, ".sock") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		targetPath := filepath.Join(dst, relPath)

		if d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			return os.MkdirAll(targetPath, safeFilePerm(info.Mode()))
		}

		if !d.Type().IsRegular() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}

		return copyFileStreaming(path, targetPath, safeFilePerm(info.Mode()))
	})
}

// Verify LimaProvider implements api.Provider at compile time.
var _ api.Provider = (*LimaProvider)(nil)

// Verify LimaProvider implements api.Provisioner at compile time.
var _ api.Provisioner = (*LimaProvider)(nil)

// Verify LimaProvider implements api.ShellProvider at compile time.
var _ api.ShellProvider = (*LimaProvider)(nil)
