//go:build linux

package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func checkRuntimeIO(root string, p IOPolicy) error {
	var fs unix.Statfs_t
	if e := unix.Statfs(root, &fs); e != nil {
		return e
	}
	if fs.Type != unix.EXT4_SUPER_MAGIC && fs.Type != unix.XFS_SUPER_MAGIC {
		return errors.New("IO policy requires a directly backed ext4/xfs runtime")
	}
	info, e := os.Stat(root)
	if e != nil {
		return e
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || fmt.Sprintf("%d:%d", unix.Major(stat.Dev), unix.Minor(stat.Dev)) != p.FilesystemDevice {
		return errors.New("IO policy does not match runtime filesystem device")
	}
	device, e := directBlockQueue("/sys", p.FilesystemDevice)
	if e != nil {
		return e
	}
	if device != p.Device {
		return errors.New("IO policy must name the exact runtime backing queue")
	}
	return nil
}

// Restrict v1 to an unstacked physical block queue, optionally a partition.
// Never guess at dm/MD/loop/overlay/network storage or silently throttle another
// device. sysfs is kernel-owned; its normal dev/block symlinks are intentional.
func directBlockQueue(sysroot, device string) (string, error) {
	if !validBlockDevice(device) {
		return "", errors.New("invalid filesystem block device")
	}
	path, e := filepath.EvalSymlinks(filepath.Join(sysroot, "dev/block", device))
	if e != nil {
		return "", e
	}
	if !strings.HasPrefix(path, filepath.Join(sysroot, "devices")+"/") || strings.HasPrefix(path, filepath.Join(sysroot, "devices/virtual")+"/") {
		return "", errors.New("block device resolved outside kernel inventory")
	}
	if _, e = os.Stat(filepath.Join(path, "partition")); e == nil {
		path = filepath.Dir(path)
	} else if !os.IsNotExist(e) {
		return "", e
	}
	for _, kind := range []string{"loop", "dm", "md"} {
		if _, e = os.Stat(filepath.Join(path, kind)); e == nil || !os.IsNotExist(e) {
			return "", errors.New("stacked or virtual IO queue unsupported")
		}
	}
	slaves, e := os.ReadDir(filepath.Join(path, "slaves"))
	if e != nil || len(slaves) != 0 {
		return "", errors.New("IO queue must have no slave devices")
	}
	if info, e := os.Stat(filepath.Join(path, "queue")); e != nil || !info.IsDir() {
		return "", errors.New("IO queue inventory absent")
	}
	value, e := os.ReadFile(filepath.Join(path, "dev"))
	if e != nil || !validBlockDevice(strings.TrimSpace(string(value))) {
		return "", errors.New("IO queue identity absent")
	}
	return strings.TrimSpace(string(value)), nil
}

func configureSnapshotIO(ctx context.Context, socket string, p IOPolicy) error {
	if err := apiRequest(ctx, socket, "PATCH", "/drives/workspace", map[string]any{"drive_id": "workspace", "rate_limiter": p.frontendLimit()}); err != nil {
		return err
	}
	return verifyFrontendIO(ctx, socket, p)
}

func applyKernelIO(group string, p IOPolicy) error {
	// No O_CREATE: absent delegation must fail, never become a regular file.
	f, e := os.OpenFile(filepath.Join(group, "io.max"), os.O_WRONLY, 0)
	if e != nil {
		return e
	}
	line := p.kernelLine()
	n, e := io.WriteString(f, line)
	if e == nil && n != len(line) {
		e = io.ErrShortWrite
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return errors.Join(e, closeErr)
	}
	raw, e := os.ReadFile(filepath.Join(group, "io.max"))
	if e != nil {
		return e
	}
	return p.verifyKernelLimit(string(raw))
}

func verifyFrontendIO(ctx context.Context, socket string, p IOPolicy) error {
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, "GET", "http://localhost/vm/config", nil)
	if e != nil {
		return e
	}
	response, e := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if e != nil || len(raw) > 64<<10 || response.StatusCode != http.StatusOK {
		return errors.New("Firecracker IO policy readback failed")
	}
	return p.verifyFrontendConfig(raw)
}

func (p IOPolicy) verifyFrontendConfig(raw []byte) error {
	var config struct {
		Drives []struct {
			ID    string       `json:"drive_id"`
			Limit *ioRateLimit `json:"rate_limiter"`
		} `json:"drives"`
	}
	// Other pinned Firecracker config fields are deliberately ignored; the
	// selected drive and both complete steady buckets must match exactly.
	if e := json.Unmarshal(raw, &config); e != nil || len(config.Drives) != 1 || config.Drives[0].ID != "workspace" ||
		config.Drives[0].Limit == nil || *config.Drives[0].Limit != p.frontendLimit() {
		return errors.New("Firecracker workspace IO policy mismatch")
	}
	return nil
}
