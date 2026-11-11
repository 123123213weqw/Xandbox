//go:build linux

package installtxn

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type programDiskFixture struct {
	f           *filesystem
	inputs      []runtimeProgramInput
	policy      runtimeProgramAuthority
	cert        runtimeProgramCertificate
	certificate string
	paths       map[*os.File]string
}

func programDiskOn(t *testing.T, f *filesystem) *programDiskFixture {
	t.Helper()
	policy, cert, _, data := programApprovalFixture(t)
	for _, dir := range []string{"/etc", runtimeProgramCertificateRoot, "/program-approval-test-data"} {
		if e := os.MkdirAll(f.root.Name()+dir, 0700); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(f.root.Name()+runtimeProgramAuthorityPath, programApprovalWire(t, policy), 0600); e != nil {
		t.Fatal(e)
	}
	certPath := runtimeProgramCertificateRoot + "/" + digest(programApprovalWire(t, cert.Claim.Programs)) + ".json"
	if e := os.WriteFile(f.root.Name()+certPath, programApprovalWire(t, cert), 0600); e != nil {
		t.Fatal(e)
	}
	x := &programDiskFixture{f: f, policy: policy, cert: cert, certificate: certPath, paths: map[*os.File]string{}}
	// Independent explicit path set, also compared to the unchanged runtime
	// engine's actual executable subset below. No candidate path-map oracle.
	for i, p := range []struct{ path, role string }{
		{SelfPath, "installer"}, {childRoot + "/gateway", "gateway"},
		{rolePath("daemon"), "daemon"}, {rolePath("gateway"), "gateway"},
		{rolePath("ingress"), "ingress"}, {rolePath("launcher"), "launcher"},
		{rolePath("node"), "node"}, {rolePath("ready"), "ready"}, {rolePath("template"), "template"},
	} {
		name := f.root.Name() + "/program-approval-test-data/" + string(rune('a'+i))
		if e := os.WriteFile(name, data[p.role], 0444); e != nil {
			t.Fatal(e)
		}
		fd, e := os.Open(name)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { fd.Close() })
		var row runtimeApprovedProgram
		for _, r := range cert.Claim.Programs {
			if r.Role == p.role {
				row = r
			}
		}
		x.inputs = append(x.inputs, runtimeProgramInput{File{Path: p.path, SHA256: row.SHA256, Bytes: row.Bytes, Mode: 0555}, fd})
		x.paths[fd] = name
	}
	sort.Slice(x.inputs, func(i, j int) bool { return x.inputs[i].file.Path < x.inputs[j].file.Path })
	return x
}
func programDisk(t *testing.T) *programDiskFixture {
	t.Helper()
	return programDiskOn(t, operationFixture(t))
}
func programContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	return ctx
}
func programCheck(t *testing.T, x *programDiskFixture) runtimeProgramEvidence {
	t.Helper()
	v, e := x.f.inspectRuntimeProgramApproval(programContext(t), x.inputs)
	if e != nil {
		t.Fatal("signed exact owned bytes refused", e)
	}
	return v
}

func TestRuntimeFileProgramApprovalExactBorrowedFDsAndOffsets(t *testing.T) {
	x := programDisk(t)
	modes := runtimeFileModes()
	count := 0
	for _, mode := range modes {
		if mode == 0555 {
			count++
		}
	}
	if count != 9 {
		t.Fatal("original runtime executable vector changed")
	}
	for _, in := range x.inputs {
		if modes[in.file.Path] != 0555 {
			t.Fatal("approved path escaped original engine vector")
		}
		if _, e := in.source.Seek(7, 0); e != nil {
			t.Fatal(e)
		}
	}
	before := ordinaryNamespaceSnapshot(t, x.f)
	a := programCheck(t, x)
	b := programCheck(t, x)
	if a != b || a == (runtimeProgramEvidence{}) {
		t.Fatal("fresh identical evidence unstable/empty")
	}
	for _, in := range x.inputs {
		if pos, e := in.source.Seek(0, 1); e != nil || pos != 7 {
			t.Fatal("borrowed FD offset changed or closed", pos, e)
		}
	}
	if !reflect.DeepEqual(before, ordinaryNamespaceSnapshot(t, x.f)) {
		t.Fatal("read-only approval wrote/changed fixture")
	}
}

func TestRuntimeFileProgramApprovalRecordFailuresPrecedeProgramAccess(t *testing.T) {
	for _, kind := range []string{"valid-closed-source", "authority-missing", "certificate-missing", "authority-json", "certificate-json", "authority-mode", "certificate-mode", "certificate-parent-mode", "authority-symlink", "certificate-symlink", "authority-hardlink", "certificate-hardlink", "authority-fifo", "certificate-over-limit", "epoch-revoked", "signature-invalid"} {
		t.Run(kind, func(t *testing.T) {
			x := programDisk(t)
			authority := x.f.root.Name() + runtimeProgramAuthorityPath
			certificate := x.f.root.Name() + x.certificate
			var e error
			switch kind {
			case "authority-missing":
				e = os.Remove(authority)
			case "certificate-missing":
				e = os.Remove(certificate)
			case "authority-json":
				e = os.WriteFile(authority, []byte("{\n"), 0600)
			case "certificate-json":
				e = os.WriteFile(certificate, []byte("{\n"), 0600)
			case "authority-mode":
				e = os.Chmod(authority, 0644)
			case "certificate-mode":
				e = os.Chmod(certificate, 0644)
			case "certificate-parent-mode":
				e = os.Chmod(filepath.Dir(certificate), 0755)
			case "authority-symlink", "certificate-symlink":
				path := authority
				if kind == "certificate-symlink" {
					path = certificate
				}
				e = os.Rename(path, path+".owned")
				if e == nil {
					e = os.Symlink(filepath.Base(path)+".owned", path)
				}
			case "authority-hardlink", "certificate-hardlink":
				path := authority
				if kind == "certificate-hardlink" {
					path = certificate
				}
				e = os.Link(path, path+".owned")
			case "authority-fifo":
				e = os.Remove(authority)
				if e == nil {
					e = unix.Mkfifo(authority, 0600)
				}
			case "certificate-over-limit":
				e = os.WriteFile(certificate, make([]byte, MaxPlan+1), 0600)
			case "epoch-revoked":
				x.policy.Epoch++
				e = os.WriteFile(authority, programApprovalWire(t, x.policy), 0600)
			case "signature-invalid":
				x.cert.Signature = strings.Repeat("A", 88)
				e = os.WriteFile(certificate, programApprovalWire(t, x.cert), 0600)
			}
			if e != nil {
				t.Fatal(e)
			}
			// The valid-record control reaches EBADF. Every invalid record MUST
			// refuse before even stat'ing this first original source descriptor.
			if e = x.inputs[0].source.Close(); e != nil {
				t.Fatal(e)
			}
			before := ordinaryNamespaceSnapshot(t, x.f)
			v, e := x.f.inspectRuntimeProgramApproval(programContext(t), x.inputs)
			if e == nil || v != (runtimeProgramEvidence{}) || (errors.Is(e, unix.EBADF) != (kind == "valid-closed-source")) {
				t.Fatal("invalid authority/certificate reached programs or returned partial evidence", kind, e)
			}
			if !reflect.DeepEqual(before, ordinaryNamespaceSnapshot(t, x.f)) {
				t.Fatal("failed approval repaired or removed unknown data")
			}
		})
	}
}

func TestRuntimeFileProgramApprovalSourceMutationAndShapeRefuse(t *testing.T) {
	for _, kind := range []string{"changed-bytes", "short", "extra", "writable", "hardlink", "directory", "nil-source", "closed-source", "missing-program", "duplicate-path", "wrong-mode", "wrong-chroot-gateway", "unbounded-context", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			x := programDisk(t)
			path := x.paths[x.inputs[0].source]
			var e error
			switch kind {
			case "changed-bytes":
				e = os.Chmod(path, 0600)
				if e == nil {
					e = os.WriteFile(path, []byte(strings.Repeat("x", int(x.inputs[0].file.Bytes))), 0444)
				}
				if e == nil {
					e = os.Chmod(path, 0444)
				}
			case "short":
				e = os.Chmod(path, 0600)
				if e == nil {
					e = os.Truncate(path, x.inputs[0].file.Bytes-1)
				}
				if e == nil {
					e = os.Chmod(path, 0444)
				}
			case "extra":
				e = os.Chmod(path, 0600)
				if e == nil {
					e = os.Truncate(path, x.inputs[0].file.Bytes+1)
				}
				if e == nil {
					e = os.Chmod(path, 0444)
				}
			case "writable":
				e = os.Chmod(path, 0666)
			case "hardlink":
				e = os.Link(path, path+".link")
			case "directory":
				var fd *os.File
				fd, e = os.Open(x.f.root.Name())
				if e == nil {
					t.Cleanup(func() { fd.Close() })
					x.inputs[0].source = fd
				}
			case "nil-source":
				x.inputs[0].source = nil
			case "closed-source":
				e = x.inputs[0].source.Close()
			case "missing-program":
				x.inputs = x.inputs[:8]
			case "duplicate-path":
				x.inputs[1].file.Path = x.inputs[0].file.Path
			case "wrong-mode":
				x.inputs[0].file.Mode = 0600
			case "wrong-chroot-gateway":
				for i := range x.inputs {
					if x.inputs[i].file.Path == childRoot+"/gateway" {
						x.inputs[i].file.SHA256 = strings.Repeat("a", 64)
					}
				}
			}
			if e != nil {
				t.Fatal(e)
			}
			ctx := programContext(t)
			if kind == "unbounded-context" {
				ctx = context.Background()
			}
			if kind == "canceled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			before := ordinaryNamespaceSnapshot(t, x.f)
			v, e := x.f.inspectRuntimeProgramApproval(ctx, x.inputs)
			if e == nil || v != (runtimeProgramEvidence{}) {
				t.Fatal("uncertain original bytes/FD/shape became approval", kind, e)
			}
			if !reflect.DeepEqual(before, ordinaryNamespaceSnapshot(t, x.f)) {
				t.Fatal("source rejection mutated fixture")
			}
		})
	}
}

func TestRuntimeFileProgramApprovalRecordPinsRevocationAndSiblingChanges(t *testing.T) {
	for _, kind := range []string{"parent-siblings", "authority-replaced", "certificate-replaced", "revoked", "source-closed"} {
		t.Run(kind, func(t *testing.T) {
			x := programDisk(t)
			old := programCheck(t, x)
			var e error
			switch kind {
			case "parent-siblings":
				e = os.WriteFile(x.f.root.Name()+"/etc/unrelated", []byte("owned"), 0600)
				if e == nil {
					e = os.Mkdir(x.f.root.Name()+"/etc/xandbox-runtime-test-sibling", 0700)
				}
				if e == nil {
					e = os.WriteFile(x.f.root.Name()+runtimeProgramCertificateRoot+"/unrelated", []byte("owned"), 0600)
				}
			case "authority-replaced", "certificate-replaced":
				path := x.f.root.Name() + runtimeProgramAuthorityPath
				raw := programApprovalWire(t, x.policy)
				if kind == "certificate-replaced" {
					path = x.f.root.Name() + x.certificate
					raw = programApprovalWire(t, x.cert)
				}
				e = os.WriteFile(path+".next", raw, 0600)
				if e == nil {
					e = os.Rename(path+".next", path)
				}
			case "revoked":
				x.policy.Epoch++
				e = os.WriteFile(x.f.root.Name()+runtimeProgramAuthorityPath, programApprovalWire(t, x.policy), 0600)
			case "source-closed":
				e = x.inputs[0].source.Close()
			}
			if e != nil {
				t.Fatal(e)
			}
			before := ordinaryNamespaceSnapshot(t, x.f)
			current, e := x.f.inspectRuntimeProgramApproval(programContext(t), x.inputs)
			if kind == "revoked" || kind == "source-closed" {
				if e == nil || current != (runtimeProgramEvidence{}) {
					t.Fatal("revoked evidence cached")
				}
			} else if e != nil || (current == old) != (kind == "parent-siblings") {
				t.Fatal("parent timestamps confused with record identity or stale inode accepted", kind, e)
			}
			if !reflect.DeepEqual(before, ordinaryNamespaceSnapshot(t, x.f)) {
				t.Fatal("fresh check wrote or repaired records")
			}
		})
	}
}

func TestRuntimeFileProgramApprovalConcurrentReadOnlyEvidence(t *testing.T) {
	x := programDisk(t)
	expected := programCheck(t, x)
	before := ordinaryNamespaceSnapshot(t, x.f)
	ctx := programContext(t)
	var wg sync.WaitGroup
	failures := make(chan error, 4)
	for n := 0; n < 4; n++ {
		inputs := append([]runtimeProgramInput(nil), x.inputs...)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 4; k++ {
				v, e := x.f.inspectRuntimeProgramApproval(ctx, inputs)
				if e != nil {
					failures <- e
					return
				}
				if v != expected {
					failures <- ErrConflict
					return
				}
			}
		}()
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		t.Fatal("fresh concurrent original-FD approval", e)
	}
	if !reflect.DeepEqual(before, ordinaryNamespaceSnapshot(t, x.f)) {
		t.Fatal("concurrent reader changed owned files")
	}
}
