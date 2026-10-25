//go:build linux && xandbox_host_fixture

package main

// TEST ONLY: fixed gateway reload FSYNC or post-commit MEMFD_CREATE hold.
// Not a security policy, filesystem D-state, or physical-media fault. No target
// receives a reply; all other notifications only CONTINUE to the real kernel.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

type tlsPolicyMode string

const tlsPolicyPre tlsPolicyMode = "pre-file"
const tlsPolicyPost tlsPolicyMode = "post-commit"
const tlsPolicyGatewaySHA = "41e9735696072936388d5481b7dcd595e38e2346437379b0f2999b5cc47b730a"
const tlsPolicyRoot = gatewayDir + "/policy"
const tlsPolicyReceipt = gatewayDir + "/policy-fault-receipt.json"
const tlsPolicyMemfd = "xandbox-gateway-policy"
const tlsPolicyHoldMax = 20 * time.Second

var tlsPolicyTemp = regexp.MustCompile(`^\.policy-[0-9]+$`)

func (m tlsPolicyMode) valid() bool { return m == tlsPolicyPre || m == tlsPolicyPost }

type tlsPolicyRecord struct {
	Version  int    `json:"version"`
	Revision uint64 `json:"revision"`
	Digest   string `json:"snapshot_sha256"`
}

func tlsPolicyRead() (tlsPolicyRecord, error) {
	var r tlsPolicyRecord
	if e := requireNode(); e != nil {
		return r, e
	}
	b, e := privatefile.Read(tlsPolicyRoot+"/policy.json", 4096)
	if e != nil {
		return r, e
	}
	if strictjson.Decode(b, &r) != nil || r.Version != 1 || r.Revision == 0 || !hashPattern.MatchString(r.Digest) {
		return r, errors.New("invalid fixed gateway policy record")
	}
	return r, nil
}
func tlsPolicyExpected(c gateway.Config) (tlsPolicyRecord, error) {
	var zero tlsPolicyRecord
	if e := requireNode(); e != nil {
		return zero, e
	}
	if (c.PolicyRevision != 1 && c.PolicyRevision != 2) || c.StateDir != tlsPolicyRoot || c.EmptyRoot != gatewayDir+"/root" || c.CertificateFile != fmt.Sprintf(gatewayDir+"/server%d.pem", c.PolicyRevision) || c.PrivateKeyFile != fmt.Sprintf(gatewayDir+"/server%d.key", c.PolicyRevision) {
		return zero, errors.New("fixed policy input required")
	}
	cert, e := privatefile.Read(c.CertificateFile, 65536)
	if e != nil {
		return zero, e
	}
	key, e := privatefile.Read(c.PrivateKeyFile, 65536)
	if e != nil {
		return zero, e
	}
	s := gateway.Snapshot{Version: 1, Epoch: c.PolicyRevision, UID: c.UID, GID: c.GID, Listen: c.Listen, ServerName: c.ServerName, CertificatePEM: string(cert), PrivateKeyPEM: string(key), Keys: c.Keys}
	b, e := json.Marshal(s)
	if e != nil {
		return zero, e
	}
	return tlsPolicyRecord{Version: 1, Revision: c.PolicyRevision, Digest: gatewayHashToken(string(b))}, nil
}
func tlsPolicyProgram() ([]unix.SockFilter, error) {
	base, e := ownerNotifyProgram()
	if e != nil {
		return nil, e
	}
	p := append([]unix.SockFilter(nil), base[:6]...)
	return append(p,
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(unix.SYS_FSYNC), Jt: 1},
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(unix.SYS_MEMFD_CREATE), Jf: 1},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_USER_NOTIF},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW}), nil
}
func runTLSPolicyGateway() error {
	if e := requireQuotaChild(); e != nil {
		return e
	}
	if _, e := fixedBudgetConfig(); e != nil {
		return e
	}
	if h, e := fileHash("/srv/assets/xandbox-gateway"); e != nil || h != tlsPolicyGatewaySHA {
		return errors.New("exact gateway ELF required")
	}
	var st unix.Stat_t
	if e := unix.Fstat(3, &st); e != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("fixed gateway observer transfer socket required")
	}
	if e := quotaNotifySizes(); e != nil {
		return e
	}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); e != 0 {
		return e
	}
	p, e := tlsPolicyProgram()
	if e != nil {
		return e
	}
	prog := unix.SockFprog{Len: uint16(len(p)), Filter: &p[0]}
	flags := unix.SECCOMP_FILTER_FLAG_NEW_LISTENER | unix.SECCOMP_FILTER_FLAG_TSYNC | unix.SECCOMP_FILTER_FLAG_TSYNC_ESRCH | unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
	fd, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, uintptr(flags), uintptr(unsafe.Pointer(&prog)))
	runtime.KeepAlive(p)
	runtime.KeepAlive(&prog)
	if errno != 0 {
		return errno
	}
	if e = unix.Sendmsg(3, []byte{1}, unix.UnixRights(int(fd)), nil, 0); e != nil {
		unix.Close(int(fd))
		return e
	}
	unix.Close(int(fd))
	unix.Close(3)
	return unix.Exec("/srv/assets/xandbox-gateway", []string{"xandbox-gateway", "-config", gatewayConfig}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "GOMAXPROCS=2"})
}

type tlsPolicySnapshot struct {
	HeldID                                                           uint64
	HeldAt                                                           time.Time
	FileEntries, DirEntries, MemfdEntries, Continued, OtherWhileHeld int
	Err                                                              error
}
type tlsPolicyObserver struct {
	mu                             sync.Mutex
	once                           sync.Once
	fd, pid                        int
	identity                       string
	armed                          bool
	mode                           tlsPolicyMode
	before, next                   tlsPolicyRecord
	dirInfo, tempInfo              os.FileInfo
	tempPath, identitySHA, lockSHA string
	value                          tlsPolicySnapshot
	held, stop, done               chan struct{}
}

func (o *tlsPolicyObserver) snapshot() tlsPolicySnapshot {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.value
}
func (o *tlsPolicyObserver) fail(e error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.value.Err == nil {
		o.value.Err = e
	}
}
func (o *tlsPolicyObserver) close() error {
	o.once.Do(func() { close(o.stop) })
	select {
	case <-o.done:
		return o.snapshot().Err
	case <-time.After(2 * time.Second):
		return errors.New("gateway observer did not close")
	}
}
func tlsPolicySequence(m tlsPolicyMode, s tlsPolicySnapshot) error {
	if s.Err != nil {
		return s.Err
	}
	if !m.valid() || s.HeldID == 0 || s.HeldAt.IsZero() || s.FileEntries != 1 {
		return errors.New("gateway file entry not held in fixed sequence")
	}
	if m == tlsPolicyPre && (s.DirEntries != 0 || s.MemfdEntries != 0) {
		return errors.New("pre-file hold progressed")
	}
	if m == tlsPolicyPost && (s.DirEntries != 1 || s.MemfdEntries != 1) {
		return errors.New("post-commit checked sequence incomplete")
	}
	return nil
}
func (o *tlsPolicyObserver) arm(m tlsPolicyMode, before, next tlsPolicyRecord) error {
	if e := requireNode(); e != nil {
		return e
	}
	if !m.valid() || before.Version != 1 || next.Version != 1 || before.Revision != 1 || next.Revision != 2 || before.Digest == next.Digest || !hashPattern.MatchString(before.Digest) || !hashPattern.MatchString(next.Digest) {
		return errors.New("fixed gateway policy1 to2 required")
	}
	disk, e := tlsPolicyRead()
	if e != nil || disk != before {
		return errors.New("gateway actual baseline journal differs")
	}
	dir, e := os.Lstat(tlsPolicyRoot)
	if e != nil {
		return e
	}
	if !dir.IsDir() || dir.Mode().Perm() != 0700 {
		return errors.New("private gateway policy directory required")
	}
	id, e := fileHash(tlsPolicyRoot + "/policy.identity")
	if e != nil {
		return e
	}
	lock, e := fileHash(tlsPolicyRoot + "/gateway.lock")
	if e != nil {
		return e
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.armed || o.mode != "" || o.value.HeldID != 0 || o.value.Continued == 0 {
		return errors.New("gateway observer not at fresh ready boundary")
	}
	o.mode, o.before, o.next, o.dirInfo, o.identitySHA, o.lockSHA, o.armed = m, before, next, dir, id, lock, true
	return nil
}
func (o *tlsPolicyObserver) validID(id uint64) error {
	return quotaNotifyIO(o.fd, quotaNotifIDValid, unsafe.Pointer(&id))
}
func (o *tlsPolicyObserver) target(q quotaNotif) (bool, error) {
	if e := requireNode(); e != nil {
		return false, e
	}
	if q.ID == 0 || q.PID == 0 || q.Flags != 0 || q.Data.Arch != unix.AUDIT_ARCH_X86_64 || (q.Data.NR != int32(unix.SYS_FSYNC) && q.Data.NR != int32(unix.SYS_MEMFD_CREATE)) {
		return false, errors.New("unexpected fixed gateway notification")
	}
	if e := o.validID(q.ID); e != nil {
		return false, e
	}
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/status", q.PID))
	if e != nil {
		return false, e
	}
	tgid := 0
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "Tgid:" {
			tgid, e = strconv.Atoi(f[1])
			if e != nil {
				return false, e
			}
		}
	}
	if tgid == 0 {
		return false, errors.New("gateway notification missing TGID")
	}
	if tgid != o.pid {
		return false, nil
	}
	if start, e := processStart(o.pid); e != nil || start != o.identity {
		return false, errors.New("gateway incarnation changed")
	}
	exe, e := os.Stat(fmt.Sprintf("/proc/%d/exe", o.pid))
	if e != nil {
		return false, e
	}
	want, e := os.Stat("/srv/assets/xandbox-gateway")
	if e != nil || !os.SameFile(exe, want) {
		return false, errors.New("gateway executable inode changed")
	}
	b, e = os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", o.pid))
	if e != nil || !operatorStoreControlMember(string(b)) {
		return false, errors.New("gateway left NodeControl")
	}
	return true, nil
}
func (o *tlsPolicyObserver) anchors() error {
	dir, e := os.Lstat(tlsPolicyRoot)
	if e != nil || !os.SameFile(dir, o.dirInfo) || dir.Mode().Perm() != 0700 {
		return errors.New("gateway policy root changed")
	}
	for _, v := range []struct{ name, hash string }{{"policy.identity", o.identitySHA}, {"gateway.lock", o.lockSHA}} {
		h, e := fileHash(tlsPolicyRoot + "/" + v.name)
		if e != nil || h != v.hash {
			return errors.New("gateway policy identity or lock changed")
		}
	}
	return nil
}
func (o *tlsPolicyObserver) renamed() error {
	if _, e := os.Lstat(o.tempPath); !os.IsNotExist(e) {
		return errors.New("gateway policy temporary name survived rename")
	}
	info, e := os.Lstat(tlsPolicyRoot + "/policy.json")
	if e != nil || o.tempInfo == nil || !os.SameFile(info, o.tempInfo) {
		return errors.New("gateway policy rename changed inode")
	}
	return nil
}
func (o *tlsPolicyObserver) match(q quotaNotif) (bool, error) {
	owned, e := o.target(q)
	if e != nil || !owned {
		return false, e
	}
	if e = o.anchors(); e != nil {
		return false, e
	}
	disk, e := tlsPolicyRead()
	if e != nil {
		return false, e
	}
	if q.Data.NR == int32(unix.SYS_MEMFD_CREATE) {
		if o.mode != tlsPolicyPost || o.snapshot().FileEntries != 1 || o.snapshot().DirEntries != 1 || disk != o.next || q.Data.Args[0] == 0 || q.Data.Args[0] > math.MaxInt64 || q.Data.Args[1] != uint64(unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING) {
			return false, errors.New("post-commit policy memfd boundary differs")
		}
		if e = o.renamed(); e != nil {
			return false, e
		}
		// The name is not an authority. Read only this fixed trusted process while
		// its notification remains valid; no arbitrary RPC address/memory access.
		f, e := os.Open(fmt.Sprintf("/proc/%d/mem", o.pid))
		if e != nil {
			return false, e
		}
		defer f.Close()
		if e = o.validID(q.ID); e != nil {
			return false, e
		}
		name := make([]byte, len(tlsPolicyMemfd)+1)
		n, e := f.ReadAt(name, int64(q.Data.Args[0]))
		if e != nil || n != len(name) || !bytes.Equal(name, append([]byte(tlsPolicyMemfd), 0)) {
			return false, errors.New("fixed policy memfd name differs")
		}
		if e = o.validID(q.ID); e != nil {
			return false, e
		}
		o.mu.Lock()
		o.value.MemfdEntries++
		o.mu.Unlock()
		return true, nil
	}
	if q.Data.Args[0] > 4095 {
		return false, errors.New("gateway fsync fd exceeds fixed bound")
	}
	path := fmt.Sprintf("/proc/%d/fd/%d", o.pid, q.Data.Args[0])
	target, e := os.Readlink(path)
	if e != nil {
		return false, e
	}
	direct, e := os.Lstat(target)
	if e != nil {
		return false, e
	}
	via, e := os.Stat(path)
	st, ok := direct.Sys().(*syscall.Stat_t)
	if e != nil || !os.SameFile(direct, via) || !ok || st.Uid != 0 || st.Gid != 0 || direct.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("gateway fsync inode/owner changed")
	}
	s := o.snapshot()
	if filepath.Dir(target) == tlsPolicyRoot && tlsPolicyTemp.MatchString(filepath.Base(target)) {
		if s.FileEntries != 0 || disk != o.before || !direct.Mode().IsRegular() || direct.Mode().Perm() != 0600 || st.Nlink != 1 || direct.Size() <= 0 || direct.Size() > 4096 {
			return false, errors.New("gateway temporary policy entry differs")
		}
		b, e := privatefile.Read(target, 4096)
		if e != nil {
			return false, e
		}
		var next tlsPolicyRecord
		if strictjson.Decode(b, &next) != nil || next != o.next {
			return false, errors.New("gateway temporary policy payload differs")
		}
		o.tempPath, o.tempInfo = target, direct
		o.mu.Lock()
		o.value.FileEntries++
		o.mu.Unlock()
		return o.mode == tlsPolicyPre, nil
	}
	if target == tlsPolicyRoot && o.mode == tlsPolicyPost && s.FileEntries == 1 && s.DirEntries == 0 && disk == o.next && os.SameFile(direct, o.dirInfo) {
		if e = o.renamed(); e != nil {
			return false, e
		}
		o.mu.Lock()
		o.value.DirEntries++
		o.mu.Unlock()
		return false, nil
	}
	return false, errors.New("unexpected gateway reload fsync path/sequence")
}
func (o *tlsPolicyObserver) heldValid() error {
	if e := requireNode(); e != nil {
		return e
	}
	s := o.snapshot()
	if e := tlsPolicySequence(o.mode, s); e != nil {
		return e
	}
	if e := o.validID(s.HeldID); e != nil {
		return e
	}
	if e := o.anchors(); e != nil {
		return e
	}
	r, e := tlsPolicyRead()
	want := o.before
	if o.mode == tlsPolicyPost {
		want = o.next
	}
	if e != nil || r != want {
		return errors.New("held gateway journal namespace changed")
	}
	return nil
}
func (o *tlsPolicyObserver) invalidAfterReap() error {
	if e := requireNode(); e != nil {
		return e
	}
	if _, e := unix.FcntlInt(uintptr(o.fd), unix.F_GETFD, 0); e != nil {
		return e
	}
	if !errors.Is(o.validID(o.snapshot().HeldID), unix.ENOENT) {
		return errors.New("held gateway call not invalid after actual root reap")
	}
	return nil
}
func (o *tlsPolicyObserver) serve() {
	defer close(o.done)
	defer unix.Close(o.fd)
	for {
		select {
		case <-o.stop:
			return
		default:
		}
		s := o.snapshot()
		if s.HeldID != 0 && time.Since(s.HeldAt) > tlsPolicyHoldMax {
			o.fail(errors.New("gateway hold exceeded fixed20s"))
			return
		}
		p := []unix.PollFd{{Fd: int32(o.fd), Events: unix.POLLIN}}
		_, e := unix.Poll(p, 50)
		if errors.Is(e, unix.EINTR) {
			continue
		}
		if e != nil {
			o.fail(e)
			return
		}
		if p[0].Revents&unix.POLLIN == 0 {
			if p[0].Revents&(unix.POLLHUP|unix.POLLERR) != 0 {
				select {
				case <-o.stop:
					return
				case <-time.After(20 * time.Millisecond):
				}
			}
			continue
		}
		var q quotaNotif
		e = quotaNotifyIO(o.fd, unix.SECCOMP_IOCTL_NOTIF_RECV, unsafe.Pointer(&q))
		if errors.Is(e, unix.EINTR) || errors.Is(e, unix.ENOENT) {
			continue
		}
		if e != nil {
			o.fail(e)
			return
		}
		o.mu.Lock()
		armed := o.armed
		o.mu.Unlock()
		if armed {
			held, e := o.match(q)
			if errors.Is(e, unix.ENOENT) && errors.Is(o.validID(q.ID), unix.ENOENT) {
				continue
			}
			if e != nil {
				o.fail(e)
				return
			}
			if held {
				o.mu.Lock()
				o.armed = false
				o.value.HeldID = q.ID
				o.value.HeldAt = time.Now()
				o.mu.Unlock()
				o.held <- struct{}{}
				continue
			}
		}
		if o.snapshot().Continued >= 8192 {
			o.fail(errors.New("gateway observer continuation bound exceeded"))
			return
		}
		response := quotaNotifResponse{ID: q.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
		e = quotaNotifyIO(o.fd, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&response))
		if errors.Is(e, unix.ENOENT) {
			continue
		}
		if e != nil {
			o.fail(e)
			return
		}
		o.mu.Lock()
		o.value.Continued++
		if o.value.HeldID != 0 {
			o.value.OtherWhileHeld++
		}
		o.mu.Unlock()
	}
}
func startTLSPolicyGateway(ctx context.Context) (*gatewayProcess, *tlsPolicyObserver, error) {
	if e := requireNode(); e != nil {
		return nil, nil, e
	}
	if h, e := fileHash("/srv/assets/xandbox-gateway"); e != nil || h != tlsPolicyGatewaySHA {
		return nil, nil, errors.New("fixed gateway artifact required")
	}
	pair, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		return nil, nil, e
	}
	parent, child := os.NewFile(uintptr(pair[0]), "policy-observer"), os.NewFile(uintptr(pair[1]), "policy-transfer")
	defer parent.Close()
	defer child.Close()
	log, e := os.OpenFile(gatewayDir+"/role-policy.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, nil, e
	}
	defer log.Close()
	cg, e := os.Open(nodeGroup + "/control")
	if e != nil {
		return nil, nil, e
	}
	defer cg.Close()
	outside, e := os.Open("/srv")
	if e != nil {
		return nil, nil, e
	}
	defer outside.Close()
	cmd := exec.Command("/usr/bin/xandbox-host-fixture", "-mode", "node-tls-policy-gateway")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "GOMAXPROCS=2"}
	cmd.Stdout, cmd.Stderr = log, log
	cmd.ExtraFiles = make([]*os.File, 8)
	cmd.ExtraFiles[0], cmd.ExtraFiles[7] = child, outside
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
	if e = cmd.Start(); e != nil {
		return nil, nil, e
	}
	p := &gatewayProcess{cmd: cmd, done: make(chan struct{})}
	go func() { p.err = cmd.Wait(); close(p.done) }()
	child.Close()
	transfer, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	fd, e := receiveQuotaListener(transfer, int(parent.Fd()))
	if e != nil {
		p.kill()
		return nil, nil, e
	}
	identity, e := processStart(cmd.Process.Pid)
	if e != nil {
		unix.Close(fd)
		p.kill()
		return nil, nil, e
	}
	o := &tlsPolicyObserver{fd: fd, pid: cmd.Process.Pid, identity: identity, held: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	go o.serve()
	return p, o, nil
}
