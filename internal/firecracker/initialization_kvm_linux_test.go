//go:build linux

package firecracker

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/123123213weqw/Xandbox/internal/guestbridge"
	"github.com/123123213weqw/Xandbox/internal/guestinit"
	"github.com/123123213weqw/Xandbox/internal/guestwire"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

type initializationFixture struct {
	StateDir, ConfigPath, RefPath, BarrierPath, ResultPath, SourceRevision, Mode, CreateKey string
}

// A TEST-ONLY bridge replaces the pathname after the real ownership fsync, when
// waitPristine has already finished and before NewRequest/Initialize. Production
// constructors, Prepare and Initialize are unmodified. The real Firecracker
// listener inode is renamed, not replaced by a fake guest or host executor.
type initializationFaultBridge struct {
	listener                          *net.UnixListener
	realSocket, mode, barrier         string
	ref                               sandbox.Ref
	ctx                               context.Context
	cancel                            context.CancelFunc
	wg                                sync.WaitGroup
	initializeRequests, sealedReplies atomic.Int64
	mu                                sync.Mutex
	hash, bootID                      string
	barrierOnce                       sync.Once
	failure                           error
}

func (p *initializationFaultBridge) fail(e error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failure == nil {
		p.failure = e
	}
}
func (p *initializationFaultBridge) err() error { p.mu.Lock(); defer p.mu.Unlock(); return p.failure }
func (p *initializationFaultBridge) close() {
	p.cancel()
	p.listener.Close()
	p.wg.Wait()
}
func newInitializationFaultBridge(socket, mode, barrier string, ref sandbox.Ref) (*initializationFaultBridge, error) {
	real := filepath.Join(filepath.Dir(socket), "o.sock")
	if _, e := os.Lstat(real); !os.IsNotExist(e) {
		return nil, errors.New("fault relay destination already exists")
	}
	if e := os.Rename(socket, real); e != nil {
		return nil, e
	}
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if e != nil {
		return nil, e
	}
	l.SetUnlinkOnClose(false)
	ctx, cancel := context.WithCancel(context.Background())
	p := &initializationFaultBridge{listener: l, realSocket: real, mode: mode, barrier: barrier, ref: ref, ctx: ctx, cancel: cancel}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			c, e := l.AcceptUnix()
			if e != nil {
				return
			}
			p.wg.Add(1)
			go func() { defer p.wg.Done(); p.serve(c) }()
		}
	}()
	return p, nil
}
func (p *initializationFaultBridge) serve(client *net.UnixConn) {
	defer client.Close()
	upstream, e := net.DialTimeout("unix", p.realSocket, time.Second)
	if e != nil {
		return
	} // A resumed port may still be entering/leaving service.
	defer upstream.Close()
	stop := context.AfterFunc(p.ctx, func() { client.Close(); upstream.Close() })
	defer stop()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_ = upstream.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReaderSize(client, 64)
	remote := bufio.NewReaderSize(upstream, 64)
	line, e := reader.ReadSlice('\n')
	if e != nil || len(line) > 32 {
		return
	}
	bootstrap := string(line) == "CONNECT 901\n"
	if !bootstrap && string(line) != "CONNECT 900\n" {
		p.fail(errors.New("unexpected relay port"))
		return
	}
	if _, e = upstream.Write(line); e != nil {
		return
	}
	ack, e := remote.ReadSlice('\n')
	if e != nil {
		return
	}
	if _, e = client.Write(ack); e != nil {
		return
	}
	if bootstrap {
		var req guestinit.Request
		if e = guestwire.Read(reader, guestinit.MaxRequest, &req); e != nil {
			return
		}
		defer req.WipeEntropy()
		if !req.Valid() || req.Operation != "initialize" || req.Ref != p.ref {
			p.fail(errors.New("unexpected bootstrap request"))
			return
		}
		p.initializeRequests.Add(1)
		p.mu.Lock()
		p.hash, p.bootID = req.Digest(), req.BootID
		p.mu.Unlock()
		if e = guestwire.Write(upstream, guestinit.MaxRequest, req); e != nil {
			return
		}
		var out guestinit.Response
		if e = guestwire.Read(remote, guestinit.MaxResponse, &out); e != nil {
			return
		}
		if !out.Valid() || out.Phase != guestinit.Claimed || out.Digest != req.Digest() {
			p.fail(errors.New("real guest did not claim exact request"))
			return
		}
		if p.mode == "drop_claim_ack" {
			return
		}
		_ = guestwire.Write(client, guestinit.MaxResponse, out)
		return
	}
	var req guestwire.Request
	if e = guestwire.Read(reader, guestwire.MaxRequest, &req); e != nil {
		return
	}
	if !req.Valid() || req.Ref != p.ref {
		p.fail(errors.New("unexpected normal request"))
		return
	}
	if e = guestwire.Write(upstream, guestwire.MaxRequest, req); e != nil {
		return
	}
	var out guestwire.Response
	if e = guestwire.Read(remote, guestwire.MaxResponse, &out); e != nil {
		return
	}
	if req.Operation == "health" {
		p.mu.Lock()
		hash, boot := p.hash, p.bootID
		p.mu.Unlock()
		if out.Status != "READY" || out.Ref != p.ref || out.InitializationHash != hash || hash == "" || out.BootID != boot || out.ActiveGroups == nil || *out.ActiveGroups != 0 {
			p.fail(errors.New("real guest health was not exact sealed empty epoch"))
			return
		}
		p.sealedReplies.Add(1)
		switch p.mode {
		case "after_sealed_before_ready":
			p.barrierOnce.Do(func() {
				p.failIf(durableJSON(p.barrier, map[string]any{"phase": "after_sealed_before_ready", "ref": p.ref, "guest_sealed_confirmed": true}))
			})
			<-p.ctx.Done()
			return // No valid health response reaches the production client.
		case "drop_health_ack":
			return
		case "wrong_health_epoch":
			if out.InitializationHash[0] == '0' {
				out.InitializationHash = "1" + out.InitializationHash[1:]
			} else {
				out.InitializationHash = "0" + out.InitializationHash[1:]
			}
		}
	}
	_ = guestwire.Write(client, guestwire.MaxResponse, out)
}
func (p *initializationFaultBridge) failIf(e error) {
	if e != nil {
		p.fail(e)
	}
}

// The external root harness is the parent of this process and is solely allowed
// to SIGKILL it at the private barrier. No PID lookup/reuse or global kill is used.
func TestKVMInitializationFault(t *testing.T) {
	if os.Getenv("XANDBOX_KVM_INITIALIZATION") != "1" {
		t.Skip("explicit isolated root fixture required; skip is not KVM acceptance")
	}
	if os.Geteuid() != 0 || runtime.GOARCH != "amd64" || runtime.Version() != "go1.27.3" {
		t.Fatal("requires root Linux amd64 Go1.27.3")
	}
	raw, e := privatefile.Read(os.Getenv("XANDBOX_KVM_INITIALIZATION_FIXTURE"), 16384)
	if e != nil {
		t.Fatal(e)
	}
	var f initializationFixture
	if e = strictjson.Decode(raw, &f); e != nil {
		t.Fatal(e)
	}
	rev, e := hex.DecodeString(f.SourceRevision)
	if e != nil || len(rev) != 20 || len(f.CreateKey) != 32 {
		t.Fatal("invalid fixture source/key")
	}
	for _, path := range []string{f.StateDir, f.ConfigPath, f.RefPath, f.BarrierPath, f.ResultPath} {
		if !cleanAbsolute(path) {
			t.Fatal("noncanonical fixture")
		}
	}
	for _, path := range []string{f.RefPath, f.BarrierPath, f.ResultPath} {
		if _, e = os.Lstat(path); !os.IsNotExist(e) {
			t.Fatal("refuse fixture output overwrite")
		}
	}
	switch f.Mode {
	case "before_initialize", "after_sealed_before_ready", "drop_claim_ack", "drop_health_ack", "wrong_health_epoch":
	default:
		t.Fatal("unknown fault mode")
	}
	lock, e := os.OpenFile(filepath.Join(f.StateDir, "controller.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		t.Fatal(e)
	}
	store, e := sandbox.NewFileStore(filepath.Join(f.StateDir, "ledger"))
	if e != nil {
		t.Fatal(e)
	}
	records, e := store.Load()
	if e != nil {
		t.Fatal(e)
	}
	rawDriver, e := New(f.StateDir, f.ConfigPath, records)
	if e != nil {
		t.Fatal(e)
	}
	real := rawDriver.(*driver)
	if real.cfg.Snapshot == nil {
		t.Fatal("snapshot mode required")
	}
	var proxy *initializationFaultBridge
	defer func() {
		if proxy != nil {
			proxy.close()
		}
	}()
	persist := real.registry.persist
	real.registry.persist = func(path string, value any) error {
		if e := persist(path, value); e != nil {
			return e
		} // Real file and directory fsync first.
		o, ok := value.(ownership)
		if !ok || !o.InitializationAttempted {
			return nil
		}
		if e := durableJSON(f.RefPath, map[string]any{"ref": o.Ref}); e != nil {
			return e
		}
		k, _ := key(o.Ref)
		_, jail := real.paths(k)
		socket := filepath.Join(jail, "root/v.sock")
		if f.Mode == "before_initialize" {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			state, e := guestbridge.Bootstrap(ctx, socket, guestinit.Request{Version: 1, Operation: "state"})
			if e != nil || state.Phase != guestinit.Waiting {
				return errors.New("pre-send real guest was not WAITING")
			}
			if _, e = guestbridge.Call(ctx, socket, guestwire.Request{Version: 1, Operation: "health", Ref: o.Ref}); e == nil {
				return errors.New("uninitialized guest allowed normal health")
			}
			if e = durableJSON(f.BarrierPath, map[string]any{"phase": "before_initialize", "ref": o.Ref, "guest_waiting_confirmed": true}); e != nil {
				return e
			}
			time.Sleep(20 * time.Second) // Parent must kill at the barrier, not await this fallback.
			return errors.New("parent did not kill pre-initialize child")
		}
		var e error
		proxy, e = newInitializationFaultBridge(socket, f.Mode, f.BarrierPath, o.Ref)
		return e
	}
	manager, e := sandbox.NewManager(store, real, sandbox.Options{MaxInstances: 4, PrepareTimeout: 12 * time.Second, StopTimeout: 5 * time.Second, CleanupTimeout: 10 * time.Second, ReapInterval: 10 * time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	closed := false
	defer func() {
		if !closed {
			ctx, c := context.WithTimeout(context.Background(), 15*time.Second)
			defer c()
			if e := manager.Close(ctx); e != nil {
				t.Error("owned cleanup unfinished", e)
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	request := sandbox.CreateRequest{TTLMS: 120000, Limits: sandbox.Limits{MaxExecMS: 5000, MaxOutputBytes: 16384, MaxJobs: 64}}
	record, createError := manager.CreateScoped(ctx, sandbox.Owner{TenantID: "local", MaxInstances: 4}, f.CreateKey, request)
	if f.Mode == "before_initialize" || f.Mode == "after_sealed_before_ready" {
		t.Fatal("crash mode returned without parent SIGKILL")
	}
	if proxy == nil || proxy.err() != nil {
		t.Fatal("fault relay failed; inspect private fixture", proxy)
	}
	if proxy.initializeRequests.Load() != 1 || proxy.sealedReplies.Load() < 1 {
		t.Fatal("fault did not observe one initialization and actual sealed guest")
	}
	positive := f.Mode == "drop_claim_ack"
	if positive {
		if createError != nil || record.State != sandbox.Ready {
			t.Fatal("lost CLAIMED ack prevented exact health recovery", createError)
		}
		job, e := manager.Exec(record.ID, sandbox.ExecRequest{Generation: record.Generation, Argv: []string{"id", "-u"}, TimeoutMS: 5000})
		if e != nil {
			t.Fatal(e)
		}
		deadline := time.Now().Add(6 * time.Second)
		for {
			job, e = manager.GetJob(record.ID, job.ID)
			if e != nil {
				t.Fatal(e)
			}
			if job.Status != "RUNNING" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("guest job timeout")
			}
			time.Sleep(5 * time.Millisecond)
		}
		if job.Status != "EXITED" || job.Output.ExitCode != 0 || strings.TrimSpace(job.Output.Stdout) != "65534" {
			t.Fatal("admitted execution not actual unprivileged guest")
		}
	} else {
		if createError == nil || record.State == sandbox.Ready {
			t.Fatal("uncertain/mismatched normal health admitted READY")
		}
		if _, e := manager.Exec(record.ID, sandbox.ExecRequest{Generation: record.Generation, Argv: []string{"true"}, TimeoutMS: 5000}); e == nil {
			t.Fatal("fenced candidate allowed execution")
		}
	}
	if _, e = manager.Destroy(record.Ref); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		r, e := manager.Get(record.ID)
		if e != nil {
			t.Fatal(e)
		}
		if r.State == sandbox.Destroyed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("durable cleanup timeout")
		}
		time.Sleep(5 * time.Millisecond)
	}
	k, _ := key(record.Ref)
	group, jail := real.paths(k)
	for _, path := range []string{group, jail, filepath.Join(real.registry.dir, k+".json")} {
		if _, e = os.Lstat(path); !os.IsNotExist(e) {
			t.Fatal("resource remains after DESTROYED")
		}
	}
	closeCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
	e = manager.Close(closeCtx)
	c()
	if e != nil {
		t.Fatal(e)
	}
	closed = true
	report := map[string]any{"test": "experimental_real_kvm_initialization_fault_child", "mode": f.Mode, "source_revision": f.SourceRevision, "toolchain": runtime.Version(), "production_ready": false, "initialize_requests": proxy.initializeRequests.Load(), "actual_sealed_health_replies_observed": proxy.sealedReplies.Load(), "create_returned_ready": positive, "fenced_candidate_reclaimed": true, "passed": true}
	if e = durableJSON(f.ResultPath, report); e != nil {
		t.Fatal(e)
	}
}

// Guard against accidentally moving the injection ahead of the durable owner
// write or making it a production option. The hardware case additionally checks
// the real owner, ledger, KVM fd and recovery from an ordinary sandboxd binary.
func TestInitializationFaultFixtureJSONIsPrivateOnly(t *testing.T) {
	f := initializationFixture{Mode: "before_initialize", CreateKey: strings.Repeat("a", 32)}
	b, e := json.Marshal(f)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(b), "seed") || strings.Contains(string(b), "nonce") {
		t.Fatal("secret-bearing fault fixture")
	}
	if fmt.Sprint(guestinit.Port) != "901" || guestwire.Port != 900 {
		t.Fatal("update explicit bounded fault relay protocol")
	}
}

// Synthetic framed UDS only; ordinary CI exercises the fault relay itself, not
// real guest/KVM admission. The opt-in root test above supplies that evidence.
func TestInitializationFaultRelayModesSyntheticOnly(t *testing.T) {
	for _, mode := range []string{"drop_claim_ack", "drop_health_ack", "wrong_health_epoch", "after_sealed_before_ready"} {
		t.Run(mode, func(t *testing.T) {
			root, e := os.MkdirTemp("/tmp", "xif")
			if e != nil {
				t.Fatal(e)
			}
			defer os.RemoveAll(root)
			socket := filepath.Join(root, "v.sock")
			l, e := net.Listen("unix", socket)
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			req, e := guestinit.NewRequest(reference("1"))
			if e != nil {
				t.Fatal(e)
			}
			defer req.WipeEntropy()
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					c, e := l.Accept()
					if e != nil {
						return
					}
					go func() {
						defer c.Close()
						_ = c.SetDeadline(time.Now().Add(time.Second))
						r := bufio.NewReader(c)
						line, e := r.ReadString('\n')
						if e != nil {
							return
						}
						_, _ = c.Write([]byte("OK 42\n"))
						if line == "CONNECT 901\n" {
							var in guestinit.Request
							if guestwire.Read(r, guestinit.MaxRequest, &in) != nil {
								return
							}
							defer in.WipeEntropy()
							_ = guestwire.Write(c, guestinit.MaxResponse, guestinit.Response{Version: 1, Phase: guestinit.Claimed, Digest: in.Digest()})
							return
						}
						var in guestwire.Request
						if guestwire.Read(r, guestwire.MaxRequest, &in) != nil {
							return
						}
						groups := 0
						_ = guestwire.Write(c, guestwire.MaxResponse, guestwire.Response{Version: 1, Ref: in.Ref, Status: "READY", BootID: req.BootID, InitializationHash: req.Digest(), ActiveGroups: &groups})
					}()
				}
			}()
			proxy, e := newInitializationFaultBridge(socket, mode, filepath.Join(root, "barrier.json"), req.Ref)
			if e != nil {
				t.Fatal(e)
			}
			defer proxy.close()
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			_, e = guestbridge.Initialize(ctx, socket, req)
			if (e == nil) != (mode == "drop_claim_ack") {
				t.Fatal("wrong relay fault outcome", e)
			}
			if proxy.err() != nil || proxy.initializeRequests.Load() != 1 || proxy.sealedReplies.Load() < 1 {
				t.Fatal("relay evidence incomplete")
			}
			if mode == "after_sealed_before_ready" {
				b, e := os.ReadFile(filepath.Join(root, "barrier.json"))
				if e != nil {
					t.Fatal(e)
				}
				var v map[string]any
				if json.Unmarshal(b, &v) != nil || v["phase"] != mode {
					t.Fatal("post-sealed barrier missing")
				}
			}
			proxy.close()
			l.Close()
			<-done
		})
	}
}
