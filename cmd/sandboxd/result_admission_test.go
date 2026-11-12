package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/diagnostics"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func TestResultAdmissionExplicitNormalization(t *testing.T) {
	for _, kind := range []string{"disabled", "small-default", "large-default", "explicit"} {
		t.Run(kind, func(t *testing.T) {
			var bytes, tenant int64
			var records int
			want := sandbox.ResultLimits{}
			switch kind {
			case "small-default":
				bytes = 1 << 20
				want = sandbox.ResultLimits{Bytes: 1 << 20, TenantBytes: 1 << 20, Records: 4096}
			case "large-default":
				bytes = 64 << 20
				want = sandbox.ResultLimits{Bytes: 64 << 20, TenantBytes: 16 << 20, Records: 4096}
			case "explicit":
				bytes, tenant, records = 1<<20, 1<<19, 100
				want = sandbox.ResultLimits{Bytes: 1 << 20, TenantBytes: 1 << 19, Records: 100}
			}
			if got := requestedResultLimits(bytes, tenant, records); got != want {
				t.Fatal("opt-in defaults differ from actual opening branch")
			}
		})
	}
}

func TestResultAdmissionFirecrackerRefusesBeforeAuthAndStateCreation(t *testing.T) {
	for _, kind := range []string{"missing-config", "bad-config", "legacy-no-reservation"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			cfg, state := filepath.Join(base, "backend.json"), filepath.Join(base, "STATE_MUST_NOT_EXIST")
			if kind == "bad-config" {
				if e := os.WriteFile(cfg, []byte("{}"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if kind == "legacy-no-reservation" {
				asset := func(name string) firecracker.Asset {
					return firecracker.Asset{Path: "/TEST-NOT-OPENED/" + name, SHA256: strings.Repeat("a", 64)}
				}
				c := firecracker.Config{Version: 1, RuntimeRoot: "/srv/test", CgroupRoot: "/sys/fs/cgroup/test", UIDStart: 65536, UIDCount: 1, ReservedUIDRange: true, Firecracker: asset("firecracker"), Jailer: asset("jailer"), Warden: asset("warden"), Kernel: asset("kernel"), Initrd: asset("initrd"), Workspace: asset("workspace")}
				raw, e := json.Marshal(c)
				if e != nil {
					t.Fatal(e)
				}
				if _, e := firecracker.DecodeInspectionConfig(raw); e != nil {
					t.Fatal("legacy structural fixture invalid", e)
				}
				if e := os.WriteFile(cfg, raw, 0600); e != nil {
					t.Fatal(e)
				}
			}
			e := runArgs([]string{"-backend", "firecracker", "-firecracker-config", cfg, "-auth-file", filepath.Join(base, "AUTH_MUST_NOT_BE_READ"), "-state-dir", state, "-result-bytes", "1048576", "-result-tenant-bytes", "524288", "-result-records", "100"})
			var failure *bootstrapFailure
			if !errors.As(e, &failure) || failure.reason != diagnostics.NodeAdmission {
				t.Fatal("unreserved retention reached auth/backend bootstrap", e)
			}
			if _, e := os.Lstat(state); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("unreserved retention created state/result/lock files")
			}
		})
	}
}
