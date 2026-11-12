package firecracker

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

func resultsPolicyConfig() Config {
	c := nodeTestConfig() // Pure owned policy values; no constructor or host probe.
	c.Version = 4
	c.Results = &ResultPolicy{Version: 1, Bytes: 1 << 20, TenantBytes: 1 << 19, Records: 100}
	return c
}

func TestInspectionResultsImmutableReservationAllDimensions(t *testing.T) {
	for _, kind := range []string{"valid", "v3-with-results", "v4-without-results", "result-version", "negative-bytes", "tenant-over", "records-zero", "bytes-over", "records-over", "node-missing", "quota-missing", "io-missing", "controller-under", "disk-under", "inode-under", "no-auto-expansion"} {
		t.Run(kind, func(t *testing.T) {
			c := resultsPolicyConfig()
			old := nodeTestConfig()
			before, e := old.Node.validate(old)
			if e != nil {
				t.Fatal(e)
			}
			after, e := c.Node.validate(c)
			if e != nil || after.ControllerMemory-before.ControllerMemory != (4<<20)+100*(16<<10) || after.ManagedDisk-before.ManagedDisk != (256<<10)+2*(1<<20)+100*2*(64<<10) || after.ManagedInodes-before.ManagedInodes != 204 || after.RequiredDisk-before.RequiredDisk != 2*(after.ManagedDisk-before.ManagedDisk) || after.FreeDiskGuard-before.FreeDiskGuard != after.ManagedDisk-before.ManagedDisk {
				t.Fatal("logical results omitted from immutable reservation", e)
			}
			switch kind {
			case "v3-with-results":
				c.Version = 3
			case "v4-without-results":
				c.Results = nil
			case "result-version":
				c.Results.Version++
			case "negative-bytes":
				c.Results.Bytes = -1
			case "tenant-over":
				c.Results.TenantBytes = c.Results.Bytes + 1
			case "records-zero":
				c.Results.Records = 0
			case "bytes-over":
				c.Results.Bytes = sandbox.MaxResultBytes + 1
			case "records-over":
				c.Results.Records = sandbox.MaxResultRecords + 1
			case "node-missing":
				c.Node = nil
			case "quota-missing":
				c.Quota = nil
			case "io-missing":
				c.IO = nil
			case "controller-under":
				c.Node.ControllerMemoryMax = after.ControllerMemory - 1
			case "disk-under":
				c.Node.DiskBytes = after.RequiredDisk - 1
			case "inode-under":
				c.Node.DiskInodes = after.RequiredInodes - 1
			}
			raw, e := json.Marshal(c)
			if e != nil {
				t.Fatal(e)
			}
			e = c.validate()
			if (e == nil) != (kind == "valid" || kind == "no-auto-expansion") {
				t.Fatal("complete results/node policy mismatch", e)
			}
			current, _ := json.Marshal(c)
			if !bytes.Equal(current, raw) {
				t.Fatal("validator enlarged or rewrote operator envelope")
			}
			legacy, _ := json.Marshal(old)
			if bytes.Contains(legacy, []byte(`"results"`)) || old.validate() != nil {
				t.Fatal("legacy policy bytes or disabled behavior changed")
			}
		})
	}
}

func TestInspectionResultsConfigPreflightMatchesExactLimitsReadOnly(t *testing.T) {
	for _, kind := range []string{"matched", "bytes", "tenant", "records", "disabled", "legacy-disabled", "legacy-enabled", "unknown-field", "null-policy", "duplicate-field", "trailing"} {
		t.Run(kind, func(t *testing.T) {
			c := resultsPolicyConfig()
			l := c.Results.Limits()
			switch kind {
			case "bytes":
				l.Bytes--
			case "tenant":
				l.TenantBytes--
			case "records":
				l.Records--
			case "disabled":
				l = sandbox.ResultLimits{}
			case "legacy-disabled", "legacy-enabled":
				c = nodeTestConfig()
				if kind == "legacy-disabled" {
					l = sandbox.ResultLimits{}
				}
			case "null-policy":
				c.Results = nil
			}
			raw, e := json.Marshal(c)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "unknown-field":
				raw = append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...)
			case "duplicate-field":
				raw = append(raw[:len(raw)-1], []byte(`,"version":4}`)...)
			case "trailing":
				raw = append(raw, []byte("\n{}")...)
			}
			path := filepath.Join(t.TempDir(), "policy.json")
			if e = os.WriteFile(path, raw, 0600); e != nil {
				t.Fatal(e)
			}
			e = ValidateResultAdmissionConfig(path, l)
			if (e == nil) != (kind == "matched" || kind == "legacy-disabled") {
				t.Fatal("preflight adopted unbound result limits", e)
			}
			after, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(raw, after) {
				t.Fatal("read-only preflight repaired policy")
			}
		})
	}
}
