//go:build linux && xandbox_host_fixture

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"syscall"

	"github.com/123123213weqw/Xandbox/internal/access"
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
	"golang.org/x/sys/unix"
)

var nodeLoadTenants = [2]string{"load-alpha", "load-beta"}

func nodeLoadPolicy() firecracker.NodePolicy {
	p := budgetPolicy()
	// A NEW named workload profile, not a silently enlarged node-budget case.
	// Production reservation formula needs3654MiB for10k records/512sessions/N4.
	p.MaxRecords = 10000
	p.MaxSessions = 512
	p.ControllerMemoryMax = 3840 << 20
	return p
}

func fixedNodeLoadConfig() (firecracker.Config, error) {
	var c firecracker.Config
	b, e := privatefile.Read("/srv/config/backend.json", 16384)
	if e != nil {
		return c, e
	}
	if e = strictjson.Decode(b, &c); e != nil {
		return c, e
	}
	if c.Version != 3 || c.RuntimeRoot != "/srv/r" || c.CgroupRoot != nodeBudgetInstances || c.UIDStart != 400000 || c.UIDCount != 4 || !c.ReservedUIDRange || c.Snapshot != nil || c.Quota == nil || c.Quota.ProjectStart != driverProjectFirst || c.Quota.MaxBytes != 192<<20 || c.Quota.MaxInodes != 128 || c.IO == nil || c.IO.Version != 1 || c.IO.BytesPerSecond != 16<<20 || c.IO.OperationsPerSecond != 1024 || c.Node == nil || *c.Node != nodeLoadPolicy() {
		return c, errors.New("fixed complete open-arrival policy required")
	}
	return c, nil
}

func (n *node) initializeNodeLoad() error {
	if e := requireNode(); e != nil {
		return e
	}
	if !n.nodeLoad || !n.nodeBudget || !n.quotaDriver || n.nodeSnapshot || n.quotaSwitch || n.quotaSnapshot || n.mapper != nil {
		return errors.New("exclusive new node-load profile required")
	}
	c, e := fixedNodeLoadConfig()
	if e != nil {
		return e
	}
	return n.initializeBudgetCgroups(c)
}

func (n *node) initializeNodeLoadAuth() error {
	if e := requireNode(); e != nil {
		return e
	}
	if !n.nodeLoad || !hashPattern.MatchString(n.token) {
		return errors.New("fixed load identity required")
	}
	b, e := privatefile.Read("/srv/fixture/load-token-b", 1024)
	if os.IsNotExist(e) {
		n.loadTokenB, e = randomKey()
		if e != nil {
			return e
		}
		if e = privateWrite("/srv/fixture/load-token-b", n.loadTokenB); e != nil {
			return e
		}
	} else if e != nil {
		return e
	} else if e = json.Unmarshal(b, &n.loadTokenB); e != nil {
		return e
	}
	if !hashPattern.MatchString(n.loadTokenB) || n.loadTokenB == n.token {
		return errors.New("independent fixed load credentials required")
	}
	want := access.Config{Version: 1}
	for i, token := range []string{n.token, n.loadTokenB} {
		digest := sha256.Sum256([]byte(token))
		want.Keys = append(want.Keys, access.Key{TenantID: nodeLoadTenants[i], MaxInstances: 3, TokenSHA256: hex.EncodeToString(digest[:])})
	}
	if _, e = access.New(want); e != nil {
		return e
	}
	b, e = privatefile.Read("/srv/config/auth.json", 65536)
	if os.IsNotExist(e) {
		return privateWrite("/srv/config/auth.json", want)
	}
	if e != nil {
		return e
	}
	var got access.Config
	if e = strictjson.Decode(b, &got); e != nil {
		return e
	}
	x, _ := json.Marshal(got)
	y, _ := json.Marshal(want)
	if !bytes.Equal(x, y) {
		return errors.New("load authentication policy changed across boot")
	}
	return nil
}

func runNodeLoadDaemon() error {
	if e := requireQuotaChild(); e != nil {
		return e
	}
	if _, e := fixedNodeLoadConfig(); e != nil {
		return e
	}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, unix.CAP_SYS_RESOURCE, 0); e != 0 {
		return e
	}
	return unix.Exec("/srv/assets/sandboxd", []string{"sandboxd", "-backend", "firecracker", "-state-dir", "/srv/state", "-auth-file", "/srv/config/auth.json", "-firecracker-config", "/srv/config/backend.json", "-max-instances", "4", "-max-records", "10000", "-max-tenant-records", "5000", "-max-sessions", "512", "-max-tenant-sessions", "256", "-session-history", "64", "-metrics"}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"})
}
