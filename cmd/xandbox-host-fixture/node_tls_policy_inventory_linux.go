//go:build linux && xandbox_host_fixture

package main

// TEST ONLY readback of an actually interrupted production temp. Negative
// probes add/remove only their own non-authoritative debris, never a journal.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/123123213weqw/Xandbox/internal/gateway"
	"github.com/123123213weqw/Xandbox/internal/privatefile"
	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

type tlsPolicyOrphan struct {
	Name, SHA string
	Bytes     int64
}

func (v tlsPolicyOrphan) valid(m tlsPolicyMode) bool {
	if m == tlsPolicyPost {
		return v == (tlsPolicyOrphan{})
	}
	return m == tlsPolicyPre && len(v.Name) <= len(".policy-")+20 && tlsPolicyTemp.MatchString(v.Name) && filepath.Base(v.Name) == v.Name && hashPattern.MatchString(v.SHA) && v.Bytes > 0 && v.Bytes <= 1024
}
func captureTLSPolicyOrphan(o *tlsPolicyObserver) (tlsPolicyOrphan, error) {
	var zero tlsPolicyOrphan
	if e := requireNode(); e != nil {
		return zero, e
	}
	if o.mode == tlsPolicyPost {
		return zero, nil
	}
	if o.mode != tlsPolicyPre || o.tempInfo == nil || filepath.Dir(o.tempPath) != tlsPolicyRoot {
		return zero, errors.New("fixed held policy temporary inode required")
	}
	info, e := os.Lstat(o.tempPath)
	if e != nil || !os.SameFile(info, o.tempInfo) {
		return zero, errors.New("held policy inode not preserved as actual orphan")
	}
	b, e := privatefile.Read(o.tempPath, 1024)
	if e != nil {
		return zero, e
	}
	var r tlsPolicyRecord
	if strictjson.Decode(b, &r) != nil || r != o.next {
		return zero, errors.New("actual orphan is not the held production record")
	}
	v := tlsPolicyOrphan{Name: filepath.Base(o.tempPath), SHA: gatewayHashToken(string(b)), Bytes: int64(len(b))}
	if !v.valid(o.mode) {
		return zero, errors.New("invalid captured production orphan")
	}
	return v, nil
}

// Returns a PRIVATE canonical inventory hash, never names/inodes in reports.
func tlsPolicyInventory(v tlsPolicyOrphan, expectedOrphan bool, probe int) (string, error) {
	if e := requireNode(); e != nil {
		return "", e
	}
	if probe < 0 || probe > 2 || (expectedOrphan && !v.valid(tlsPolicyPre)) {
		return "", errors.New("fixed policy inventory required")
	}
	dir, e := os.Open(tlsPolicyRoot)
	if e != nil {
		return "", e
	}
	defer dir.Close()
	names, e := dir.Readdirnames(12)
	if e != nil && !errors.Is(e, io.EOF) {
		return "", e
	}
	expected := map[string]int{"gateway.lock": 0, "policy.identity": 1024, "policy.json": 4096}
	if expectedOrphan {
		expected[v.Name] = 1024
	}
	if probe == 1 {
		expected["foreign-gateway-probe"] = 1024
	}
	if probe == 2 {
		expected[".policy-00000000000000000000"] = -1
	}
	if len(names) != len(expected) {
		return "", errors.New("policy inventory has missing or unknown entry")
	}
	sort.Strings(names)
	type item struct {
		Name, Hash string
		Mode       uint32
		Inode      uint64
		Bytes      int64
	}
	items := make([]item, 0, len(names))
	for _, name := range names {
		max, ok := expected[name]
		if !ok {
			return "", errors.New("unexpected policy inventory name")
		}
		path := tlsPolicyRoot + "/" + name
		info, e := os.Lstat(path)
		if e != nil {
			return "", e
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return "", errors.New("unexpected policy inventory ownership")
		}
		hash := ""
		if max < 0 {
			target, e := os.Readlink(path)
			if e != nil || target != "policy.json" || info.Mode()&os.ModeSymlink == 0 {
				return "", errors.New("own symlink probe changed")
			}
			hash = gatewayHashToken(target)
		} else {
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Nlink != 1 || info.Size() > int64(max) {
				return "", errors.New("policy inventory attributes differ")
			}
			b, e := privatefile.Read(path, int64(max))
			if e != nil {
				return "", e
			}
			hash = gatewayHashToken(string(b))
			if expectedOrphan && name == v.Name && (hash != v.SHA || info.Size() != v.Bytes) {
				return "", errors.New("actual orphan payload changed across cold")
			}
		}
		items = append(items, item{name, hash, st.Mode, st.Ino, info.Size()})
	}
	b, e := json.Marshal(items)
	if e != nil {
		return "", e
	}
	return gatewayHashToken(string(b)), nil
}
func tlsPolicyDirSync() error {
	if e := requireNode(); e != nil {
		return e
	}
	d, e := os.Open(tlsPolicyRoot)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func tlsPolicyColdRefusalProbes(ctx context.Context, s tlsPolicySaved, current gateway.Config) error {
	if e := requireNode(); e != nil {
		return e
	}
	if s.Mode != tlsPolicyPre || !s.Orphan.valid(s.Mode) {
		return errors.New("fixed actual orphan refusal probes required")
	}
	for label := 1; label <= 3; label++ {
		probe := label
		if probe == 3 {
			probe = 0
		}
		path := ""
		var owned os.FileInfo
		switch label {
		case 1:
			path = tlsPolicyRoot + "/foreign-gateway-probe"
			f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
			if e != nil {
				return e
			}
			_, e = f.Write([]byte("Xandbox own non-authoritative inventory probe\n"))
			if e == nil {
				e = f.Sync()
			}
			ce := f.Close()
			if e != nil {
				return e
			}
			if ce != nil {
				return ce
			}
		case 2:
			path = tlsPolicyRoot + "/.policy-00000000000000000000"
			if e := os.Symlink("policy.json", path); e != nil {
				return e
			}
		case 3:
			invalid := current
			invalid.PolicyRevision = 3
			if e := privateWrite(gatewayConfig, invalid); e != nil {
				return e
			}
		}
		if path != "" {
			var e error
			owned, e = os.Lstat(path)
			if e != nil {
				return e
			}
			if e = tlsPolicyDirSync(); e != nil {
				return e
			}
		}
		before, e := tlsPolicyInventory(s.Orphan, true, probe)
		if e != nil {
			return e
		}
		p, e := startGateway(ctx, label)
		if e != nil {
			return e
		}
		e = p.wait(ctx, 1)
		if e != nil {
			p.kill()
			return e
		}
		if e = gatewayGone(p); e != nil {
			return e
		}
		if e = gatewayAbsentListener(); e != nil {
			return e
		}
		log, e := privatefile.Read(fmt.Sprintf(gatewayDir+"/role-%d.log", label), 1024)
		if e != nil || string(log) != "gateway unavailable; ingress closed (POLICY_STATE)\n" {
			return errors.New("inventory probe did not fail at policy-state boundary")
		}
		after, e := tlsPolicyInventory(s.Orphan, true, probe)
		if e != nil || before != after {
			return errors.New("refused policy input mutated real orphan or authority")
		}
		if path != "" {
			now, e := os.Lstat(path)
			if e != nil || !os.SameFile(owned, now) {
				return errors.New("own probe inode changed before removal")
			}
			if e = os.Remove(path); e != nil {
				return e
			}
			if e = tlsPolicyDirSync(); e != nil {
				return e
			}
		} else {
			if e = privateWrite(gatewayConfig, current); e != nil {
				return e
			}
		}
	}
	return nil
}
