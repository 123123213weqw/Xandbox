//go:build linux

package installtxn

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// Exact2792b89 file-list validator, retained as a differential oracle.
func originalFileList2792(t transaction) bool {
	if t.Version != 1 || t.Revision != 1 || !requestPattern.MatchString(t.RequestID) {
		return false
	}
	p, e := originalDecodePlan2792(encode(t.Plan))
	if e != nil || !bytes.Equal(encode(p), encode(t.Plan)) {
		return false
	}
	expected := map[string]uint32{SelfPath: 0555, childRoot + "/gateway": 0555, UnitDir + "/" + MainUnit: 0600, UnitDir + "/" + IngressUnit: 0600}
	for _, name := range configNamesFor(p.Version) {
		expected[Root+"/"+name] = 0600
	}
	for _, r := range roles {
		mode := uint32(0444)
		if executable(r) {
			mode = 0555
		}
		expected[rolePath(r)] = mode
	}
	art, err := descriptor(t.Release)
	if err != nil || digest(encode(t.Release)) != t.Plan.Release {
		return false
	}
	if len(t.Files) != len(expected) {
		return false
	}
	for _, v := range t.Files {
		mode, ok := expected[v.Path]
		if !ok || mode != v.Mode || v.Bytes < 1 || v.Bytes > 512<<20 || !digestPattern.MatchString(v.SHA256) {
			return false
		}
		if v.Path == SelfPath && v.SHA256 != t.Plan.Self.SHA256 {
			return false
		}
		sourcePins := map[string]string{}
		for _, input := range planInputs(t.Plan) {
			sourcePins[Root+"/"+input.name] = input.a.SHA256
		}
		if pin, ok := sourcePins[v.Path]; ok && v.SHA256 != pin {
			return false
		}
		for role, a := range art {
			if v.Path == rolePath(role) || (role == "gateway" && v.Path == childRoot+"/gateway") {
				if v.SHA256 != a.SHA256 || v.Bytes != a.Bytes {
					return false
				}
			}
		}
		delete(expected, v.Path)
	}
	return len(expected) == 0
}

func TestRuntimeFileTypedPlanFileListMatchesOriginal(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			var p *prepared
			if version == 1 {
				_, p, _ = fixture(t)
			} else {
				_, p, _ = managedFixture(t)
			}
			tx := p.transaction(request())
			if !originalFileList2792(tx) || !validFileList(tx) {
				t.Fatal("invalid baseline model")
			}
			clone := func() transaction {
				out := tx
				out.Plan = snapshotPlanValue(tx.Plan)
				out.Files = append([]File(nil), tx.Files...)
				out.Release.Files = append([]Artifact(nil), tx.Release.Files...)
				return out
			}
			compare := func(q transaction) {
				t.Helper()
				before := encode(q)
				if validFileList(q) != originalFileList2792(q) {
					t.Fatal("file-list result changed")
				}
				if !bytes.Equal(before, encode(q)) {
					t.Fatal("validator mutated transaction")
				}
			}
			for i := range tx.Files {
				for _, field := range []string{"path", "sha256", "bytes", "mode"} {
					q := clone()
					switch field {
					case "path":
						q.Files[i].Path += "-foreign"
					case "sha256":
						q.Files[i].SHA256 = strings.Repeat("f", 64)
					case "bytes":
						q.Files[i].Bytes++
					case "mode":
						q.Files[i].Mode ^= 1
					}
					compare(q)
				}
			}
			for _, change := range []func(*transaction){
				func(q *transaction) { q.Version++ }, func(q *transaction) { q.Revision++ }, func(q *transaction) { q.RequestID = strings.Repeat("A", 32) },
				func(q *transaction) { q.Plan.ReleaseRevision = 0 }, func(q *transaction) { q.Plan.Self.SHA256 = strings.Repeat("9", 64) },
				func(q *transaction) { q.Files = q.Files[1:] }, func(q *transaction) { q.Files = append(q.Files, q.Files[0]) },
				func(q *transaction) { q.Files[1] = q.Files[0] }, func(q *transaction) { q.Release.Files[0].Bytes++ },
				func(q *transaction) { q.Release.SourceRevision = "foreign" }, func(q *transaction) { q.Plan.Auth.Path = "/bootstrap/../auth.json" },
			} {
				q := clone()
				change(&q)
				compare(q)
			}
		})
	}
}
