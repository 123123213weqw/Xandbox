package releasestore

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func sampleManifest() Manifest {
	m := Manifest{Version: 1, SourceRevision: strings.Repeat("a", 40), Toolchain: "go1.27.3", GOARCH: "amd64"}
	for _, r := range roles {
		m.Files = append(m.Files, File{r, "/incoming/" + r, hash([]byte(r)), int64(len(r))})
	}
	return m
}
func TestManifestClosedSchema(t *testing.T) {
	m := sampleManifest()
	raw := encoded(m)
	v, e := Decode(raw)
	if e != nil || !bytes.Equal(description(v), description(m)) {
		t.Fatal(e)
	}
	tests := map[string]func(*Manifest){
		"version": func(m *Manifest) { m.Version = 2 }, "source": func(m *Manifest) { m.SourceRevision = "main" }, "toolchain": func(m *Manifest) { m.Toolchain = "go1.27.3;command" }, "arch": func(m *Manifest) { m.GOARCH = "386" },
		"missing": func(m *Manifest) { m.Files = m.Files[:12] }, "duplicate": func(m *Manifest) { m.Files[1] = m.Files[0] }, "role": func(m *Manifest) { m.Files[0].Role = "../ref.json" }, "path": func(m *Manifest) { m.Files[0].Source = "/incoming/../ref.json" }, "store": func(m *Manifest) { m.Files[0].Source = Root + "/objects/daemon" }, "newline": func(m *Manifest) { m.Files[0].Source = "/incoming/file\ncommand" }, "digest": func(m *Manifest) { m.Files[0].SHA256 = "untrusted" }, "zero": func(m *Manifest) { m.Files[0].Bytes = 0 }, "too_large": func(m *Manifest) { m.Files[0].Bytes = MaxReleaseBytes + 1 }, "duplicate_source": func(m *Manifest) { m.Files[1].Source = m.Files[0].Source },
		"total": func(m *Manifest) {
			for i := range m.Files {
				m.Files[i].Bytes = maximum(m.Files[i].Role)
			}
		},
	}
	for n, mutate := range tests {
		t.Run(n, func(t *testing.T) {
			v := sampleManifest()
			mutate(&v)
			if _, e := Decode(encoded(v)); e == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
	for _, bad := range [][]byte{append(bytes.TrimSpace(raw)[:len(bytes.TrimSpace(raw))-1], []byte(`,"extra":true}`)...), []byte(`{"version":1,"version":1}`), append(raw, []byte(`{}`)...), bytes.Repeat([]byte(" "), MaxManifest+1)} {
		if _, e := Decode(bad); e == nil {
			t.Fatal("nonclosed schema accepted")
		}
	}
}
func TestDescriptionDoesNotContainSourcePaths(t *testing.T) {
	m := sampleManifest()
	b := description(m)
	id := hash(b)
	m.Files[0].Source = "/another-private-input/daemon"
	if !bytes.Equal(b, description(m)) || hash(description(m)) != id {
		t.Fatal("artifact identity changed with source path")
	}
	if bytes.Contains(b, []byte("/incoming")) || bytes.Contains(b, []byte(`"source"`)) {
		t.Fatal("private source exported")
	}
	for i, j := 0, len(m.Files)-1; i < j; i, j = i+1, j-1 {
		m.Files[i], m.Files[j] = m.Files[j], m.Files[i]
	}
	norm, e := Decode(encoded(m))
	if e != nil || hash(description(norm)) != id {
		t.Fatal("canonical order changed identity", e)
	}
	in := intent{Version: 1, RequestID: strings.Repeat("b", 32), Manifest: norm}
	old := intentDigest(in)
	in.BaseSHA256 = hash([]byte("base"))
	if intentDigest(in) != old {
		t.Fatal("retry depends on forgotten old reference")
	}
	in.Manifest.Files[0].Source = "/changed/daemon"
	if intentDigest(in) == old {
		t.Fatal("exact request lost source binding")
	}
}
func TestReferenceAndResult(t *testing.T) {
	r := Reference{Version: 1, Revision: 1, Release: hash([]byte("release")), RequestID: strings.Repeat("a", 32), IntentSHA256: hash([]byte("intent"))}
	if !validReference(r) {
		t.Fatal("valid initial reference rejected")
	}
	r.Revision = 2
	r.ExpectedRevision = 1
	if validReference(r) {
		t.Fatal("missing retained predecessor accepted")
	}
	r.Previous = hash([]byte("prior"))
	if !validReference(r) {
		t.Fatal("second reference rejected")
	}
	v := result(r)
	b, _ := json.Marshal(v)
	if v.Retained != 2 || !v.PublicationDurable || v.ServicesChanged || v.ProductionReady || bytes.Contains(b, []byte(r.Release)) {
		t.Fatal("result inflated or leaked identity")
	}
	r.Previous = r.Release
	if validReference(r) {
		t.Fatal("same predecessor accepted")
	}
}
