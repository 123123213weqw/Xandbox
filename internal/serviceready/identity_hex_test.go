package serviceready

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

// Pinned pre-change literal regexps, never candidate aliases or inferred widths.
var originalIdentitySHA64F9 = regexp.MustCompile(`^[0-9a-f]{64}$`)

type identityHexMatcherF9 struct {
	name     string
	width    int
	current  func(string) bool
	original *regexp.Regexp
}

func identityHexMatchersF9() []identityHexMatcherF9 {
	return []identityHexMatcherF9{
		{"shaPattern", 64, shaPattern.MatchString, originalIdentitySHA64F9},
	}
}

func identityHexCorpusF9(width int) []string {
	good := strings.Repeat("a", width)
	values := []string{"", good, strings.Repeat("0", width), strings.Repeat("0123456789abcdef", width/16), good[:width-1], good + "f", strings.ToUpper(good), " " + good, good + "\n", good + "\r\n", good + "\x00"}
	for _, u := range []string{"é", "ſ", "K", "ａ", "０", "\u200b", "\ufffd", string([]byte{255})} {
		values = append(values, u+good[len(u):], good[:width-len(u)]+u)
	}
	state := uint32(0xF93264)
	for n := 0; n < 256; n++ {
		state = state*1664525 + 1013904223
		size := width - 1 + int(state%3)
		b := make([]byte, size)
		for i := range b {
			state = state*1664525 + 1013904223
			if n%2 == 0 {
				b[i] = "0123456789abcdef"[state%16]
			} else {
				b[i] = byte(state >> 24)
			}
		}
		values = append(values, string(b))
	}
	return values
}

func TestReadinessIdentityHexMatchesPinnedOriginal(t *testing.T) {
	for _, m := range identityHexMatchersF9() {
		t.Run(m.name, func(t *testing.T) {
			check := func(s string) {
				t.Helper()
				if m.current(s) != m.original.MatchString(s) {
					t.Fatal("identity/digest language differs from pinned literal original")
				}
			}
			for _, s := range identityHexCorpusF9(m.width) {
				check(s)
			}
			b := []byte(strings.Repeat("a", m.width))
			for _, at := range []int{0, m.width / 2, m.width - 1} {
				for n := 0; n < 256; n++ {
					b[at] = byte(n)
					check(string(b))
				}
				b[at] = 'a'
			}
		})
	}
}

func TestReadinessIdentityHexFreshConcurrent(t *testing.T) {
	type work struct {
		matcher identityHexMatcherF9
		values  []string
	}
	var jobs []work
	for _, m := range identityHexMatchersF9() {
		jobs = append(jobs, work{m, identityHexCorpusF9(m.width)})
	}
	done := make(chan bool, 8)
	for worker := 0; worker < 8; worker++ {
		go func(worker int) {
			bad := false
			for _, job := range jobs {
				for i := worker; i < len(job.values); i += 8 {
					s := job.values[i]
					want := job.matcher.original.MatchString(s)
					bad = job.matcher.current(s) != want || job.matcher.current(s) != want || bad
				}
			}
			done <- bad
		}(worker)
	}
	for worker := 0; worker < 8; worker++ {
		if <-done {
			t.Fatal("fresh concurrent fixed identity/digest changed")
		}
	}
}

func originalIdentityReadyDecodeF9(data []byte) (Manifest, error) {
	var m Manifest
	if len(data) > 16384 || strictjson.Decode(data, &m) != nil || m.Version != 1 || !originalCanonicalPathE57(m.NodeLaunch.Path) || !originalIdentitySHA64F9.MatchString(m.NodeLaunch.SHA256) || m.Helper.Path != HelperPath || !originalIdentitySHA64F9.MatchString(m.Helper.SHA256) || m.NodeLaunch.Path == m.Helper.Path || !devicePattern.MatchString(m.Device) || m.Device == "0:0" {
		return m, errPolicy
	}
	return m, nil
}

func TestReadinessIdentityHexBindingsKeepOriginalRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Manifest)
	}{
		{"valid", func(*Manifest) {}},
		{"node-sha-short", func(m *Manifest) { m.NodeLaunch.SHA256 = m.NodeLaunch.SHA256[:63] }},
		{"node-sha-long", func(m *Manifest) { m.NodeLaunch.SHA256 += "a" }},
		{"node-sha-upper", func(m *Manifest) { m.NodeLaunch.SHA256 = strings.Repeat("A", 64) }},
		{"helper-sha-short", func(m *Manifest) { m.Helper.SHA256 = m.Helper.SHA256[:63] }},
		{"helper-sha-identity-domain", func(m *Manifest) { m.Helper.SHA256 = strings.Repeat("a", 32) }},
		{"version", func(m *Manifest) { m.Version = 0 }},
		{"device-zero", func(m *Manifest) { m.Device = "0:0" }},
		{"unclean-path", func(m *Manifest) { m.NodeLaunch.Path = "/a/../b" }},
		{"helper-path", func(m *Manifest) { m.Helper.Path = "/bin/sh" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := policies()
			tc.change(&m)
			raw, e := json.Marshal(m)
			if e != nil {
				t.Fatal(e)
			}
			a, ae := originalIdentityReadyDecodeF9(raw)
			b, be := Decode(raw)
			if a != b || ae != be {
				t.Fatal("readiness decoded value/error/policy differs from pinned original")
			}
		})
	}
	m, _ := policies()
	raw, _ := json.Marshal(m)
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"unknown", append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"foreign":1}`)...)},
		{"duplicate", append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"version":1}`)...)},
		{"null", []byte("null")},
		{"oversize", []byte(strings.Repeat(" ", 16385))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, ae := originalIdentityReadyDecodeF9(tc.raw)
			b, be := Decode(tc.raw)
			if a != b || ae != be {
				t.Fatal("readiness raw decoded partial value/error changed")
			}
		})
	}
}
