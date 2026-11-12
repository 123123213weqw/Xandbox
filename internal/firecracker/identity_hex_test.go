package firecracker

import (
	"regexp"
	"strings"
	"testing"

	"github.com/123123213weqw/Xandbox/internal/sandbox"
)

// Pinned pre-change literal regexps, never candidate aliases or inferred widths.
var originalIdentityID32F9 = regexp.MustCompile(`^[0-9a-f]{32}$`)
var originalIdentitySHA64F9 = regexp.MustCompile(`^[0-9a-f]{64}$`)

type identityHexMatcherF9 struct {
	name     string
	width    int
	current  func(string) bool
	original *regexp.Regexp
}

func identityHexMatchersF9() []identityHexMatcherF9 {
	return []identityHexMatcherF9{
		{"hex32", 32, hex32.MatchString, originalIdentityID32F9},
		{"hex64", 64, hex64.MatchString, originalIdentitySHA64F9},
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

func TestInspectionIdentityHexMatchesPinnedOriginal(t *testing.T) {
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

func TestInspectionIdentityHexFreshConcurrent(t *testing.T) {
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

func originalIdentityKeyF9(ref sandbox.Ref) (string, error) {
	if !originalIdentityID32F9.MatchString(ref.ID) || !originalIdentityID32F9.MatchString(ref.Generation) {
		return "", sandbox.ErrInvalid
	}
	return ref.ID + ref.Generation, nil
}

func TestInspectionIdentityHexBindingsKeepOriginalRefusals(t *testing.T) {
	for _, tc := range []struct {
		name           string
		id, generation string
	}{
		{"valid", strings.Repeat("a", 32), strings.Repeat("b", 32)},
		{"empty-id", "", strings.Repeat("b", 32)},
		{"short-id", strings.Repeat("a", 31), strings.Repeat("b", 32)},
		{"long-id", strings.Repeat("a", 33), strings.Repeat("b", 32)},
		{"upper-id", strings.Repeat("A", 32), strings.Repeat("b", 32)},
		{"invalid-UTF8-id", "\xff" + strings.Repeat("a", 31), strings.Repeat("b", 32)},
		{"generation-short", strings.Repeat("a", 32), strings.Repeat("b", 31)},
		{"generation-upper", strings.Repeat("a", 32), strings.Repeat("B", 32)},
		{"digest-domain", strings.Repeat("a", 64), strings.Repeat("b", 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref := sandbox.Ref{ID: tc.id, Generation: tc.generation}
			a, ae := originalIdentityKeyF9(ref)
			b, be := key(ref)
			if a != b || ae != be {
				t.Fatal("backend identity key/value/error differs from pinned original")
			}
		})
	}
}
