//go:build linux

package gateway

import (
	"regexp"
	"strings"
	"testing"
)

// Pinned pre-change literal regexps, never candidate aliases or inferred widths.
var originalIdentityID32F9 = regexp.MustCompile(`^[0-9a-f]{32}$`)

type identityHexMatcherF9 struct {
	name     string
	width    int
	current  func(string) bool
	original *regexp.Regexp
}

func identityHexMatchersF9() []identityHexMatcherF9 {
	return []identityHexMatcherF9{
		{"policyRequest", 32, policyRequest.MatchString, originalIdentityID32F9},
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

func TestPolicyIdentityHexMatchesPinnedOriginal(t *testing.T) {
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

func TestPolicyIdentityHexFreshConcurrent(t *testing.T) {
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
