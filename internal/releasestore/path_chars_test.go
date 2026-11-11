package releasestore

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var originalAbsolutePathPatternE57 = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)

// This is the pinned pre-change predicate, never the candidate alias. Existing
// policy/decoder baselines also use it rather than calling candidate canonical.
func originalCanonicalPathE57(path string) bool {
	return originalAbsolutePathPatternE57.MatchString(path) && filepath.Clean(path) == path && path != "/"
}

func pathCharsE57Corpus() []string {
	values := []string{"", "/", "//", "/x", "/x/", "/a/../b", "/A-Z/a_09.json", "/\xff", "/a\x00b", "/é", "/a\n"}
	state := uint32(0x62511)
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./-"
	for n := 0; n < 512; n++ {
		state = state*1664525 + 1013904223
		size := int(state % 129)
		raw, allowed := make([]byte, size), make([]byte, size+1)
		allowed[0] = '/'
		for i := range raw {
			state = state*1664525 + 1013904223
			raw[i] = byte(state >> 24)
			allowed[i+1] = alphabet[int(state%uint32(len(alphabet)))]
		}
		values = append(values, string(raw), string(allowed))
	}
	return values
}

func TestCanonicalPathMatchesPinnedOriginal(t *testing.T) {
	check := func(t *testing.T, p string) {
		t.Helper()
		if canonical(p) != originalCanonicalPathE57(p) {
			t.Fatal("canonical path differs from pinned original regexp/Clean/root predicate")
		}
	}
	for _, tc := range []struct{ name, path string }{
		{"empty", ""}, {"root", "/"}, {"relative", "a/b"},
		{"double-slash", "//"}, {"dot-segment", "/./a"},
		{"parent-segment", "/a/../b"}, {"trailing-slash", "/a/"},
		{"embedded-double-slash", "/a//b"}, {"allowed-ascii", "/A-Z/a_09.json"},
		{"hidden-component", "/a/.hidden"}, {"unicode", "/é"},
		{"invalid-utf8", "/\xff"}, {"linefeed", "/a\n"},
		{"carriage-return", "/a\r"}, {"nul", "/a\x00b"},
		{"backslash", "/a\\b"},
	} {
		t.Run(tc.name, func(t *testing.T) { check(t, tc.path) })
	}
	t.Run("all-bytes", func(t *testing.T) {
		for b := 0; b < 256; b++ {
			c := string([]byte{byte(b)})
			for _, p := range []string{c + "x", "/" + c, "/a" + c + "b", "/a/" + c, "/" + c + "/z", "/a" + c + "/z"} {
				check(t, p)
			}
		}
	})
	t.Run("long-inputs", func(t *testing.T) {
		// No invented character-layer ceiling, even above manifest/OS path limits.
		for _, n := range []int{1, 2, 63, 64, 65, 255, 256, 257, 4095, 4096, 4097, 16383, 16384, 16385, 65536} {
			p := "/" + strings.Repeat("a", n)
			check(t, p)
			check(t, p+"/")
			check(t, p+"\xff")
		}
	})
	t.Run("deterministic-corpus", func(t *testing.T) {
		for _, p := range pathCharsE57Corpus() {
			check(t, p)
		}
	})
}

func TestCanonicalPathFreshConcurrent(t *testing.T) {
	values := pathCharsE57Corpus()
	done := make(chan bool, 8)
	for worker := 0; worker < 8; worker++ {
		go func(worker int) {
			bad := false
			for i := worker; i < len(values); i += 8 {
				p := values[i]
				bad = canonical(p) != originalCanonicalPathE57(p) || bad
			}
			done <- bad
		}(worker)
	}
	for worker := 0; worker < 8; worker++ {
		if <-done {
			t.Fatal("concurrent fresh canonical path differs")
		}
	}
}
