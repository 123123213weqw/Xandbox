package installtxn

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// Reference regexps are the exact installer validators at53e9ce2.
func hexPatternReferences() []struct {
	width   int
	current lowerHexPattern
	old     *regexp.Regexp
} {
	return []struct {
		width   int
		current lowerHexPattern
		old     *regexp.Regexp
	}{
		{32, requestPattern, regexp.MustCompile(`^[0-9a-f]{32}$`)},
		{64, digestPattern, regexp.MustCompile(`^[0-9a-f]{64}$`)},
	}
}

func TestRuntimeFileFixedHexEveryByteAtEveryPositionMatchesOriginal(t *testing.T) {
	for _, p := range hexPatternReferences() {
		s := []byte(strings.Repeat("a", p.width))
		for i := range s {
			for b := 0; b < 256; b++ {
				s[i] = byte(b)
				v := string(s)
				if p.current.MatchString(v) != p.old.MatchString(v) {
					t.Fatalf("width%d position%d byte%d diverged", p.width, i, b)
				}
			}
			s[i] = 'a'
		}
	}
}

func TestRuntimeFileFixedHexLengthUnicodeAndBoundariesMatchOriginal(t *testing.T) {
	for _, p := range hexPatternReferences() {
		valid := strings.Repeat("0123456789abcdef", p.width/16)
		cases := []string{"", valid, strings.Repeat("0", p.width), strings.Repeat("f", p.width), strings.ToUpper(valid), valid + "\n", "\n" + valid, valid + "\r\n", " " + valid, valid + " ", valid + "\x00", valid[1:], valid + "0"}
		for _, s := range []string{"ſ", "K", "０", "ａ", "é", "\u200b", "\ufffd"} {
			cases = append(cases, s+valid[len(s):], valid[:p.width-len(s)]+s)
		}
		for n := 0; n <= 128; n++ {
			cases = append(cases, strings.Repeat("a", n))
		}
		for _, v := range cases {
			if p.current.MatchString(v) != p.old.MatchString(v) {
				t.Fatalf("width%d input%q diverged", p.width, v)
			}
		}
	}
}

func TestRuntimeFileFixedHexDeterministicCorpusAndConcurrentReaders(t *testing.T) {
	for _, p := range hexPatternReferences() {
		p := p
		t.Run(fmt.Sprint(p.width), func(t *testing.T) {
			t.Parallel()
			r := rand.New(rand.NewSource(76123))
			for n := 0; n < 4096; n++ {
				b := make([]byte, r.Intn(130))
				for i := range b {
					if n%2 == 0 {
						b[i] = "0123456789abcdef"[r.Intn(16)]
					} else {
						b[i] = byte(r.Intn(256))
					}
				}
				v := string(b)
				if p.current.MatchString(v) != p.old.MatchString(v) {
					t.Fatalf("corpus %d diverged", n)
				}
			}
		})
	}
}

var hexBenchmarkResult bool

func BenchmarkRuntimeFileFixedHex(b *testing.B) {
	for _, p := range hexPatternReferences() {
		for _, c := range []struct{ name, value string }{{"valid", strings.Repeat("a", p.width)}, {"invalid-last", strings.Repeat("a", p.width-1) + "g"}} {
			name, v := c.name, c.value
			b.Run(fmt.Sprintf("%d/%s/original-regexp", p.width, name), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					hexBenchmarkResult = p.old.MatchString(v)
				}
			})
			b.Run(fmt.Sprintf("%d/%s/byte-validator", p.width, name), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					hexBenchmarkResult = p.current.MatchString(v)
				}
			})
		}
	}
}
