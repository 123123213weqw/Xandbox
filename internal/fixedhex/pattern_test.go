package fixedhex

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"sync"
	"testing"
)

func TestPatternExactRegexpLanguage(t *testing.T) {
	for _, width := range []int{32, 40, 64} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			old := regexp.MustCompile(fmt.Sprintf(`^[0-9a-f]{%d}$`, width))
			current := Pattern(width)
			v := []byte(strings.Repeat("a", width))
			for i := range v {
				for c := 0; c < 256; c++ {
					v[i] = byte(c)
					s := string(v)
					if current.MatchString(s) != old.MatchString(s) {
						t.Fatal("byte language changed", i, c)
					}
				}
				v[i] = 'a'
			}
			corpus := []string{"", string(v), string(v) + "\n", "\n" + string(v), string(v) + "\r\n", strings.ToUpper(string(v)), " " + string(v), string(v) + "\x00"}
			for _, s := range []string{"ſ", "K", "ａ", "０", "\u200b", "\ufffd", string([]byte{255})} {
				corpus = append(corpus, s+string(v[len(s):]), string(v[:width-len(s)])+s)
			}
			rng := rand.New(rand.NewSource(981461))
			for n := 0; n < 4096; n++ {
				b := make([]byte, rng.Intn(130))
				for i := range b {
					if n%2 == 0 {
						b[i] = "0123456789abcdef"[rng.Intn(16)]
					} else {
						b[i] = byte(rng.Intn(256))
					}
				}
				corpus = append(corpus, string(b))
			}
			var wg sync.WaitGroup
			for k := 0; k < 8; k++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for _, s := range corpus {
						if current.MatchString(s) != old.MatchString(s) {
							t.Error("boundary/concurrent language changed")
							return
						}
					}
				}()
			}
			wg.Wait()
		})
	}
	for _, width := range []Pattern{0, -1, -64} {
		if width.MatchString("") || width.MatchString("a") {
			t.Fatal("invalid width accepted")
		}
	}
}
