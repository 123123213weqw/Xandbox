package session

import (
	"errors"
	"math"
	"regexp"
	"strings"
	"testing"
	"time"

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
		{"idPattern", 32, idPattern.MatchString, originalIdentityID32F9},
		{"hashPattern", 64, hashPattern.MatchString, originalIdentitySHA64F9},
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

func TestSessionIdentityHexMatchesPinnedOriginal(t *testing.T) {
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

func TestSessionIdentityHexFreshConcurrent(t *testing.T) {
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

func originalIdentityRefF9(r sandbox.Ref) bool {
	return originalIdentityID32F9.MatchString(r.ID) && originalIdentityID32F9.MatchString(r.Generation)
}
func originalIdentityOptionalRefF9(r sandbox.Ref) bool { return zeroRef(r) || originalIdentityRefF9(r) }
func originalIdentitySessionF9(r Record) error {
	if !originalIdentityID32F9.MatchString(r.ID) || !(sandbox.Owner{TenantID: r.TenantID, MaxInstances: 1}).Valid() || !originalIdentitySHA64F9.MatchString(r.CreateKeyHash) || !originalIdentitySHA64F9.MatchString(r.CreateSpecHash) || r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() || len(r.Attempts) < 1 || len(r.Attempts) > MaxHistory || !originalIdentityOptionalRefF9(r.Current) {
		return errors.New("invalid session identity/metadata")
	}
	switch r.State {
	case Creating, Active, Preparing, Prepared, Closed:
	default:
		return errors.New("unknown session state")
	}
	if r.Revision > MaxHistory || (r.Revision == 0) != zeroRef(r.Current) || (r.State == Active && r.Revision == 0) {
		return errors.New("invalid session binding")
	}
	keys := map[string]bool{}
	targets := map[sandbox.Ref]bool{}
	var revision uint64
	var current sandbox.Ref
	for n, a := range r.Attempts {
		if !originalIdentitySHA64F9.MatchString(a.KeyHash) || !originalIdentitySHA64F9.MatchString(a.SpecHash) || keys[a.KeyHash] || !originalIdentityOptionalRefF9(a.From) || !originalIdentityOptionalRefF9(a.Target) || a.StartedAt.IsZero() || a.ExpectedRevision > MaxHistory || a.ResultRevision != a.ExpectedRevision+1 {
			return errors.New("invalid session attempt")
		}
		keys[a.KeyHash] = true
		if a.ExpectedRevision != revision || a.From != current || (n > 0 && a.ExpectedRevision == 0) {
			return errors.New("session history is not a revision chain")
		}
		if !zeroRef(a.Target) {
			if a.Target == a.From || targets[a.Target] {
				return errors.New("session target reused")
			}
			targets[a.Target] = true
		}
		if (a.ExpectedRevision == 0) != zeroRef(a.From) {
			return errors.New("invalid previous binding")
		}
		switch a.State {
		case Preparing:
			if n != len(r.Attempts)-1 {
				return errors.New("unfinished nonfinal session attempt")
			}
			if !zeroRef(a.Target) {
				return errors.New("preparing attempt has durable target")
			}
		case Prepared:
			if n != len(r.Attempts)-1 {
				return errors.New("unfinished nonfinal session attempt")
			}
			if !originalIdentityRefF9(a.Target) || a.ReadyAt.IsZero() {
				return errors.New("prepared attempt missing target")
			}
		case "COMMITTED":
			if !originalIdentityRefF9(a.Target) || a.ReadyAt.IsZero() || a.FencedAt.IsZero() || a.CommitStartedAt.IsZero() {
				return errors.New("incomplete committed attempt")
			}
			revision, current = a.ResultRevision, a.Target
		case "FAILED":
			// A failed final write can have consumed the new revision without
			// publishing it. It is terminal/fenced, never a route to resurrect.
			if n == len(r.Attempts)-1 && r.State == Closed && !a.FencedAt.IsZero() && r.Revision == a.ResultRevision && r.Current == a.Target {
				revision, current = a.ResultRevision, a.Target
			}
		default:
			return errors.New("unknown attempt state")
		}
		if n == 0 && (a.KeyHash != r.CreateKeyHash || a.SpecHash != r.CreateSpecHash || a.ExpectedRevision != 0) {
			return errors.New("invalid initial attempt")
		}
		for _, v := range []float64{a.Timings.TotalMS, a.Timings.CandidateReadyMS, a.Timings.AdmissionRevokedMS, a.Timings.FenceToCommitMS} {
			if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
				return errors.New("invalid session timing")
			}
		}
	}
	if r.Revision != revision || r.Current != current {
		return errors.New("session current disagrees with history")
	}
	return nil
}

func TestSessionIdentityHexBindingsKeepOriginalRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Record)
	}{
		{"valid", func(*Record) {}},
		{"id-short", func(r *Record) { r.ID = r.ID[:31] }},
		{"id-upper", func(r *Record) { r.ID = strings.Repeat("A", 32) }},
		{"create-key-long", func(r *Record) { r.CreateKeyHash += "a" }},
		{"create-spec-invalid-UTF8", func(r *Record) { r.CreateSpecHash = "\xff" + r.CreateSpecHash[1:] }},
		{"current-id-invalid", func(r *Record) { r.Current.ID = "invalid" }},
		{"current-generation-long", func(r *Record) { r.Current.Generation += "a" }},
		{"attempt-key-upper", func(r *Record) { r.Attempts[1].KeyHash = strings.Repeat("A", 64) }},
		{"attempt-spec-short", func(r *Record) { r.Attempts[1].SpecHash = r.Attempts[1].SpecHash[:63] }},
		{"from-generation-invalid", func(r *Record) { r.Attempts[1].From.Generation = "invalid" }},
		{"target-id-long", func(r *Record) { r.Attempts[1].Target.ID += "a" }},
		{"revision-exhausted", func(r *Record) { r.Revision = MaxHistory + 1 }},
		{"history-disconnected", func(r *Record) { r.Attempts[1].ExpectedRevision = 0 }},
		{"target-reused", func(r *Record) { r.Attempts[1].Target = r.Attempts[0].Target; r.Current = r.Attempts[1].Target }},
		{"ready-time-zero", func(r *Record) { r.Attempts[1].ReadyAt = time.Time{} }},
		{"state-unknown", func(r *Record) { r.State = "foreign" }},
		{"timing-NaN", func(r *Record) { r.Attempts[1].Timings.TotalMS = math.NaN() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := storeFixture(2)
			tc.change(&r)
			a, b := originalIdentitySessionF9(r), validate(r)
			if (a == nil) != (b == nil) || (a != nil && a.Error() != b.Error()) {
				t.Fatal("session complete metadata/history predicate/error differs from pinned original")
			}
		})
	}
}
