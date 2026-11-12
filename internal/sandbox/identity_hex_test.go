package sandbox

import (
	"regexp"
	"strings"
	"testing"
	"time"
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
		{"tokenPattern", 32, tokenPattern.MatchString, originalIdentityID32F9},
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

func TestResultStoreIdentityHexMatchesPinnedOriginal(t *testing.T) {
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

func TestResultStoreIdentityHexFreshConcurrent(t *testing.T) {
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

func originalIdentityRefF9(r Ref) bool {
	return originalIdentityID32F9.MatchString(r.ID) && originalIdentityID32F9.MatchString(r.Generation)
}
func originalIdentityReservationF9(r ResultReservation) bool {
	return originalIdentityID32F9.MatchString(r.JobID) && originalIdentityRefF9(r.Ref) && tenantPattern.MatchString(r.TenantID) && r.MaxOutputBytes >= 1 && r.MaxOutputBytes <= 65_536 && resultTimeValid(r.StartedAt)
}

func originalIdentityClosureF9(o ClosureObservation) bool {
	return o.Version == 1 && o.Records >= 0 && o.Records <= 100_000 && originalIdentitySHA64F9.MatchString(o.RecordsSHA256)
}

func originalIdentityResultsClosureF9(o ResultClosureObservation) bool {
	return o.Version == 2 && o.Records >= 0 && o.Records <= MaxResultRecords && o.Bytes >= 0 && o.Bytes <= MaxResultBytes && o.ReservedBytes >= o.Bytes && o.ReservedBytes <= MaxResultBytes && originalIdentitySHA64F9.MatchString(o.RecordsSHA256) && ((o.Records == 0 && o.Bytes == 0 && o.ReservedBytes == 0) || (o.Records > 0 && o.Bytes > 0 && o.ReservedBytes > 0))
}

func TestResultStoreIdentityHexBindingsKeepOriginalRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*ResultReservation, *ClosureObservation, *ResultClosureObservation)
	}{
		{"valid", func(*ResultReservation, *ClosureObservation, *ResultClosureObservation) {}},
		{"job-id-short", func(r *ResultReservation, _ *ClosureObservation, _ *ResultClosureObservation) { r.JobID = r.JobID[:31] }},
		{"ref-generation-upper", func(r *ResultReservation, _ *ClosureObservation, _ *ResultClosureObservation) {
			r.Ref.Generation = strings.ToUpper(r.Ref.Generation)
		}},
		{"job-id-digest-domain", func(r *ResultReservation, _ *ClosureObservation, _ *ResultClosureObservation) {
			r.JobID = strings.Repeat("a", 64)
		}},
		{"output-zero", func(r *ResultReservation, _ *ClosureObservation, _ *ResultClosureObservation) { r.MaxOutputBytes = 0 }},
		{"tenant-invalid", func(r *ResultReservation, _ *ClosureObservation, _ *ResultClosureObservation) { r.TenantID = "!" }},
		{"time-zero", func(r *ResultReservation, _ *ClosureObservation, _ *ResultClosureObservation) {
			r.StartedAt = time.Time{}
		}},
		{"closure-digest-short", func(_ *ResultReservation, c *ClosureObservation, _ *ResultClosureObservation) {
			c.RecordsSHA256 = c.RecordsSHA256[:63]
		}},
		{"result-digest-upper", func(_ *ResultReservation, _ *ClosureObservation, c *ResultClosureObservation) {
			c.RecordsSHA256 = strings.ToUpper(c.RecordsSHA256)
		}},
		{"record-negative", func(_ *ResultReservation, c *ClosureObservation, r *ResultClosureObservation) {
			c.Records = -1
			r.Records = -1
		}},
		{"reservation-less-than-output", func(_ *ResultReservation, _ *ClosureObservation, c *ResultClosureObservation) {
			c.ReservedBytes = c.Bytes - 1
		}},
		{"version", func(r *ResultReservation, c *ClosureObservation, x *ResultClosureObservation) {
			r.Ref = Ref{}
			c.Version = 0
			x.Version = 0
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := ResultReservation{JobID: strings.Repeat("a", 32), Ref: Ref{ID: strings.Repeat("b", 32), Generation: strings.Repeat("c", 32)}, TenantID: "alpha", MaxOutputBytes: 64, StartedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
			c := ClosureObservation{Version: 1, Records: 1, RecordsSHA256: strings.Repeat("d", 64)}
			x := ResultClosureObservation{Version: 2, Records: 1, Bytes: 128, ReservedBytes: 256, RecordsSHA256: strings.Repeat("e", 64)}
			tc.change(&r, &c, &x)
			if r.valid() != originalIdentityReservationF9(r) || c.Valid() != originalIdentityClosureF9(c) || x.Valid() != originalIdentityResultsClosureF9(x) {
				t.Fatal("result reservation/closure binding differs from pinned original predicates")
			}
		})
	}
}
