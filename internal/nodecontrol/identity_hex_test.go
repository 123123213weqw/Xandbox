package nodecontrol

import (
	"math"
	"regexp"
	"strings"
	"testing"
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
		{"maintenanceDigest", 64, maintenanceDigest.MatchString, originalIdentitySHA64F9},
		{"hexID", 32, hexID.MatchString, originalIdentityID32F9},
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

func TestMaintenanceIdentityHexMatchesPinnedOriginal(t *testing.T) {
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

func TestMaintenanceIdentityHexFreshConcurrent(t *testing.T) {
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

func originalIdentityOwnerF9(o MaintenanceOwner) bool {
	return o.Version == 1 && originalIdentitySHA64F9.MatchString(o.InstallCommitSHA256) && originalIdentityID32F9.MatchString(o.OperationID)
}

func originalIdentityStateF9(s State) bool {
	if s.Version != 1 || !originalIdentityID32F9.MatchString(s.Epoch) || s.Revision == 0 || (s.Mode != ModeOpen && s.Mode != ModeDrained) {
		return false
	}
	if s.Revision == math.MaxUint64 && s.Mode != ModeDrained {
		return false
	}
	if s.Revision == 1 {
		return s.LastRequestID == "" && s.LastExpectedRevision == 0
	}
	return originalIdentityID32F9.MatchString(s.LastRequestID) && s.LastExpectedRevision == s.Revision-1
}

func originalIdentityCommandF9(c Command) bool {
	return c.Version == 1 && originalIdentityID32F9.MatchString(c.Epoch) && c.ExpectedRevision > 0 && originalIdentityID32F9.MatchString(c.RequestID)
}

func TestMaintenanceIdentityHexBindingsKeepOriginalRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*State, *Command, *MaintenanceOwner)
	}{
		{"valid", func(*State, *Command, *MaintenanceOwner) {}},
		{"epoch-short", func(s *State, _ *Command, _ *MaintenanceOwner) { s.Epoch = s.Epoch[:31] }},
		{"epoch-upper", func(s *State, _ *Command, _ *MaintenanceOwner) { s.Epoch = strings.ToUpper(s.Epoch) }},
		{"owner-operation-long", func(_ *State, _ *Command, o *MaintenanceOwner) { o.OperationID += "a" }},
		{"owner-digest-short", func(_ *State, _ *Command, o *MaintenanceOwner) { o.InstallCommitSHA256 = o.InstallCommitSHA256[:63] }},
		{"owner-digest-upper", func(_ *State, _ *Command, o *MaintenanceOwner) {
			o.InstallCommitSHA256 = strings.ToUpper(o.InstallCommitSHA256)
		}},
		{"command-request-invalid", func(_ *State, c *Command, _ *MaintenanceOwner) { c.RequestID = "invalid" }},
		{"version", func(s *State, c *Command, o *MaintenanceOwner) { s.Version = 0; c.Version = 0; o.Version = 0 }},
		{"state-revision-zero", func(s *State, _ *Command, _ *MaintenanceOwner) { s.Revision = 0 }},
		{"state-max-open", func(s *State, _ *Command, _ *MaintenanceOwner) { s.Revision = math.MaxUint64 }},
		{"state-mode", func(s *State, _ *Command, _ *MaintenanceOwner) { s.Mode = "foreign" }},
		{"command-epoch-digest-domain", func(_ *State, c *Command, _ *MaintenanceOwner) { c.Epoch = strings.Repeat("a", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := State{Version: 1, Epoch: strings.Repeat("a", 32), Revision: 1, Mode: ModeOpen}
			c := Command{Version: 1, Epoch: s.Epoch, ExpectedRevision: 1, RequestID: strings.Repeat("b", 32)}
			o := MaintenanceOwner{Version: 1, InstallCommitSHA256: strings.Repeat("c", 64), OperationID: strings.Repeat("d", 32)}
			tc.change(&s, &c, &o)
			if s.Valid() != originalIdentityStateF9(s) || c.Valid() != originalIdentityCommandF9(c) || o.Valid() != originalIdentityOwnerF9(o) {
				t.Fatal("control/maintenance binding differs from pinned full original predicates")
			}
		})
	}
}
