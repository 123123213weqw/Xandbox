//go:build linux

package warden

import "testing"

func TestWardenRefusesDirectHostInvocation(t *testing.T) {
	for _, group := range []string{"", "../escape", "/sys/fs/cgroup/other", "xandbox-test"} {
		if err := Run(group, 0, []string{"/not/executed"}); err == nil {
			t.Fatal("warden initialized without assigned membership and inherited descriptors")
		}
	}
}
