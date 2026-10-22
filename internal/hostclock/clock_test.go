package hostclock

import "testing"

func TestClockNondecreasing(t *testing.T) {
	previous, err := NowNS()
	if err != nil || previous <= 0 {
		t.Fatal("host clock unavailable", err)
	}
	for range 1000 {
		next, err := NowNS()
		if err != nil || next < previous {
			t.Fatal("host clock regressed", err)
		}
		previous = next
	}
}
