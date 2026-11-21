package security

import (
	"testing"
	"time"
)

// CheckRateLimit never removed per-IP entries, so an internet-facing instance
// grew requestCount/windowStart by one pair per unique IP forever. Once the map
// is over the prune threshold, a new request must sweep out long-expired
// windows while keeping fresh ones.
func TestCheckRateLimitPrunesExpiredWindows(t *testing.T) {
	ad := NewAntiDetect(StealthConfig{
		Enabled:       true,
		RateLimit:     1000,
		RequestJitter: 0,
	})
	stale := time.Now().Add(-5 * time.Minute)
	for i := 0; i < 5000; i++ {
		ip := ipAt(i)
		ad.windowStart[ip] = stale
		ad.requestCount[ip] = 1
	}
	// Fresh windows must survive the sweep triggered by the new request.
	ad.windowStart["203.0.113.200"] = time.Now()
	ad.requestCount["203.0.113.200"] = 1

	if allowed, wait := ad.CheckRateLimit("198.51.100.1"); !allowed || wait != 0 {
		t.Fatalf("new IP must be allowed, allowed=%v wait=%v", allowed, wait)
	}
	if _, ok := ad.windowStart["203.0.113.200"]; !ok {
		t.Fatal("fresh entry must survive pruning")
	}
	if _, ok := ad.windowStart[ipAt(0)]; ok {
		t.Fatal("stale entries must be pruned")
	}
	if got := len(ad.windowStart); got > 3 {
		t.Fatalf("map still holds %d entries after prune", got)
	}
}

func ipAt(i int) string {
	return "198.51.100." + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
