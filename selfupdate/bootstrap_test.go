package selfupdate

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// clipUTF8 must never return a string ending in half a rune: the smoke-test
// failure message is shown to users, and split multi-byte output used to render
// as replacement characters.
func TestClipUTF8(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		max  int
	}{
		{"short ascii untouched", "hello", 300},
		{"ascii cut", strings.Repeat("a", 400), 300},
		{"cut inside a han rune", strings.Repeat("爆", 200), 300},
		{"cut inside combining emoji", "🚨" + strings.Repeat("x", 300), 200},
		{"max 0", "abc", 0},
		{"max 1 with multibyte", "爆爆爆", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := clipUTF8(tc.in, tc.max)
			if len(got) > tc.max {
				t.Fatalf("clipUTF8 len=%d exceeds max=%d", len(got), tc.max)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("clipUTF8 produced invalid UTF-8: %q", got)
			}
			if !strings.HasPrefix(tc.in, got) {
				t.Fatalf("clipUTF8 is not a prefix of the input: %q", got)
			}
		})
	}
}
