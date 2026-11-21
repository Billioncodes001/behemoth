package captcha

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
)

// TestOtsuThresholdBinarizesTextOnBackground builds a synthetic 60x20 image
// with a dark rectangle (text) on a light background and checks that Otsu
// keeps the text black and the background white.
func TestOtsuThresholdBinarizesTextOnBackground(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 60, 20))
	for y := 0; y < 20; y++ {
		for x := 0; x < 60; x++ {
			src.Set(x, y, color.RGBA{R: 230, G: 230, B: 230, A: 255})
		}
	}
	for y := 4; y < 16; y++ {
		for x := 10; x < 50; x++ {
			src.Set(x, y, color.RGBA{R: 20, G: 20, B: 20, A: 255})
		}
	}
	bin := otsuThreshold(toGray(src))
	if got := bin.Pix[0]; got != 255 {
		t.Fatalf("background should stay white, got %d", got)
	}
	if got := bin.Pix[7*60+30]; got != 0 {
		t.Fatalf("text pixel should become black, got %d", got)
	}
}

// TestDespeckleRemovesIsolatedNoise verifies single-pixel dots are removed
// while 2x2 blobs survive (the exact failure mode of dotted captchas).
func TestDespeckleRemovesIsolatedNoise(t *testing.T) {
	g := image.NewGray(image.Rect(0, 0, 10, 10))
	for i := range g.Pix {
		g.Pix[i] = 255
	}
	g.Pix[2*10+2] = 0 // isolated dot → must disappear
	g.Pix[6*10+6] = 0 // 2x2 blob → must survive
	g.Pix[6*10+7] = 0
	g.Pix[7*10+6] = 0
	g.Pix[7*10+7] = 0

	out := despeckle(g)
	if out.Pix[2*10+2] != 255 {
		t.Fatalf("isolated noise pixel should be removed")
	}
	for _, idx := range []int{6*10 + 6, 6*10 + 7, 7*10 + 6, 7*10 + 7} {
		if out.Pix[idx] != 0 {
			t.Fatalf("blob pixel %d should survive despeckle", idx)
		}
	}
}

// TestUpscaleNearestDoublesSize checks dimensions of the upscale helper.
func TestUpscaleNearestDoublesSize(t *testing.T) {
	src := image.NewGray(image.Rect(0, 0, 5, 3))
	out := upscaleNearest(src, 3)
	if b := out.Bounds(); b.Dx() != 15 || b.Dy() != 9 {
		t.Fatalf("expected 15x9, got %dx%d", b.Dx(), b.Dy())
	}
}

// TestRankCandidatesOrdersByFrequencyAndPlausibility verifies voting prefers
// frequent, plausible-length readings.
func TestRankCandidatesOrdersByFrequencyAndPlausibility(t *testing.T) {
	counts := map[string]int{
		"a2b9":          3, // frequent, plausible length → best
		"a2b9x":         2,
		"zzzzzzzzzzzzz": 5, // frequent but implausible length (13)
		"ab":            1, // short
	}
	got := rankCandidates(counts, 10)
	if len(got) == 0 {
		t.Fatal("expected candidates")
	}
	if got[0] != "a2b9" {
		t.Fatalf("expected a2b9 first, got %v", got)
	}
	seen := map[string]bool{}
	for _, c := range got {
		if seen[c] {
			t.Fatalf("duplicate candidate %q", c)
		}
		seen[c] = true
	}
}

// TestSanitizeOCRText strips spaces, punctuation and newlines.
func TestSanitizeOCRText(t *testing.T) {
	if got := sanitizeOCRText(" a2 b9 \n", ""); got != "a2b9" {
		t.Fatalf("expected a2b9, got %q", got)
	}
	if got := sanitizeOCRText("A1B2", "0123456789"); got != "12" {
		t.Fatalf("whitelist not applied: %q", got)
	}
}

// TestSolveImageCaptchaRequiresTesseract documents the no-tesseract error path
// in environments without the binary.
func TestSolveImageCaptchaMissingBinary(t *testing.T) {
	if TesseractPath() != "" {
		t.Skip("tesseract is installed on this host")
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, image.NewGray(image.Rect(0, 0, 4, 4)))
	if _, err := SolveImageCaptcha(t.Context(), buf.Bytes(), OCRRequest{}); err == nil {
		t.Fatal("expected an error when tesseract is missing")
	}
}
