package captcha

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/color"
	_ "image/gif"
	_ "image/jpeg"
	"image/png"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Image-captcha OCR pipeline: decode → preprocess (grayscale → Otsu threshold →
// despeckle → upscale / invert variants) → tesseract across multiple page
// segmentation modes → candidate voting. Everything runs locally so an agent
// can burn hundreds of attempts inside ONE tool call instead of reading ASCII
// art with LLM tokens.

// tesseractTimeout bounds each tesseract invocation.
const tesseractTimeout = 15 * time.Second

// OCRRequest tunes the OCR pass.
type OCRRequest struct {
	// CharWhitelist restricts recognized characters (default: letters+digits).
	CharWhitelist string
	// Language is the tesseract language (default "eng").
	Language string
	// PSMs overrides the tesseract page segmentation modes tried per variant.
	PSMs []int
	// MaxVariants caps the number of preprocessed variants (default all).
	MaxVariants int
	// MaxCandidates caps the ranked candidate list (default 8).
	MaxCandidates int
}

// OCRAttempt is one tesseract run over one preprocessed variant.
type OCRAttempt struct {
	Variant string `json:"variant"`
	PSM     int    `json:"psm"`
	Text    string `json:"text"`
}

// OCRResult is the ranked output of SolveImageCaptcha.
type OCRResult struct {
	Best       string       `json:"best"`
	Candidates []string     `json:"candidates"`
	Attempts   []OCRAttempt `json:"attempts,omitempty"`
	Engine     string       `json:"engine"`
	Error      string       `json:"error,omitempty"`
}

// Recognizer turns captcha image bytes into ranked answer candidates. Used by
// the form solver; tests inject deterministic implementations.
type Recognizer func(ctx context.Context, img []byte) ([]string, error)

// TesseractPath resolves the tesseract binary (env override + PATH).
func TesseractPath() string {
	if p := strings.TrimSpace(os.Getenv("BEHEMOTH_TESSERACT")); p != "" {
		return p
	}
	if p, err := exec.LookPath("tesseract"); err == nil {
		return p
	}
	return ""
}

// defaultPSMs are the page segmentation modes that work best on short
// single-line captcha strings.
var defaultPSMs = []int{7, 8, 13}

// toGray converts any image to 8-bit grayscale.
func toGray(src image.Image) *image.Gray {
	b := src.Bounds()
	g := image.NewGray(image.Rect(0, 0, b.Dx(), b.Dy()))
	for y := 0; y < b.Dy(); y++ {
		for x := 0; x < b.Dx(); x++ {
			r, gr, bl, _ := src.At(b.Min.X+x, b.Min.Y+y).RGBA()
			lum := (299*r + 587*gr + 114*bl) / 1000
			g.SetGray(x, y, color.Gray{Y: uint8(lum >> 8)})
		}
	}
	return g
}

// otsuThreshold picks the luminance split that minimizes intra-class variance
// and returns a binarized image (text=0/black, background=255/white).
func otsuThreshold(g *image.Gray) *image.Gray {
	var hist [256]int
	for _, p := range g.Pix {
		hist[p]++
	}
	total := len(g.Pix)
	sum := 0
	for v, n := range hist {
		sum += v * n
	}
	sumB, wB := 0, 0
	bestVar := -1.0
	thresh := 128
	for v := 0; v < 256; v++ {
		wB += hist[v]
		if wB == 0 {
			continue
		}
		wF := total - wB
		if wF == 0 {
			break
		}
		sumB += v * hist[v]
		mB := float64(sumB) / float64(wB)
		mF := float64(sum-sumB) / float64(wF)
		variance := float64(wB) * float64(wF) * (mB - mF) * (mB - mF)
		if variance > bestVar {
			bestVar = variance
			thresh = v
		}
	}
	out := image.NewGray(g.Bounds())
	for i, p := range g.Pix {
		if uint8(p) > uint8(thresh) {
			out.Pix[i] = 255
		}
	}
	return out
}

// despeckle removes isolated dark pixels (single-pixel noise dots that wreck
// OCR on classic captcha fonts).
func despeckle(g *image.Gray) *image.Gray {
	b := g.Bounds()
	out := image.NewGray(b)
	w, h := b.Dx(), b.Dy()
	at := func(x, y int) bool {
		if x < 0 || y < 0 || x >= w || y >= h {
			return false
		}
		return g.Pix[y*w+x] == 0
	}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if !at(x, y) {
				continue
			}
			neighbors := 0
			for dy := -1; dy <= 1; dy++ {
				for dx := -1; dx <= 1; dx++ {
					if dx == 0 && dy == 0 {
						continue
					}
					if at(x+dx, y+dy) {
						neighbors++
					}
				}
			}
			if neighbors >= 2 {
				out.Pix[y*w+x] = 0
			} else {
				out.Pix[y*w+x] = 255
			}
		}
	}
	return out
}

// upscaleNearest scales the image by an integer factor (tesseract reads small
// captcha text much better at 3-4x).
func upscaleNearest(src image.Image, factor int) *image.Gray {
	if factor < 1 {
		factor = 1
	}
	b := src.Bounds()
	w, h := b.Dx()*factor, b.Dy()*factor
	out := image.NewGray(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		sy := b.Min.Y + y/factor
		for x := 0; x < w; x++ {
			sx := b.Min.X + x/factor
			r, g, bl, _ := src.At(sx, sy).RGBA()
			lum := (299*r + 587*g + 114*bl) / 1000
			out.SetGray(x, y, color.Gray{Y: uint8(lum >> 8)})
		}
	}
	return out
}

// invert flips a binarized image (some captcha styles render light-on-dark).
func invert(g *image.Gray) *image.Gray {
	out := image.NewGray(g.Bounds())
	for i, p := range g.Pix {
		if p == 0 {
			out.Pix[i] = 255
		} else {
			out.Pix[i] = 0
		}
	}
	return out
}

// buildVariants produces the preprocessing variants to OCR.
func buildVariants(src image.Image, maxVariants int) []struct {
	name string
	img  image.Image
} {
	gray := toGray(src)
	bin := otsuThreshold(gray)
	clean := despeckle(bin)
	variants := []struct {
		name string
		img  image.Image
	}{
		{"gray", gray},
		{"otsu", bin},
		{"otsu_despeckle", clean},
		{"otsu_x3", upscaleNearest(bin, 3)},
		{"otsu_despeckle_x4", upscaleNearest(clean, 4)},
		{"otsu_invert", invert(bin)},
	}
	if maxVariants > 0 && maxVariants < len(variants) {
		variants = variants[:maxVariants]
	}
	return variants
}

// sanitizeOCRText keeps only characters allowed in a captcha answer.
func sanitizeOCRText(raw, whitelist string) string {
	if whitelist == "" {
		whitelist = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	}
	var b strings.Builder
	for _, r := range raw {
		if strings.ContainsRune(whitelist, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// rankCandidates votes across all tesseract outputs. Plausible captcha lengths
// (3-8 chars) get the highest weight so frequent-but-garbage long readings
// can't dominate.
func rankCandidates(counts map[string]int, max int) []string {
	type scored struct {
		text  string
		score float64
	}
	weight := func(l int) float64 {
		switch {
		case l >= 3 && l <= 8:
			return 10
		case l == 2 || l == 9 || l == 10:
			return 4
		default:
			return 1
		}
	}
	out := make([]scored, 0, len(counts))
	for text, n := range counts {
		out = append(out, scored{text, float64(n) * weight(len(text))})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].score != out[j].score {
			return out[i].score > out[j].score
		}
		return out[i].text < out[j].text
	})
	if max <= 0 {
		max = 8
	}
	res := make([]string, 0, len(out))
	for _, s := range out {
		res = append(res, s.text)
		if len(res) >= max {
			break
		}
	}
	return res
}

// SolveImageCaptcha runs the full local OCR pipeline over one captcha image.
func SolveImageCaptcha(ctx context.Context, img []byte, req OCRRequest) (OCRResult, error) {
	res := OCRResult{Engine: "tesseract"}
	bin := TesseractPath()
	if bin == "" {
		return res, errors.New("tesseract is not installed (apt-get install -y tesseract-ocr)")
	}
	src, _, err := image.Decode(bytes.NewReader(img))
	if err != nil {
		return res, fmt.Errorf("decode captcha image: %w", err)
	}
	if req.CharWhitelist == "" {
		req.CharWhitelist = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	}
	if req.Language == "" {
		req.Language = "eng"
	}
	psms := req.PSMs
	if len(psms) == 0 {
		psms = defaultPSMs
	}

	variants := buildVariants(src, req.MaxVariants)
	counts := map[string]int{}
	tmp, err := os.CreateTemp("", "behemoth-captcha-*.png")
	if err != nil {
		return res, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	for _, v := range variants {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		var buf bytes.Buffer
		if err := png.Encode(&buf, v.img); err != nil {
			continue
		}
		if err := tmp.Truncate(0); err != nil {
			return res, err
		}
		if _, err := tmp.Seek(0, 0); err != nil {
			return res, err
		}
		if _, err := tmp.Write(buf.Bytes()); err != nil {
			return res, err
		}
		for _, psm := range psms {
			cctx, cancel := context.WithTimeout(ctx, tesseractTimeout)
			cmd := exec.CommandContext(cctx, bin, tmpName, "stdout",
				"--psm", fmt.Sprint(psm), "-l", req.Language,
				"-c", "tessedit_char_whitelist="+req.CharWhitelist)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()
			cancel()
			text := sanitizeOCRText(stdout.String(), req.CharWhitelist)
			if err != nil && text == "" {
				continue
			}
			if text == "" || len(text) > 14 {
				continue
			}
			res.Attempts = append(res.Attempts, OCRAttempt{Variant: v.name, PSM: psm, Text: text})
			counts[text]++
		}
	}
	_ = tmp.Close()

	res.Candidates = rankCandidates(counts, req.MaxCandidates)
	if len(res.Candidates) == 0 {
		res.Error = "ocr produced no readable candidates"
		return res, nil
	}
	res.Best = res.Candidates[0]
	return res, nil
}
