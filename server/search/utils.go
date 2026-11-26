package search

import (
	"bytes"
	"compress/gzip"
	"html"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// readResponseBytes reads up to maxBytes from an HTTP response, transparently
// decompressing gzip payloads even if an upstream server or proxy sends raw
// gzip bytes (`\x1f\x8b`) without Go's transport auto-gunzipping them.
func readResponseBytes(resp *http.Response, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 2 << 20
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return nil, err
	}
	isGzip := strings.Contains(strings.ToLower(resp.Header.Get("Content-Encoding")), "gzip") ||
		(len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b)
	if !isGzip {
		return raw, nil
	}
	zr, zerr := gzip.NewReader(bytes.NewReader(raw))
	if zerr != nil {
		return raw, nil
	}
	defer zr.Close()
	decoded, derr := io.ReadAll(io.LimitReader(zr, maxBytes*4))
	if derr != nil {
		return raw, nil
	}
	return decoded, nil
}

// cleanHTML removes HTML tags and unescapes HTML entities from a string.
func cleanHTML(s string) string {
	re := regexp.MustCompile(`<[^>]+>`)
	s = re.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	s = strings.Join(strings.Fields(s), " ")
	return s
}

// truncateString truncates a string to maxLen characters with ellipsis.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "... [truncated]"
}

// min returns the smaller of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// isBinaryURL checks if URL points to non-HTML content.
var binaryExtensions = map[string]bool{
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	".ppt": true, ".pptx": true, ".zip": true, ".tar": true, ".gz": true,
	".mp3": true, ".mp4": true, ".avi": true, ".mov": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".exe": true, ".bin": true, ".dmg": true, ".apk": true,
}

func isBinaryURL(rawURL string) bool {
	for ext := range binaryExtensions {
		if strings.HasSuffix(strings.ToLower(rawURL), ext) {
			return true
		}
	}
	return false
}
