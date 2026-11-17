package search

import (
	"html"
	"regexp"
	"strings"
)

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