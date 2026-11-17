package browser

import (
	"fmt"
	"regexp"
	"strings"
)

// htmlToMarkdown converts HTML content to simplified markdown.
// This is a basic implementation - for production, use a proper library.
func htmlToMarkdown(html string) string {
	// Remove script and style blocks
	reScript := regexp.MustCompile(`(?si)<script[^>]*>.*?</script>`)
	html = reScript.ReplaceAllString(html, "")
	reStyle := regexp.MustCompile(`(?si)<style[^>]*>.*?</style>`)
	html = reStyle.ReplaceAllString(html, "")

	// Convert headers
	for i := 6; i >= 1; i-- {
		pattern := fmt.Sprintf(`(?si)<h%d[^>]*>(.*?)</h%d>`, i, i)
		re := regexp.MustCompile(pattern)
		prefix := strings.Repeat("#", i)
		html = re.ReplaceAllStringFunc(html, func(m string) string {
			content := stripTags(m)
			return prefix + " " + content + "\n\n"
		})
	}

	// Convert paragraphs
	reP := regexp.MustCompile(`(?si)<p[^>]*>(.*?)</p>`)
	html = reP.ReplaceAllStringFunc(html, func(m string) string {
		content := stripTags(m)
		return content + "\n\n"
	})

	// Convert links
	reA := regexp.MustCompile(`<a[^>]*href="([^"]*)"[^>]*>(.*?)</a>`)
	html = reA.ReplaceAllStringFunc(html, func(m string) string {
		submatches := reA.FindStringSubmatch(m)
		if len(submatches) >= 3 {
			return fmt.Sprintf("[%s](%s)", submatches[2], submatches[1])
		}
		return m
	})

	// Convert bold/italic
	html = regexp.MustCompile(`<(?:strong|b)[^>]*>(.*?)</(?:strong|b)>`).ReplaceAllString(html, "**$1**")
	html = regexp.MustCompile(`<(?:em|i)[^>]*>(.*?)</(?:em|i)>`).ReplaceAllString(html, "*$1*")

	// Convert lists
	html = regexp.MustCompile(`<li[^>]*>(.*?)</li>`).ReplaceAllString(html, "- $1\n")

	// Remove remaining tags
	html = stripTags(html)

	// Clean up whitespace
	html = regexp.MustCompile(`\n{3,}`).ReplaceAllString(html, "\n\n")
	html = strings.TrimSpace(html)

	return html
}

// stripTags removes all HTML tags from a string.
func stripTags(s string) string {
	re := regexp.MustCompile(`<[^>]+>`)
	s = re.ReplaceAllString(s, "")
	// Decode common entities
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&quot;", "\"")
	return s
}

// extractTitle extracts a title from URL.
func extractTitle(url string) string {
	// Try to get hostname as title
	if strings.Contains(url, "://") {
		parts := strings.Split(url, "://")
		if len(parts) > 1 {
			host := parts[1]
			if idx := strings.Index(host, "/"); idx != -1 {
				host = host[:idx]
			}
			return host
		}
	}
	return url
}

// sanitizeFilename creates a safe filename from URL.
func sanitizeFilename(rawURL string) string {
	// Extract hostname and path
	name := rawURL
	if strings.Contains(name, "://") {
		parts := strings.Split(name, "://")
		if len(parts) > 1 {
			name = parts[1]
		}
	}

	// Replace unsafe characters
	replacer := strings.NewReplacer(
		"/", "_",
		":", "_",
		"?", "_",
		"&", "_",
		"=", "_",
		"%", "_",
		".", "_",
	)
	name = replacer.Replace(name)

	// Truncate if too long
	if len(name) > 100 {
		name = name[:100]
	}

	return name
}

// getExtension returns file extension from URL.
func getExtension(rawURL string) string {
	url := rawURL
	if idx := strings.Index(url, "?"); idx != -1 {
		url = url[:idx]
	}
	if idx := strings.LastIndex(url, "."); idx != -1 {
		return url[idx:]
	}
	return ""
}