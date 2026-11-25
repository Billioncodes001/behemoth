//go:build embedui

package server

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// webuiDist holds the statically-exported frontend (built with
// `cd web && npm run build:static`, then copied into server/webui/dist). Compiled
// into the binary only when building with `-tags embedui`. The `all:` prefix is
// required so Next's `_next/` asset dir (leading underscore) is included.
//
//go:embed all:webui/dist
var webuiDist embed.FS

type cachedEmbeddedAsset struct {
	raw     []byte
	gz      []byte
	ctype   string
	etag    string
	modUnix int64
	size    int64
}

var webuiAssetCache sync.Map // map[string]*cachedEmbeddedAsset

// ClearWebUICache flushes the in-memory compressed asset cache after a live
// frontend hot-reload updates server/webui/dist on disk without restarting.
func ClearWebUICache() {
	webuiAssetCache.Range(func(k, _ any) bool {
		webuiAssetCache.Delete(k)
		return true
	})
}

func shouldPrecompressAsset(ext string, size int) bool {
	if size < 256 {
		return false
	}
	switch ext {
	case ".js", ".mjs", ".css", ".html", ".txt", ".json", ".svg", ".xml", ".ico", ".map":
		return true
	default:
		return false
	}
}

func detectAssetContentType(name string, raw []byte) string {
	ext := strings.ToLower(path.Ext(name))
	switch ext {
	case ".js", ".mjs":
		return "application/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".html":
		return "text/html; charset=utf-8"
	case ".txt":
		return "text/plain; charset=utf-8"
	case ".json":
		return "application/json; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".woff2":
		return "font/woff2"
	case ".png":
		return "image/png"
	case ".ico":
		return "image/x-icon"
	}
	if ct := mime.TypeByExtension(ext); ct != "" {
		return ct
	}
	return http.DetectContentType(raw)
}

func buildCachedWebAsset(name string, raw []byte, modUnix, size int64) *cachedEmbeddedAsset {
	sum := sha256.Sum256(raw)
	entry := &cachedEmbeddedAsset{
		raw:     raw,
		ctype:   detectAssetContentType(name, raw),
		etag:    `"` + hex.EncodeToString(sum[:8]) + `"`,
		modUnix: modUnix,
		size:    size,
	}
	if shouldPrecompressAsset(strings.ToLower(path.Ext(name)), len(raw)) {
		var buf bytes.Buffer
		zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		if err == nil {
			if _, werr := zw.Write(raw); werr == nil && zw.Close() == nil && buf.Len() < len(raw) {
				entry.gz = buf.Bytes()
			}
		}
	}
	return entry
}

// loadLiveDiskWebAsset checks server/webui/dist on disk first so frontend-only
// Git updates hot-reload in place without restarting the backend process.
func loadLiveDiskWebAsset(name string) (*cachedEmbeddedAsset, bool) {
	cleanRel := filepath.FromSlash(strings.TrimPrefix(path.Clean("/"+name), "/"))
	if cleanRel == "" || cleanRel == "." || strings.Contains(cleanRel, "..") {
		return nil, false
	}
	diskPath := filepath.Join("server", "webui", "dist", cleanRel)
	st, err := os.Stat(diskPath)
	if err != nil || st.IsDir() {
		return nil, false
	}
	cacheKey := "disk:" + name
	modNano := st.ModTime().UnixNano()
	sz := st.Size()
	if v, ok := webuiAssetCache.Load(cacheKey); ok {
		cached := v.(*cachedEmbeddedAsset)
		if cached.modUnix == modNano && cached.size == sz {
			return cached, true
		}
	}
	raw, err := os.ReadFile(diskPath)
	if err != nil {
		return nil, false
	}
	entry := buildCachedWebAsset(name, raw, modNano, sz)
	webuiAssetCache.Store(cacheKey, entry)
	return entry, true
}

func loadEmbeddedAsset(fsys fs.FS, name string) (*cachedEmbeddedAsset, bool) {
	if live, ok := loadLiveDiskWebAsset(name); ok {
		return live, true
	}
	cacheKey := "embed:" + name
	if v, ok := webuiAssetCache.Load(cacheKey); ok {
		return v.(*cachedEmbeddedAsset), true
	}
	f, err := fsys.Open(name)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		return nil, false
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, false
	}
	entry := buildCachedWebAsset(name, raw, 0, st.Size())
	actual, _ := webuiAssetCache.LoadOrStore(cacheKey, entry)
	return actual.(*cachedEmbeddedAsset), true
}

// webuiHandler serves the embedded SPA with in-memory gzip precompression,
// ETag conditional GETs, and immutable browser caching for hashed static bundles.
func (s *Server) webuiHandler() http.Handler {
	root, err := fs.Sub(webuiDist, "webui/dist")
	if err != nil {
		panic(err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" || p == "." {
			p = "index.html"
		}
		gated := s.basicAuth.snapshot().Enabled
		for _, cand := range []string{p, p + "/index.html", p + ".html"} {
			if serveEmbeddedAsset(w, r, root, cand, gated) {
				return
			}
		}
		_ = serveEmbeddedAsset(w, r, root, "index.html", gated)
	})
}

func setStaticCacheHeaders(w http.ResponseWriter, name string, gated bool) {
	// Respect explicit Cache-Control: no-store if already set by outer auth middleware
	// (e.g. initial Set-Cookie response or HTML document behind Basic Auth).
	if w.Header().Get("Cache-Control") != "" {
		return
	}
	scope := "public"
	if gated {
		scope = "private"
	}
	switch {
	case strings.HasPrefix(name, "_next/static/"):
		w.Header().Set("Cache-Control", scope+", max-age=31536000, immutable")
	case strings.HasSuffix(name, ".woff2"), strings.HasSuffix(name, ".png"), strings.HasSuffix(name, ".ico"), strings.HasSuffix(name, ".svg"):
		w.Header().Set("Cache-Control", scope+", max-age=86400, stale-while-revalidate=604800")
	case strings.HasSuffix(name, ".txt"):
		// Next.js App Router RSC flight payloads carry a build-specific ?_rsc= query.
		w.Header().Set("Cache-Control", "private, max-age=300, stale-while-revalidate=3600")
	default:
		w.Header().Set("Cache-Control", "private, no-cache")
	}
}

func etagMatches(ifNoneMatch, etag string) bool {
	if ifNoneMatch == "" || etag == "" {
		return false
	}
	for _, item := range strings.Split(ifNoneMatch, ",") {
		cand := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(item), "W/"))
		if cand == "*" || cand == etag {
			return true
		}
	}
	return false
}

func serveEmbeddedAsset(w http.ResponseWriter, r *http.Request, fsys fs.FS, name string, gated bool) bool {
	entry, ok := loadEmbeddedAsset(fsys, name)
	if !ok {
		return false
	}
	setStaticCacheHeaders(w, name, gated)
	w.Header().Set("ETag", entry.etag)
	if len(entry.gz) > 0 {
		w.Header().Add("Vary", "Accept-Encoding")
	}
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && etagMatches(r.Header.Get("If-None-Match"), entry.etag) {
		w.WriteHeader(http.StatusNotModified)
		return true
	}
	if len(entry.gz) > 0 && requestAcceptsGzip(r) {
		w.Header().Set("Content-Type", entry.ctype)
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(entry.gz)))
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(entry.gz)
		}
		return true
	}
	w.Header().Set("Content-Type", entry.ctype)
	http.ServeContent(w, r, path.Base(name), time.Time{}, bytes.NewReader(entry.raw))
	return true
}
