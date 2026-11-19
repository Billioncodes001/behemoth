package server

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"
)

const minAPIGzipBytes = 512

var apiGzipPool = sync.Pool{
	New: func() any {
		zw, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
		return zw
	},
}

func isCompressibleAPIContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if strings.HasPrefix(ct, "text/event-stream") {
		return false
	}
	return strings.HasPrefix(ct, "application/json") ||
		strings.HasPrefix(ct, "text/") ||
		strings.HasPrefix(ct, "application/javascript") ||
		strings.HasPrefix(ct, "application/xml")
}

type apiGzipResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	decided     bool
	compressing bool
	buf         []byte
	zw          *gzip.Writer
}

func (g *apiGzipResponseWriter) Unwrap() http.ResponseWriter {
	return g.ResponseWriter
}

func (g *apiGzipResponseWriter) WriteHeader(code int) {
	if g.wroteHeader {
		return
	}
	g.status = code
	g.wroteHeader = true
	// Defer emitting wire headers until we know whether the body exceeds
	// minAPIGzipBytes, except for header-only / streaming status codes.
	if code == http.StatusNoContent || code == http.StatusNotModified || code < 200 ||
		strings.HasPrefix(strings.ToLower(g.Header().Get("Content-Type")), "text/event-stream") {
		g.decided = true
		g.ResponseWriter.WriteHeader(code)
	}
}

func (g *apiGzipResponseWriter) commit(useGzip bool) {
	if g.decided {
		return
	}
	g.decided = true
	if g.status == 0 {
		g.status = http.StatusOK
	}
	if useGzip && g.Header().Get("Content-Encoding") == "" && isCompressibleAPIContentType(g.Header().Get("Content-Type")) {
		g.compressing = true
		g.Header().Del("Content-Length")
		g.Header().Set("Content-Encoding", "gzip")
		g.Header().Add("Vary", "Accept-Encoding")
		zw := apiGzipPool.Get().(*gzip.Writer)
		zw.Reset(g.ResponseWriter)
		g.zw = zw
	}
	g.ResponseWriter.WriteHeader(g.status)
	if len(g.buf) > 0 {
		if g.compressing {
			_, _ = g.zw.Write(g.buf)
		} else {
			_, _ = g.ResponseWriter.Write(g.buf)
		}
		g.buf = nil
	}
}

func (g *apiGzipResponseWriter) Write(p []byte) (int, error) {
	if !g.wroteHeader {
		if g.Header().Get("Content-Type") == "" {
			g.Header().Set("Content-Type", http.DetectContentType(p))
		}
		g.WriteHeader(http.StatusOK)
	}
	if !g.decided {
		if g.Header().Get("Content-Encoding") != "" || !isCompressibleAPIContentType(g.Header().Get("Content-Type")) {
			g.commit(false)
			return g.ResponseWriter.Write(p)
		}
		if len(g.buf)+len(p) < minAPIGzipBytes {
			g.buf = append(g.buf, p...)
			return len(p), nil
		}
		g.commit(true)
	}
	if g.compressing {
		return g.zw.Write(p)
	}
	return g.ResponseWriter.Write(p)
}

func (g *apiGzipResponseWriter) Flush() {
	if !g.decided {
		g.commit(len(g.buf) >= minAPIGzipBytes)
	}
	if g.compressing && g.zw != nil {
		_ = g.zw.Flush()
	}
	if fl, ok := g.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

func (g *apiGzipResponseWriter) finish() {
	if !g.decided {
		if g.wroteHeader || len(g.buf) > 0 {
			g.commit(len(g.buf) >= minAPIGzipBytes)
		}
	}
	if g.zw != nil {
		_ = g.zw.Close()
		g.zw.Reset(io.Discard)
		apiGzipPool.Put(g.zw)
		g.zw = nil
	}
}

func requestAcceptsGzip(r *http.Request) bool {
	if r.Header.Get("Range") != "" {
		return false
	}
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		enc, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if strings.EqualFold(strings.TrimSpace(enc), "gzip") {
			lp := strings.ToLower(params)
			if strings.Contains(lp, "q=0") && !strings.Contains(lp, "q=0.") {
				return false
			}
			return true
		}
	}
	return false
}

// gzipAPI transparently compresses JSON/text API responses >= 512 bytes when the
// client advertises Accept-Encoding: gzip, skipping SSE streams and binary archives.
func gzipAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead || r.Method == http.MethodOptions ||
			r.Header.Get("Upgrade") != "" ||
			strings.HasSuffix(r.URL.Path, "/stream") ||
			strings.HasSuffix(r.URL.Path, "/archive") ||
			strings.HasSuffix(r.URL.Path, "/download") ||
			strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream") ||
			!requestAcceptsGzip(r) {
			next.ServeHTTP(w, r)
			return
		}
		gw := &apiGzipResponseWriter{ResponseWriter: w}
		defer gw.finish()
		next.ServeHTTP(gw, r)
	})
}
