package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Autumn-27/artex/server/fingerprint"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const basicAuthKey = "auth.http_basic"

// Dynamic cookie name - set at startup via fingerprint package
var basicAuthCookie = "artex_basic_auth" // will be overridden by InitializeDynamicNames()
const basicAuthTTL = 12 * time.Hour
const basicAuthSaveTimeout = 10 * time.Second

// Dynamic auth header name - set at startup
var dynamicAuthHeaderName = "X-Artex-Auth" // will be overridden

// InitializeDynamicNames sets dynamic names from fingerprint manager.
// Call once at server startup after fingerprint.Initialize().
func InitializeDynamicNames() {
	basicAuthCookie = fingerprint.GetDynamicCookieName()
	dynamicAuthHeaderName = fingerprint.GetDynamicAuthHeaderName()
}

type basicAuthConfig struct {
	Enabled      bool   `json:"enabled"`
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Revision     string `json:"revision"`
}

type basicAuthSettingsStore interface {
	GetSetting(string) (string, bool, error)
	SetSettingContext(context.Context, string, string) error
}

// Keep one atomic configuration in the DB and publish it only after a successful
// save. Requests use the in-memory snapshot, avoiding a DB read for every asset.
type basicAuthGate struct {
	saveMu sync.Mutex // serializes persistence without blocking request snapshots
	mu     sync.RWMutex
	cfg    basicAuthConfig
	store  basicAuthSettingsStore
}

func (g *basicAuthGate) load(store basicAuthSettingsStore) error {
	g.saveMu.Lock()
	defer g.saveMu.Unlock()
	raw, ok, err := store.GetSetting(basicAuthKey)
	if err != nil {
		return err
	}
	var cfg basicAuthConfig
	if ok {
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			return fmt.Errorf("invalid HTTP Basic Auth configuration")
		}
	}
	if cfg.Enabled {
		if !validBasicUsername(cfg.Username) || cfg.Revision == "" {
			return fmt.Errorf("incomplete HTTP Basic Auth configuration")
		}
		if _, err := bcrypt.Cost([]byte(cfg.PasswordHash)); err != nil {
			return fmt.Errorf("invalid HTTP Basic Auth password hash")
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cfg, g.store = cfg, store
	return nil
}

func (g *basicAuthGate) snapshot() basicAuthConfig {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.cfg
}

func validBasicUsername(username string) bool {
	return strings.TrimSpace(username) != "" && len(username) <= 128 &&
		!strings.Contains(username, ":") && strings.IndexFunc(username, unicode.IsControl) == -1
}

// A separate signing key prevents a gate cookie from being used as an admin JWT.
func (s *Server) basicAuthSigningKey() []byte {
	m := hmac.New(sha256.New, s.jwtKey)
	m.Write([]byte("artex/http-basic-auth/session/v1"))
	return m.Sum(nil)
}

func (s *Server) validBasicAuthCookie(r *http.Request, cfg basicAuthConfig) bool {
	cookie, err := r.Cookie(basicAuthCookie)
	if err != nil || cfg.Revision == "" {
		return false
	}
	claims := &jwt.RegisteredClaims{}
	_, err = jwt.ParseWithClaims(cookie.Value, claims, func(*jwt.Token) (any, error) {
		return s.basicAuthSigningKey(), nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired(),
		jwt.WithAudience("artex-basic-auth"), jwt.WithSubject(cfg.Revision))
	return err == nil
}

func (s *Server) setBasicAuthCookie(w http.ResponseWriter, r *http.Request, cfg basicAuthConfig) error {
	cookie := &http.Cookie{
		Name: basicAuthCookie, Path: "/", HttpOnly: true,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteStrictMode, MaxAge: -1,
	}
	if cfg.Enabled {
		now := time.Now()
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
			Subject: cfg.Revision, Audience: jwt.ClaimStrings{"artex-basic-auth"},
			IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(basicAuthTTL)),
		}).SignedString(s.basicAuthSigningKey())
		if err != nil {
			return err
		}
		cookie.Value, cookie.MaxAge = token, int(basicAuthTTL.Seconds())
	}
	http.SetCookie(w, cookie)
	return nil
}

func isBrowserCacheableAssetPath(p string) bool {
	if strings.HasPrefix(p, "/_next/static/") {
		return true
	}
	if strings.HasPrefix(p, "/api/") {
		return false
	}
	return strings.HasSuffix(p, ".txt") ||
		strings.HasSuffix(p, ".woff2") ||
		strings.HasSuffix(p, ".png") ||
		strings.HasSuffix(p, ".ico") ||
		strings.HasSuffix(p, ".svg")
}

func (s *Server) requireBasicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := s.basicAuth.snapshot()
		// CORS preflight contains no credentials; the API CORS handler returns
		// 204 without invoking any business handler, including health probes.
		if !cfg.Enabled || strings.HasPrefix(r.URL.Path, "/api/oast-cb/") || (r.Method == "OPTIONS" && strings.HasPrefix(r.URL.Path, "/api/")) {
			next.ServeHTTP(w, r)
			return
		}
		if s.validBasicAuthCookie(r, cfg) {
			// Allow authenticated browsers to cache content-hashed static bundles
			// privately in memory (never shared proxies), while keeping API & HTML uncached.
			if !isBrowserCacheableAssetPath(r.URL.Path) {
				w.Header().Set("Cache-Control", "no-store")
			}
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		username, password, ok := r.BasicAuth()
		if !ok || len(password) > maxPasswordBytes || username != cfg.Username ||
			bcrypt.CompareHashAndPassword([]byte(cfg.PasswordHash), []byte(password)) != nil {
			// Background requests use Bearer auth. Challenging them with Basic
			// can trap the browser in repeated native dialogs. Let the client
			// reload the current page once to renew only the outer session.
			w.Header().Set("X-Artex-Auth", "basic")
			if dynamicAuthHeaderName != "" && !strings.EqualFold(dynamicAuthHeaderName, "X-Artex-Auth") {
				w.Header().Set(dynamicAuthHeaderName, "basic")
			}
			if !strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api/basic-auth/check" || r.URL.Path == "/api/health" {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted", charset="UTF-8"`)
			}
			writeProductError(w, http.StatusUnauthorized, "basic_auth_required", "Complete HTTP Basic Auth verification first", nil)
			return
		}
		// Browser API requests already use Authorization: Bearer. A separate
		// HttpOnly cookie keeps the gate satisfied without replacing that header.
		if err := s.setBasicAuthCookie(w, r, cfg); err != nil {
			writeProductError(w, 500, "auth_session_failed", "Unable to create an authentication session", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func basicAuthPublicSettings(cfg basicAuthConfig) map[string]any {
	return map[string]any{"enabled": cfg.Enabled, "username": cfg.Username, "password_set": cfg.PasswordHash != ""}
}

func (s *Server) getBasicAuthSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, basicAuthPublicSettings(s.basicAuth.snapshot()))
}

func (s *Server) saveBasicAuthSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled  *bool   `json:"enabled"`
		Username *string `json:"username"`
		Password string  `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeProductError(w, 400, "invalid_request", "Invalid request format", nil)
		return
	}
	g := &s.basicAuth
	g.saveMu.Lock()
	defer g.saveMu.Unlock()
	g.mu.RLock()
	cfg, store := g.cfg, g.store
	g.mu.RUnlock()
	if store == nil {
		writeProductError(w, 503, "data_unavailable", errDataSourceUnavailable, nil)
		return
	}
	if req.Enabled != nil {
		cfg.Enabled = *req.Enabled
	}
	if req.Username != nil {
		cfg.Username = strings.TrimSpace(*req.Username)
	}
	if (cfg.Enabled || cfg.Username != "") && !validBasicUsername(cfg.Username) {
		writeProductError(w, 400, "basic_auth_username_invalid", "The Basic Auth username is required, must not exceed 128 bytes, and cannot contain colons or control characters", nil)
		return
	}
	if req.Password != "" {
		if msg := validatePassword(req.Password); msg != "" {
			code, params := passwordValidationCode(req.Password)
			writeProductError(w, 400, code, msg, params)
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			writeProductError(w, 500, "password_hash_failed", "Unable to secure the password", nil)
			return
		}
		cfg.PasswordHash = string(hash)
	}
	if cfg.Enabled && cfg.PasswordHash == "" {
		writeProductError(w, 400, "basic_auth_password_required", "Set a Basic Auth password first", nil)
		return
	}
	// Every save revokes previous gate cookies, including disable/re-enable.
	cfg.Revision = uuid.NewString()
	data, err := json.Marshal(cfg)
	ctx, cancel := context.WithTimeout(r.Context(), basicAuthSaveTimeout)
	defer cancel()
	if err != nil || store.SetSettingContext(ctx, basicAuthKey, string(data)) != nil {
		writeProductError(w, 503, "basic_auth_save_failed", "Could not save Basic Auth settings. Try again.", nil)
		return
	}
	// Hashing, persistence and response output never hold the request mutex.
	// Publish only committed settings; requests keep using the previous snapshot
	// until this short critical section completes.
	g.mu.Lock()
	g.cfg = cfg
	g.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	// Keep the administrator who just saved the settings in their session.
	if err := s.setBasicAuthCookie(w, r, cfg); err != nil {
		writeProductError(w, 500, "auth_session_failed", "Unable to create an authentication session", nil)
		return
	}
	writeJSON(w, 200, basicAuthPublicSettings(cfg))
}
