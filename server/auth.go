package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash"
	jwtTTL         = 7 * 24 * time.Hour
	keyChars       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// 下限与 setup 页的前端校验一致——校验只放在前端等于没放，直接打 API 就能
	// 绕过。上限是 bcrypt 的硬限制：超过 72 字节 GenerateFromPassword 会返回
	// ErrPasswordTooLong，提前挡掉好过让用户收到一句含义不明的「密码加密失败」。
	minPasswordRunes = 8
	maxPasswordBytes = 72
)

// errDataSourceUnavailable 是密码相关读操作失败时统一的回复。这些 handler 绝不能
// 把"读不到"当成"没有设置"：authInit 曾因此在数据库报错时放行，让未认证请求覆盖
// 掉已有的管理员密码。
const errDataSourceUnavailable = "The data source is temporarily unavailable. Try again later."

// validatePassword returns an empty string on success or an English fallback message.
func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("Password must contain at least %d characters", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("Password must not exceed %d bytes", maxPasswordBytes)
	}
	return ""
}

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// the project base dir (next to the executable), NOT the browsable workspace root
// (dataDir) — the signing key must never be listable/downloadable via the file
// manager. Legacy installs kept it at dataDir/jwt.key; if present there and not yet
// at the new location, it is migrated (key preserved, so sessions stay valid) and
// the old file removed so it disappears from the workspace. On first run a random
// key is generated and persisted.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	path := filepath.Join(keyDir, jwtKeyFilename)
	// one-time migration out of the old in-workspace location.
	if legacy := filepath.Join(dataDir, jwtKeyFilename); legacy != path {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if data, rerr := os.ReadFile(legacy); rerr == nil {
				if werr := os.WriteFile(path, data, 0o600); werr == nil {
					_ = os.Remove(legacy)
					log.Printf("[auth] Migrated JWT key from %s to %s (outside the browsable workspace)", legacy, path)
				}
			}
		}
	}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] Wrote new JWT key to %s", path)
	return buf, nil
}

// signJWT issues a 7-day HS256 token for user BEHEMOTH.
func signJWT(key []byte) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   "BEHEMOTH",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}).SignedString(key)
}

// verifyJWT returns true when tokenStr is a valid, non-expired HS256 token.
//
// The algorithm is pinned: a bare *jwt.SigningMethodHMAC check also accepts
// HS384/HS512, so a token re-signed with the leaked key under another HMAC
// variant would pass while nothing else in the system ever issues one. Pinning
// keeps exactly one accepted shape.
func verifyJWT(tokenStr string, key []byte) bool {
	tokenStr = strings.TrimSpace(tokenStr)
	if tokenStr == "" || len(key) == 0 {
		return false
	}
	t, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	return err == nil && t.Valid
}

// loginLockout is the shared brute-force answer for auth handlers under
// /api/auth/*, which securityMiddleware's generic rate limiter never sees.
// It writes 429 + Retry-After and reports true when the caller must stop.
func (s *Server) loginLockout(w http.ResponseWriter, r *http.Request, key string) bool {
	wait := s.loginGuard.retryAfter(key)
	if wait <= 0 {
		return false
	}
	secs := int(wait.Seconds())
	if secs < 1 {
		secs = 1
	}
	log.Printf("[auth] login rate limited: ip=%s retry_after=%ds", getClientIP(r), secs)
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeProductError(w, http.StatusTooManyRequests, "too_many_attempts",
		"Too many failed attempts. Try again later.", map[string]any{"retry_after": secs})
	return true
}

// noteLoginFailure records a wrong credential and logs the lockout that starts.
func (s *Server) noteLoginFailure(r *http.Request, key string) {
	if wait := s.loginGuard.fail(key); wait > 0 {
		log.Printf("[auth] too many failed logins: ip=%s locked for %ds", getClientIP(r), int(wait.Seconds()))
	}
}

// extractToken reads the JWT from Authorization: Bearer header,
// behemoth_token cookie, or ?token= query param (for SSE connections).
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("behemoth_token"); err == nil && c.Value != "" {
		return c.Value
	}
	if c, err := r.Cookie("artex_token"); err == nil && c.Value != "" {
		return c.Value
	}
	return r.URL.Query().Get("token")
}

// requireAuth wraps h with JWT validation.
// /api/auth/*, /api/health and the Basic Auth gate check are exempt.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || strings.HasPrefix(p, "/api/oast-cb/") || strings.HasPrefix(p, "/api/c2/") || strings.HasPrefix(p, "/c2/ui/") || p == "/api/health" || p == "/api/branding" || p == "/api/basic-auth/check" || p == "/api/update/maintenance" || p == "/api/update/webhook" {
			h.ServeHTTP(w, r)
			return
		}
		tok := extractToken(r)
		if tok == "" {
			writeProductError(w, 401, "unauthorized", "Unauthorized", nil)
			return
		}
		if !verifyJWT(tok, s.jwtKey) {
			writeProductError(w, 401, "token_expired", "Your sign-in token is invalid or expired", nil)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// verifyTurnstileSecretKey checks a Cloudflare Turnstile secret key against Cloudflare's
// siteverify endpoint using a synthetic probe token. Cloudflare returns "invalid-input-secret"
// when the secret key itself is invalid, whereas a valid secret key returns either success=true
// (for official test keys) or "invalid-input-response" (confirming the secret key was accepted).
func verifyTurnstileSecretKey(secretKey string) error {
	secretKey = strings.TrimSpace(secretKey)
	if secretKey == "" {
		return fmt.Errorf("Turnstile secret key is empty")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	form := url.Values{
		"secret":   {secretKey},
		"response": {"behemoth-secret-key-validation-probe"},
	}
	resp, err := client.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify", form)
	if err != nil {
		return fmt.Errorf("failed to reach Cloudflare siteverify endpoint to verify key: %w", err)
	}
	defer resp.Body.Close()

	var out struct {
		Success    bool     `json:"success"`
		ErrorCodes []string `json:"error-codes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("unexpected response from Cloudflare siteverify: %w", err)
	}
	for _, code := range out.ErrorCodes {
		if code == "invalid-input-secret" || code == "missing-input-secret" {
			return fmt.Errorf("Cloudflare rejected the Turnstile Secret Key (%s)", code)
		}
	}
	return nil
}

// turnstileConfig is the single source of truth for Cloudflare Turnstile settings.
// If environment variables are set and the database has no stored value yet, it
// seeds them into PostgreSQL so the Settings UI, /api/auth/status, and
// /api/auth/turnstile-verify always see the exact same state.
func (s *Server) turnstileConfig() (enabled bool, siteKey string, secretKey string, verified bool) {
	if s == nil || s.m == nil || s.m.pg == nil {
		sk := strings.TrimSpace(os.Getenv("CLOUDFLARE_TURNSTILE_SITE_KEY"))
		sec := strings.TrimSpace(os.Getenv("CLOUDFLARE_TURNSTILE_SECRET_KEY"))
		return true, sk, sec, sk != "" && sec != ""
	}
	pg := s.m.pg
	enabled = pg.GetBool("turnstile_enabled", true)
	siteVal, siteOk, _ := pg.GetSetting("turnstile_site_key")
	if !siteOk && strings.TrimSpace(os.Getenv("CLOUDFLARE_TURNSTILE_SITE_KEY")) != "" {
		siteVal = strings.TrimSpace(os.Getenv("CLOUDFLARE_TURNSTILE_SITE_KEY"))
		_ = pg.SetSetting("turnstile_site_key", siteVal)
	}
	secVal, secOk, _ := pg.GetSetting("turnstile_secret_key")
	if !secOk && strings.TrimSpace(os.Getenv("CLOUDFLARE_TURNSTILE_SECRET_KEY")) != "" {
		secVal = strings.TrimSpace(os.Getenv("CLOUDFLARE_TURNSTILE_SECRET_KEY"))
		_ = pg.SetSetting("turnstile_secret_key", secVal)
	}
	siteKey = strings.TrimSpace(siteVal)
	secretKey = strings.TrimSpace(secVal)
	if siteKey != "" && secretKey != "" {
		vFlag, vSet, _ := pg.GetSetting("turnstile_keys_verified")
		if vSet {
			verified = vFlag == "true"
		} else {
			// Verify pre-existing keys once and cache the result in PostgreSQL.
			if verifyTurnstileSecretKey(secretKey) == nil {
				verified = true
				_ = pg.SetSetting("turnstile_keys_verified", "true")
			} else {
				_ = pg.SetSetting("turnstile_keys_verified", "false")
			}
		}
	}
	return enabled, siteKey, secretKey, verified
}

// GET /api/auth/status — reports whether the admin password has been initialised
// and returns optional Cloudflare Turnstile configuration.
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	hash, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeProductError(w, 503, "data_unavailable", errDataSourceUnavailable, nil)
		return
	}
	turnstileEnabled, siteKey, secretKey, verified := s.turnstileConfig()
	activeSiteKey := ""
	if verified {
		activeSiteKey = siteKey
	}
	writeJSON(w, 200, map[string]any{
		"initialized":              hash != "",
		"turnstile_enabled":        turnstileEnabled,
		"turnstile_site_key":       activeSiteKey,
		"turnstile_secret_key_set": secretKey != "",
		"turnstile_verified":       verified,
	})
}

// POST /api/auth/turnstile-verify — verifies a Cloudflare Turnstile token (when
// verified Turnstile keys are configured) or validates the built-in automatic gate
// ONLY when Cloudflare keys have not been configured.
func (s *Server) authTurnstileVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token     string `json:"token"`
		UserAgent string `json:"user_agent"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	_, _, secretKey, verified := s.turnstileConfig()
	if verified && secretKey != "" {
		tok := strings.TrimSpace(req.Token)
		if tok == "" || tok == "auto-verified" {
			writeProductError(w, 403, "turnstile_failed", "Cloudflare Turnstile challenge token is required", nil)
			return
		}
		form := url.Values{
			"secret":   {secretKey},
			"response": {tok},
			"remoteip": {getClientIP(r)},
		}
		resp, err := http.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify", form)
		if err != nil {
			writeProductError(w, 502, "turnstile_unreachable", "Failed to contact Cloudflare Turnstile verification service", nil)
			return
		}
		defer resp.Body.Close()
		var out struct {
			Success bool `json:"success"`
		}
		if json.NewDecoder(resp.Body).Decode(&out) != nil || !out.Success {
			writeProductError(w, 403, "turnstile_failed", "Cloudflare Turnstile verification failed", nil)
			return
		}
	}

	writeJSON(w, 200, map[string]any{
		"verified": true,
		"ray_id":   fmt.Sprintf("%x", time.Now().UnixNano()&0xffffffffffff),
	})
}

// POST /api/auth/init — sets the password for the first time; rejected if already set.
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	existing, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeProductError(w, 503, "data_unavailable", errDataSourceUnavailable, nil)
		return
	}
	if existing != "" {
		writeProductError(w, 403, "password_already_set", "A password has already been set", nil)
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil || req.Password == "" {
		writeProductError(w, 400, "password_required", "Password is required", nil)
		return
	}
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
	// 用 INSERT ... ON CONFLICT DO NOTHING 而不是 upsert：上面那次 GetSetting 只是
	// 快速失败路径，真正"仅首次可设"的保证落在主键约束上。bcrypt 要跑几十毫秒，
	// 这期间别的请求完全可能先把密码设好，而读检查本身也可能因故障而失效。
	inserted, err := pg.InsertSettingIfAbsent(authPassKey, string(hash))
	if err != nil {
		writeProductError(w, 500, "save_failed", "Unable to save changes: "+err.Error(), nil)
		return
	}
	if !inserted {
		writeProductError(w, 403, "password_already_set", "A password has already been set", nil)
		return
	}
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		writeProductError(w, 500, "token_failed", "Unable to create a sign-in token", nil)
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}

// POST /api/auth/change-password — changes the admin password. Requires a valid
// token (this route is under /api/auth/* which requireAuth exempts, so the token
// is validated here) AND the current password.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if !verifyJWT(extractToken(r), s.jwtKey) {
		writeProductError(w, 401, "unauthorized", "Unauthorized", nil)
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		writeProductError(w, 400, "invalid_request", "Invalid request format", nil)
		return
	}
	if req.NewPassword == "" {
		writeProductError(w, 400, "new_password_required", "New password is required", nil)
		return
	}
	// A valid token proves session ownership, not knowledge of the old password:
	// brute-forcing that bcrypt compare through a stolen token gets its own
	// namespace so it cannot lock the login flow out.
	limitKey := "chg:" + getClientIP(r)
	if s.loginLockout(w, r, limitKey) {
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		code, params := passwordValidationCode(req.NewPassword)
		writeProductError(w, 400, code, msg, params)
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeProductError(w, 503, "data_unavailable", errDataSourceUnavailable, nil)
		return
	}
	if !ok || hash == "" {
		writeProductError(w, 403, "password_not_initialized", "Set up a password first", nil)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)); err != nil {
		s.noteLoginFailure(r, limitKey)
		writeProductError(w, 401, "current_password_incorrect", "The current password is incorrect", nil)
		return
	}
	s.loginGuard.reset(limitKey)
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeProductError(w, 500, "password_hash_failed", "Unable to secure the password", nil)
		return
	}
	if err := pg.SetSetting(authPassKey, string(newHash)); err != nil {
		writeProductError(w, 500, "save_failed", "Unable to save changes: "+err.Error(), nil)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/auth/login — validates username/password and returns a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeProductError(w, 400, "invalid_request", "Invalid request format", nil)
		return
	}
	// Throttle on the client IP: /api/auth/* bypasses securityMiddleware, so
	// nothing else rate-limits the bcrypt guesses below.
	ip := getClientIP(r)
	if s.loginLockout(w, r, ip) {
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.Username), []byte("BEHEMOTH")) != 1 {
		s.noteLoginFailure(r, ip)
		writeProductError(w, 401, "invalid_credentials", "Incorrect username or password", nil)
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeProductError(w, 503, "data_unavailable", errDataSourceUnavailable, nil)
		return
	}
	if !ok || hash == "" {
		writeProductError(w, 403, "password_not_initialized", "Set up a password first", nil)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		s.noteLoginFailure(r, ip)
		writeProductError(w, 401, "invalid_credentials", "Incorrect username or password", nil)
		return
	}
	s.loginGuard.reset(ip)
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		writeProductError(w, 500, "token_failed", "Unable to create a sign-in token", nil)
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}

func passwordValidationCode(password string) (string, map[string]any) {
	if utf8.RuneCountInString(password) < minPasswordRunes {
		return "password_too_short", map[string]any{"min": minPasswordRunes}
	}
	return "password_too_long", map[string]any{"max": maxPasswordBytes}
}
