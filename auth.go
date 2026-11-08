package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookieName = "denims_session"
	sessionDuration   = 8 * time.Hour

	// Login throttling: after this many failures within loginWindow, further
	// attempts are rejected (HTTP 429) until the window ends. The per-username
	// limit is looser so that an attacker can't trivially lock the real admin
	// out, but still caps distributed guessing against one account.
	loginWindow          = 15 * time.Minute
	maxFailuresPerIP     = 5
	maxFailuresPerUser   = 20
	maxLoginUsernameKeyN = 64
)

// ── htpasswd helpers ─────────────────────────────────────────────────────────

// parseHTAccess reads an Apache-compatible htpasswd file and returns a map of
// username -> bcrypt hash. Lines beginning with '#' and empty lines are ignored.
func parseHTAccess(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening htaccess file: %w", err)
	}
	defer f.Close()

	users := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		users[parts[0]] = parts[1]
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading htaccess file: %w", err)
	}
	return users, nil
}

var (
	dummyHashOnce sync.Once
	dummyHash     []byte
)

// burnPasswordHash spends roughly one bcrypt comparison so that logins for
// unknown users take about as long as logins for known ones, which stops
// response timing from revealing which usernames exist.
func burnPasswordHash(password string) {
	dummyHashOnce.Do(func() {
		dummyHash, _ = bcrypt.GenerateFromPassword([]byte("denims-timing-dummy"), bcrypt.DefaultCost)
	})
	_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
}

// validateCredentials checks username/password against the .htaccess file.
func validateCredentials(htaccessPath, username, password string) bool {
	users, err := parseHTAccess(htaccessPath)
	if err != nil {
		burnPasswordHash(password)
		return false
	}
	hash, ok := users[username]
	// $2y$, $2a$, $2b$ are all handled by Go's bcrypt package
	if !ok || !strings.HasPrefix(hash, "$2") {
		burnPasswordHash(password)
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// AddHTAccessUser adds or updates a user entry in the .htaccess file.
func AddHTAccessUser(htaccessPath, username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}
	users, _ := parseHTAccess(htaccessPath)
	if users == nil {
		users = make(map[string]string)
	}
	users[username] = string(hash)
	return writeHTAccess(htaccessPath, users)
}

func writeHTAccess(path string, users map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	var sb strings.Builder
	sb.WriteString("# Denims htpasswd file — do not edit by hand while the service is running\n")
	for u, h := range users {
		sb.WriteString(u + ":" + h + "\n")
	}
	return os.WriteFile(path, []byte(sb.String()), 0640)
}

// ── JWT helpers ───────────────────────────────────────────────────────────────

type claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func issueSessionToken(username string, secret []byte) (string, error) {
	now := time.Now()
	c := claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(sessionDuration)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	return token.SignedString(secret)
}

func verifySessionToken(tokenStr string, secret []byte) (*claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	c, ok := token.Claims.(*claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	return c, nil
}

// ── Middleware & handlers ─────────────────────────────────────────────────────

// jwtMiddleware redirects unauthenticated requests to /login.
func jwtMiddleware(secret []byte, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Login/logout routes are always reachable
		if r.URL.Path == "/login" || r.URL.Path == "/logout" {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if _, err := verifySessionToken(cookie.Value, secret); err != nil {
			http.SetCookie(w, expiredCookie())
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// loginHandler handles GET (show form) and POST (validate + issue token).
func loginHandler(cfg *Config, secret []byte) http.HandlerFunc {
	ipLimiter := newFailureLimiter(maxFailuresPerIP, loginWindow)
	userLimiter := newFailureLimiter(maxFailuresPerUser, loginWindow)
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if err := tmplLogin.ExecuteTemplate(w, "login", map[string]string{"Error": ""}); err != nil {
				http.Error(w, "template error", http.StatusInternalServerError)
			}

		case http.MethodPost:
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			username := r.FormValue("username")
			password := r.FormValue("password")

			// Only the TCP peer address is used; X-Forwarded-For is client
			// controlled and would let an attacker dodge the limit.
			ipKey := clientIP(r)
			userKey := username
			if len(userKey) > maxLoginUsernameKeyN {
				userKey = userKey[:maxLoginUsernameKeyN]
			}
			for _, l := range []struct {
				lim *failureLimiter
				key string
			}{{ipLimiter, ipKey}, {userLimiter, userKey}} {
				if blocked, wait := l.lim.blocked(l.key); blocked {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
					w.WriteHeader(http.StatusTooManyRequests)
					_ = tmplLogin.ExecuteTemplate(w, "login", map[string]string{
						"Error": fmt.Sprintf("Too many failed sign-in attempts. Try again in %d minute(s).", int(wait.Minutes())+1),
					})
					return
				}
			}

			if !validateCredentials(cfg.HTAccessPath, username, password) {
				ipLimiter.fail(ipKey)
				userLimiter.fail(userKey)
				log.Printf("denims: failed login for %q from %s", username, ipKey)
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				_ = tmplLogin.ExecuteTemplate(w, "login", map[string]string{
					"Error": "Invalid username or password.",
				})
				return
			}

			ipLimiter.reset(ipKey)

			tokenStr, err := issueSessionToken(username, secret)
			if err != nil {
				http.Error(w, "session error", http.StatusInternalServerError)
				return
			}

			http.SetCookie(w, &http.Cookie{
				Name:     sessionCookieName,
				Value:    tokenStr,
				Path:     "/",
				MaxAge:   int(sessionDuration.Seconds()),
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			})
			http.Redirect(w, r, "/users", http.StatusSeeOther)

		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
}

// logoutHandler clears the session cookie and redirects to /login.
func logoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, expiredCookie())
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

// clientIP returns the host part of the connection's remote address.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func expiredCookie() *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}
