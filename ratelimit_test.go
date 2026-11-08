package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFailureLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newFailureLimiter(3, time.Minute)
	l.now = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		l.fail("a")
	}
	if b, _ := l.blocked("a"); b {
		t.Fatal("blocked before reaching max")
	}
	l.fail("a")
	if b, wait := l.blocked("a"); !b || wait <= 0 {
		t.Fatalf("not blocked at max (blocked=%v wait=%v)", b, wait)
	}
	if b, _ := l.blocked("other"); b {
		t.Fatal("unrelated key blocked")
	}

	now = now.Add(61 * time.Second)
	if b, _ := l.blocked("a"); b {
		t.Fatal("still blocked after window")
	}
	l.fail("a")
	if b, _ := l.blocked("a"); b {
		t.Fatal("count should restart after window expiry")
	}

	l.fail("b")
	l.reset("b")
	l.fail("b")
	l.fail("b")
	if b, _ := l.blocked("b"); b {
		t.Fatal("reset did not clear count")
	}
}

func TestLoginRateLimitHandler(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{HTAccessPath: filepath.Join(dir, ".htaccess")}
	if err := AddHTAccessUser(cfg.HTAccessPath, "admin", "right-password"); err != nil {
		// writeHTAccess uses the fixed ConfigDir; skip where it isn't writable.
		t.Skipf("cannot write htaccess: %v", err)
	}
	h := loginHandler(cfg, []byte("secret"))

	post := func(user, pass, remote string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/login",
			strings.NewReader(url.Values{"username": {user}, "password": {pass}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = remote
		req.Header.Set("X-Forwarded-For", "9.9.9.9") // must be ignored
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}

	for i := 0; i < maxFailuresPerIP; i++ {
		if rec := post("admin", "wrong", "1.2.3.4:5000"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, rec.Code)
		}
	}
	// Locked out: even the correct password is refused now.
	rec := post("admin", "right-password", "1.2.3.4:5001")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("got %d (Retry-After=%q), want 429 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
	// A different client can still sign in, and success issues a cookie.
	rec = post("admin", "right-password", "5.6.7.8:1")
	if rec.Code != http.StatusSeeOther || len(rec.Result().Cookies()) == 0 {
		t.Fatalf("other IP: got %d, want 303 with cookie", rec.Code)
	}
}
