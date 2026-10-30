package session

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/random"
)

const (
	defaultCookieName = "auth_session"
	hostPrefix        = "__Host-"
	securePrefix      = "__Secure-"
	defaultMaximumAge = 24 * time.Hour
	cookieValueBytes  = 32
	// revokeTimeout bounds End's revocation, which a disconnecting client cannot cancel.
	revokeTimeout = 10 * time.Second
)

// StoreOptions configures NewStore.
type StoreOptions struct {
	Backend        Backend       // required
	EncryptionKey  []byte        // required, exactly 32 bytes (AES-256-GCM); see ParseKey
	CookieName     string        // default "auth_session"; "__Host-" is prepended when Secure, host-only and on "/" (see NewStore)
	CookieDomain   string        // default "" (host-only cookie)
	CookiePath     string        // default "/"
	SameSite       http.SameSite // default http.SameSiteLaxMode; SameSiteNoneMode requires InsecureCookie false (front-channel logout needs None)
	InsecureCookie bool          // drops the Secure attribute; local HTTP development only
	MaximumAge     time.Duration // default 24h, at least 1s; absolute session lifetime, also the cookie Max-Age
}

// Store issues and ends server-side sessions. The cookie carries 32 random bytes; the backend sees
// their SHA-256 and sealed values only. It is safe for concurrent use.
type Store struct {
	options StoreOptions
	now     func() time.Time
}

// NewStore validates options and returns a Store working on a copy of them. A Secure, host-only cookie on
// path "/" is named "__Host-" + CookieName, unless CookieName has its own "__Host-" or "__Secure-" prefix:
// browsers accept such a cookie only from this host over https, so a sibling subdomain cannot toss a cookie
// of the same name that the store would read first. A "__Host-" CookieName needs exactly those attributes,
// a "__Secure-" one a Secure cookie.
func NewStore(options *StoreOptions) (*Store, error) {
	if options == nil || options.Backend == nil {
		return nil, errors.New("session store: Backend is required")
	}
	if len(options.EncryptionKey) != encryptionKeyLength {
		return nil, fmt.Errorf("session store: EncryptionKey has %d bytes, want %d", len(options.EncryptionKey), encryptionKeyLength)
	}
	resolved := withStoreDefaults(*options)
	if err := validateStoreOptions(resolved); err != nil {
		return nil, err
	}
	resolved.EncryptionKey = slices.Clone(options.EncryptionKey)
	resolved.CookieName = effectiveCookieName(resolved)
	return &Store{options: resolved, now: time.Now}, nil
}

func withStoreDefaults(options StoreOptions) StoreOptions {
	if options.CookieName == "" {
		options.CookieName = defaultCookieName
	}
	if options.CookiePath == "" {
		options.CookiePath = "/"
	}
	if options.SameSite == 0 {
		options.SameSite = http.SameSiteLaxMode
	}
	if options.MaximumAge == 0 {
		options.MaximumAge = defaultMaximumAge
	}
	return options
}

func validateStoreOptions(options StoreOptions) error {
	if options.MaximumAge < time.Second {
		return fmt.Errorf("session store: MaximumAge %s is below one second", options.MaximumAge)
	}
	if options.SameSite < http.SameSiteDefaultMode || options.SameSite > http.SameSiteNoneMode {
		return fmt.Errorf("session store: SameSite %d is unknown", options.SameSite)
	}
	if options.SameSite == http.SameSiteNoneMode && options.InsecureCookie {
		return errors.New("session store: SameSite None requires a Secure cookie, so InsecureCookie must be false")
	}
	if !strings.HasPrefix(options.CookiePath, "/") {
		return errors.New("session store: CookiePath must start with \"/\"")
	}
	if err := sessionCookie(options, "value", 0).Valid(); err != nil {
		return fmt.Errorf("session store: %w", err)
	}
	return validateCookiePrefix(options)
}

// validateCookiePrefix refuses a prefixed CookieName whose attributes a browser would reject the cookie for.
func validateCookiePrefix(options StoreOptions) error {
	switch {
	case hasCookiePrefix(options.CookieName, hostPrefix) && !hostOnlyOnRoot(options):
		return errors.New(`session store: a "__Host-" CookieName needs a Secure cookie (InsecureCookie false) without CookieDomain on CookiePath "/"`)
	case hasCookiePrefix(options.CookieName, securePrefix) && options.InsecureCookie:
		return errors.New(`session store: a "__Secure-" CookieName needs a Secure cookie, so InsecureCookie must be false`)
	}
	return nil
}

// effectiveCookieName is CookieName with "__Host-" prepended when the cookie qualifies for it and has no prefix.
func effectiveCookieName(options StoreOptions) string {
	if !hostOnlyOnRoot(options) || hasCookiePrefix(options.CookieName, hostPrefix) || hasCookiePrefix(options.CookieName, securePrefix) {
		return options.CookieName
	}
	return hostPrefix + options.CookieName
}

// hostOnlyOnRoot reports whether the cookie has the attributes "__Host-" requires: Secure, no Domain, Path "/".
func hostOnlyOnRoot(options StoreOptions) bool {
	return !options.InsecureCookie && options.CookieDomain == "" && options.CookiePath == "/"
}

// hasCookiePrefix matches prefix case-insensitively, as browsers do.
func hasCookiePrefix(name, prefix string) bool {
	return len(name) >= len(prefix) && strings.EqualFold(name[:len(prefix)], prefix)
}

// Start issues a new session: revokes the request's current session (if any), sets a fresh cookie, returns the handle.
// Used at login start and again after authentication (session ID rotation, fixation defense).
func (s *Store) Start(ctx context.Context, writer http.ResponseWriter, request *http.Request) (Session, error) {
	if previousID, found := s.sessionID(request); found {
		if err := s.revoke(ctx, previousID); err != nil {
			return Session{}, err
		}
	}
	cookieValue, err := random.Token(cookieValueBytes)
	if err != nil {
		return Session{}, fmt.Errorf("start session: %w", err)
	}
	http.SetCookie(writer, sessionCookie(s.options, cookieValue, int(s.options.MaximumAge/time.Second)))
	return Session{store: s, id: sessionIDOf(cookieValue), start: &start{at: s.now()}}, nil
}

// Open returns the handle of the request's session from its cookie (no I/O). No or malformed cookie: *auth.Error ErrUnauthenticated.
func (s *Store) Open(request *http.Request) (Session, error) {
	id, found := s.sessionID(request)
	if !found {
		return Session{}, &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "no valid session cookie"}
	}
	return Session{store: s, id: id}, nil
}

// End revokes the request's session (with context.WithoutCancel and its own 10 s timeout, so a disconnecting
// client cannot keep it and a hung backend cannot hold the request) and expires the cookie. No cookie: only expires it.
func (s *Store) End(ctx context.Context, writer http.ResponseWriter, request *http.Request) error {
	http.SetCookie(writer, sessionCookie(s.options, "", -1))
	id, found := s.sessionID(request)
	if !found {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revokeTimeout)
	defer cancel()
	return s.revoke(ctx, id)
}

// MaximumAge returns the configured absolute session lifetime.
func (s *Store) MaximumAge() time.Duration {
	return s.options.MaximumAge
}

func (s *Store) revoke(ctx context.Context, id string) error {
	if err := s.options.Backend.Revoke(ctx, id, s.options.MaximumAge); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// sessionID returns the backend ID of the request's session cookie; false without a well-formed one.
func (s *Store) sessionID(request *http.Request) (string, bool) {
	cookie, err := request.Cookie(s.options.CookieName)
	if err != nil || !isCookieValue(cookie.Value) {
		return "", false
	}
	return sessionIDOf(cookie.Value), true
}

func isCookieValue(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == cookieValueBytes
}

// sessionIDOf derives the backend ID from the cookie value, so a backend dump reveals no live cookie.
func sessionIDOf(cookieValue string) string {
	sum := sha256.Sum256([]byte(cookieValue))
	return hex.EncodeToString(sum[:])
}

func sessionCookie(options StoreOptions, value string, maximumAge int) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // G124: Secure is dropped only when the caller opts into InsecureCookie for local HTTP
		Name:     options.CookieName,
		Value:    value,
		Path:     options.CookiePath,
		Domain:   options.CookieDomain,
		MaxAge:   maximumAge,
		Secure:   !options.InsecureCookie,
		HttpOnly: true,
		SameSite: options.SameSite,
	}
}
