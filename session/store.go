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
	defaultMaxAge     = 24 * time.Hour
	cookieValueBytes  = 32
)

// StoreOptions configures NewStore.
type StoreOptions struct {
	Backend        Backend       // required
	EncryptionKey  []byte        // required, exactly 32 bytes (AES-256-GCM); see ParseKey
	CookieName     string        // default "auth_session"
	CookieDomain   string        // default "" (host-only cookie)
	CookiePath     string        // default "/"
	SameSite       http.SameSite // default http.SameSiteLaxMode; SameSiteNoneMode requires InsecureCookie false (front-channel logout needs None)
	InsecureCookie bool          // drops the Secure attribute; local HTTP development only
	MaxAge         time.Duration // default 24h, at least 1s; absolute session lifetime, also the cookie Max-Age
}

// Store issues and ends server-side sessions. The cookie carries 32 random bytes; the backend sees
// their SHA-256 and sealed values only. It is safe for concurrent use.
type Store struct {
	options StoreOptions
	now     func() time.Time
}

// NewStore validates options and returns a Store working on a copy of them.
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
	if options.MaxAge == 0 {
		options.MaxAge = defaultMaxAge
	}
	return options
}

func validateStoreOptions(options StoreOptions) error {
	if options.MaxAge < time.Second {
		return fmt.Errorf("session store: MaxAge %s is below one second", options.MaxAge)
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
	return nil
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
	http.SetCookie(writer, sessionCookie(s.options, cookieValue, int(s.options.MaxAge/time.Second)))
	return Session{store: s, id: sessionIDOf(cookieValue), started: true}, nil
}

// Open returns the handle of the request's session from its cookie (no I/O). No or malformed cookie: *auth.Error ErrUnauthenticated.
func (s *Store) Open(request *http.Request) (Session, error) {
	id, found := s.sessionID(request)
	if !found {
		return Session{}, &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "no valid session cookie"}
	}
	return Session{store: s, id: id}, nil
}

// End revokes the request's session (with context.WithoutCancel, so a disconnecting client cannot keep it) and expires the cookie. No cookie: only expires it.
func (s *Store) End(ctx context.Context, writer http.ResponseWriter, request *http.Request) error {
	http.SetCookie(writer, sessionCookie(s.options, "", -1))
	id, found := s.sessionID(request)
	if !found {
		return nil
	}
	return s.revoke(context.WithoutCancel(ctx), id)
}

// MaxAge returns the configured absolute session lifetime.
func (s *Store) MaxAge() time.Duration {
	return s.options.MaxAge
}

func (s *Store) revoke(ctx context.Context, id string) error {
	if err := s.options.Backend.Revoke(ctx, id, s.options.MaxAge); err != nil {
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

func sessionCookie(options StoreOptions, value string, maxAge int) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // G124: Secure is dropped only when the caller opts into InsecureCookie for local HTTP
		Name:     options.CookieName,
		Value:    value,
		Path:     options.CookiePath,
		Domain:   options.CookieDomain,
		MaxAge:   maxAge,
		Secure:   !options.InsecureCookie,
		HttpOnly: true,
		SameSite: options.SameSite,
	}
}
