package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/govengers/auth"
)

const identityKey = "identity"

// Session is a handle on one server-side session (value type, unexported fields: the backend ID and the store).
// Values are AES-256-GCM sealed with a random 12-byte nonce and additional data "<sessionID>\x00<key>";
// a value that does not decrypt (moved, tampered, other key) counts as absent. A Session is safe for
// concurrent use; the zero value is not usable.
type Session struct {
	store     *Store
	id        string
	startedAt time.Time // set by Start: the first SaveIdentity begins the absolute lifetime here; zero when opened
}

// identityEnvelope is the persistence format of the "identity" key; never rename the tags.
type identityEnvelope struct {
	Identity        *auth.Identity `json:"identity"`
	AuthenticatedAt time.Time      `json:"authenticatedAt"`
	RefreshedAt     time.Time      `json:"refreshedAt"`
	sealed          []byte         // the stored value it was read from (never encoded): what swapEnvelope compares
}

// Put seals value and stores it under key for ttl (positive). A revoked session refuses with ErrUnauthenticated.
func (s Session) Put(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if key == "" || ttl <= 0 {
		return fmt.Errorf("put session value %q for %s: key must not be empty and ttl must be positive", key, ttl)
	}
	sealed, err := seal(s.store.options.EncryptionKey, s.id, key, value)
	if err != nil {
		return fmt.Errorf("put session value %q: %w", key, err)
	}
	err = s.store.options.Backend.Put(ctx, s.id, key, sealed, ttl)
	if errors.Is(err, ErrSessionRevoked) {
		return &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "session revoked", Err: err}
	}
	if err != nil {
		return fmt.Errorf("put session value %q: %w", key, err)
	}
	return nil
}

// Get returns the value under key; false when there is none, it expired or it does not decrypt.
func (s Session) Get(ctx context.Context, key string) ([]byte, bool, error) {
	sealed, found, err := s.store.options.Backend.Get(ctx, s.id, key)
	if err != nil {
		return nil, false, fmt.Errorf("get session value %q: %w", key, err)
	}
	value, found := s.open(key, sealed, found)
	return value, found, nil
}

// Pop returns the value under key and deletes it; of two concurrent Pops at most one finds it.
func (s Session) Pop(ctx context.Context, key string) ([]byte, bool, error) {
	sealed, found, err := s.store.options.Backend.Pop(ctx, s.id, key)
	if err != nil {
		return nil, false, fmt.Errorf("pop session value %q: %w", key, err)
	}
	value, found := s.open(key, sealed, found)
	return value, found, nil
}

// SaveIdentity stores identity under key "identity". The first save of a session sets authenticatedAt to
// the time Start issued it; later saves (refresh, TOTP enable, impersonation) keep it. refreshedAt=now.
// TTL = authenticatedAt + MaximumAge - now. Only a session returned by Start may have a first save: on a
// session opened from a cookie without an identity (never authenticated, expired, revoked) it refuses with
// ErrUnauthenticated, so neither a planted cookie, a save racing the expiry nor a retained Start handle
// gets a fresh lifetime.
func (s Session) SaveIdentity(ctx context.Context, identity *auth.Identity) error {
	if identity == nil {
		return errors.New("save session identity: identity is nil")
	}
	authenticatedAt, err := s.authenticatedAt(ctx)
	if err != nil {
		return err
	}
	return s.saveEnvelope(ctx, identityEnvelope{Identity: identity, AuthenticatedAt: authenticatedAt, RefreshedAt: s.store.now()})
}

// Identity returns the stored identity; none, expired (now > authenticatedAt + MaximumAge) or revoked: *auth.Error ErrUnauthenticated.
func (s Session) Identity(ctx context.Context) (*auth.Identity, error) {
	envelope, err := s.envelope(ctx)
	if err != nil {
		return nil, err
	}
	return envelope.Identity, nil
}

func (s Session) open(key string, sealed []byte, found bool) ([]byte, bool) {
	if !found {
		return nil, false
	}
	return open(s.store.options.EncryptionKey, s.id, key, sealed)
}

// authenticatedAt is when the session's lifetime began: its start for a started session without identity.
func (s Session) authenticatedAt(ctx context.Context) (time.Time, error) {
	envelope, err := s.envelope(ctx)
	if err == nil {
		return envelope.AuthenticatedAt, nil
	}
	if !s.startedAt.IsZero() && errors.Is(err, auth.ErrUnauthenticated) {
		return s.startedAt, nil
	}
	return time.Time{}, err
}

func (s Session) envelope(ctx context.Context) (identityEnvelope, error) {
	sealed, found, err := s.store.options.Backend.Get(ctx, s.id, identityKey)
	if err != nil {
		return identityEnvelope{}, fmt.Errorf("get session value %q: %w", identityKey, err)
	}
	encoded, found := s.open(identityKey, sealed, found)
	if !found {
		return identityEnvelope{}, &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "no session identity"}
	}
	var envelope identityEnvelope
	if err := json.Unmarshal(encoded, &envelope); err != nil || envelope.Identity == nil {
		return identityEnvelope{}, &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "unreadable session identity", Err: err}
	}
	if s.store.now().After(s.expiresAt(envelope)) {
		return identityEnvelope{}, &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "session expired"}
	}
	envelope.sealed = sealed
	return envelope, nil
}

func (s Session) saveEnvelope(ctx context.Context, envelope identityEnvelope) error {
	encoded, ttl, err := s.encodeEnvelope(envelope)
	if err != nil {
		return err
	}
	return s.Put(ctx, identityKey, encoded, ttl)
}

// swapEnvelope saves envelope, keeping the stored lifetime, only while the stored value is still the one
// envelope was read from; false when the session was saved, revoked or expired meanwhile.
func (s Session) swapEnvelope(ctx context.Context, envelope identityEnvelope) (bool, error) {
	encoded, _, err := s.encodeEnvelope(envelope)
	if err != nil {
		return false, err
	}
	sealed, err := seal(s.store.options.EncryptionKey, s.id, identityKey, encoded)
	if err != nil {
		return false, fmt.Errorf("swap session identity: %w", err)
	}
	swapped, err := s.store.options.Backend.CompareAndSwap(ctx, s.id, identityKey, envelope.sealed, sealed)
	if err != nil {
		return false, fmt.Errorf("swap session identity: %w", err)
	}
	return swapped, nil
}

// encodeEnvelope returns envelope's JSON and the time left of its absolute lifetime; refused once that is over.
func (s Session) encodeEnvelope(envelope identityEnvelope) ([]byte, time.Duration, error) {
	ttl := s.expiresAt(envelope).Sub(s.store.now())
	if ttl <= 0 {
		return nil, 0, &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "session expired"}
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, 0, fmt.Errorf("encode session identity: %w", err)
	}
	return encoded, ttl, nil
}

func (s Session) expiresAt(envelope identityEnvelope) time.Time {
	return envelope.AuthenticatedAt.Add(s.store.options.MaximumAge)
}
