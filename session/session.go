package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/govengers/auth"
)

const (
	identityKey = "identity"
	// saveAttempts bounds SaveIdentity's swaps lost to concurrent saves.
	saveAttempts = 3
)

// Session is a handle on one server-side session (value type, unexported fields: the backend ID and the store).
// Values are AES-256-GCM sealed under a key derived per session from the store's key (HKDF-SHA256), with a
// random 12-byte nonce and additional data "<sessionID>\x00<key>";
// a value that does not decrypt (moved, tampered, other key) counts as absent. A Session is safe for
// concurrent use; the zero value is not usable.
// The name repeats the package on purpose (NAM-003): it is the package's domain noun, like time.Time, and
// session.Handle would hide what it is a handle on.
type Session struct {
	store *Store
	id    string
	start *start // set by Start, shared by copies of the handle; nil when opened
}

// start is the first-save capability of a session returned by Start: usable once, by the handle or a copy.
type start struct {
	at   time.Time // the first SaveIdentity begins the absolute lifetime here
	used atomic.Bool
}

// identityEnvelope is the persistence format of the "identity" key; never rename the tags.
type identityEnvelope struct {
	Identity        *auth.Identity `json:"identity"`
	AuthenticatedAt time.Time      `json:"authenticatedAt"`
	RefreshedAt     time.Time      `json:"refreshedAt"`
	VerifiedAt      time.Time      `json:"verifiedAt"` // the login or the last successful Guard refresh; see verifiedAt
	// ImpersonationEndsAt is when the Guard ends the impersonation Identity holds; zero when it holds none.
	ImpersonationEndsAt time.Time `json:"impersonationEndsAt,omitzero"`
	sealed              []byte    // the stored value it was read from or swapped in (never encoded): what swapEnvelope compares
}

// verifiedAt is when a provider last vouched for the identity; an envelope stored before VerifiedAt
// existed falls back to its AuthenticatedAt.
func (e identityEnvelope) verifiedAt() time.Time {
	if e.VerifiedAt.IsZero() {
		return e.AuthenticatedAt
	}
	return e.VerifiedAt
}

// impersonationOver reports whether the envelope holds an impersonation whose time is up. One without an
// end (saved by an application before the Impersonator existed) is over as well.
func (e identityEnvelope) impersonationOver(now time.Time) bool {
	return e.Identity.Impersonator != nil && !now.Before(e.ImpersonationEndsAt)
}

// Put seals value and stores it under key for ttl (positive). A revoked session refuses with ErrUnauthenticated.
// The key "identity" is reserved: only SaveIdentity and SwapIdentity write it, with their lifetime and swap rules.
func (s Session) Put(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if key == identityKey {
		return errReservedKey("put", key)
	}
	return s.put(ctx, key, value, ttl)
}

// errReservedKey is the error of a generic value operation on the identity's key.
func errReservedKey(operation, key string) error {
	return fmt.Errorf("%s session value %q: the key is reserved for the identity", operation, key)
}

func (s Session) put(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if key == "" || ttl <= 0 {
		return fmt.Errorf("put session value %q for %s: key must not be empty and ttl must be positive", key, ttl)
	}
	sealed, err := seal(s.store.options.EncryptionKey, s.id, key, value)
	if err != nil {
		return fmt.Errorf("put session value %q: %w", key, err)
	}
	err = s.store.options.Backend.Put(ctx, s.id, key, sealed, ttl)
	if errors.Is(err, ErrRevoked) {
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

// Pop returns the value under key and deletes it; of two concurrent Pops at most one finds it. The key
// "identity" is reserved, as for Put.
func (s Session) Pop(ctx context.Context, key string) ([]byte, bool, error) {
	if key == identityKey {
		return nil, false, errReservedKey("pop", key)
	}
	sealed, found, err := s.store.options.Backend.Pop(ctx, s.id, key)
	if err != nil {
		return nil, false, fmt.Errorf("pop session value %q: %w", key, err)
	}
	value, found := s.open(key, sealed, found)
	return value, found, nil
}

// SaveIdentity stores identity under key "identity". The first save of a session sets authenticatedAt to
// the time Start issued it; later saves (TOTP enable, application changes) keep it and refreshedAt: they verify
// nothing, so only the login and a Guard refresh may postpone the next refresh. TTL = authenticatedAt + MaximumAge - now. Only a session returned by Start may have a first save, and only
// one: without a live identity (never authenticated, expired, revoked) any other save refuses with
// ErrUnauthenticated, so neither a planted cookie, a save racing the expiry nor a retained Start handle gets
// a fresh lifetime. A later save swaps against the identity it read, so a save racing a logout cannot write
// the identity back even where the backend forgot the revocation (a full MemoryBackend).
// A save never changes who the session belongs to: the first one refuses an impersonating identity, a later
// one an identity or impersonator of another provider or subject than the stored ones (see Impersonator).
func (s Session) SaveIdentity(ctx context.Context, identity *auth.Identity) error {
	if identity == nil {
		return errors.New("save session identity: identity is nil")
	}
	for range saveAttempts {
		stored, err := s.envelope(ctx)
		if s.start != nil && errors.Is(err, auth.ErrUnauthenticated) {
			if identity.Impersonator != nil {
				return errors.New("save session identity: a login cannot impersonate; use session.Impersonator")
			}
			return s.saveFirstIdentity(ctx, identity, err)
		}
		if err != nil {
			return err
		}
		if err := checkPrincipals(stored.Identity, identity); err != nil {
			return err
		}
		stored.Identity = identity
		_, swapped, err := s.swapEnvelope(ctx, stored)
		if err != nil || swapped {
			return err
		}
	}
	return fmt.Errorf("save session identity: lost %d swaps to concurrent saves", saveAttempts)
}

// saveFirstIdentity begins the session's lifetime at its start, once per Start; absent is the refusal of a
// handle whose capability is used.
func (s Session) saveFirstIdentity(ctx context.Context, identity *auth.Identity, absent error) error {
	encoded, ttl, err := s.encodeEnvelope(identityEnvelope{Identity: identity, AuthenticatedAt: s.start.at, RefreshedAt: s.store.now(), VerifiedAt: s.start.at})
	if err != nil {
		return err
	}
	if !s.start.used.CompareAndSwap(false, true) {
		return absent
	}
	return s.put(ctx, identityKey, encoded, ttl)
}

// Identity returns the stored identity; none, expired (now > authenticatedAt + MaximumAge) or revoked: *auth.Error ErrUnauthenticated.
func (s Session) Identity(ctx context.Context) (*auth.Identity, error) {
	envelope, err := s.envelope(ctx)
	if err != nil {
		return nil, err
	}
	return envelope.Identity, nil
}

// SwapIdentity saves identity in place of previous (an identity Identity returned) only while the session
// still holds an identity equal to it (same JSON); swapped is false when another request saved a different
// one meanwhile or changed the session between the read and the swap. It keeps authenticatedAt, the
// expiry and refreshedAt, like SaveIdentity. A session without a live identity refuses with ErrUnauthenticated, like Identity.
// Like SaveIdentity it never changes who the session belongs to: an identity or impersonator of another
// provider or subject than the stored ones is an error (see Impersonator).
func (s Session) SwapIdentity(ctx context.Context, previous, identity *auth.Identity) (bool, error) {
	if identity == nil {
		return false, errors.New("swap session identity: identity is nil")
	}
	stored, err := s.envelope(ctx)
	if err != nil {
		return false, err
	}
	same, err := sameIdentity(stored.Identity, previous)
	if err != nil || !same {
		return false, err
	}
	if err := checkPrincipals(stored.Identity, identity); err != nil {
		return false, err
	}
	stored.Identity = identity
	_, swapped, err := s.swapEnvelope(ctx, stored)
	return swapped, err
}

// checkPrincipals refuses a save of identity over stored that starts, stops or changes an impersonation or
// replaces the user: only the Impersonator may do the first three, and only a login (Store.Start) the last.
func checkPrincipals(stored, identity *auth.Identity) error {
	if !samePrincipal(stored, identity) || !samePrincipal(stored.Impersonator, identity.Impersonator) {
		return errors.New("save session identity: the identity and its impersonator must keep their provider and subject; start and stop impersonating with session.Impersonator")
	}
	return nil
}

// samePrincipal reports whether two identities have the same provider and subject; two nil identities do.
func samePrincipal(first, second *auth.Identity) bool {
	if first == nil || second == nil {
		return first == second
	}
	return first.Provider == second.Provider && first.Subject == second.Subject
}

// replaceIdentity saves next with its impersonation end in place of previous (an identity the session held),
// keeping the lifetime and refreshedAt like SwapIdentity. It is how the Impersonator starts and stops: a
// session that no longer holds previous refuses with ErrConflict.
func (s Session) replaceIdentity(ctx context.Context, previous, next *auth.Identity, impersonationEndsAt time.Time) error {
	stored, err := s.envelope(ctx)
	if err != nil {
		return err
	}
	same, err := sameIdentity(stored.Identity, previous)
	if err != nil {
		return err
	}
	if same {
		stored.Identity, stored.ImpersonationEndsAt = next, impersonationEndsAt
		_, same, err = s.swapEnvelope(ctx, stored)
	}
	if err != nil {
		return err
	}
	if !same {
		return &auth.Error{Kind: auth.ErrConflict, Reason: "session identity changed meanwhile"}
	}
	return nil
}

// endImpersonation saves stored with the impersonation it holds ended (the identity that authenticated in
// place of the impersonated one) and returns the envelope the session holds now: the saved one, or what
// another request saved meanwhile. That one still holding an impersonation that is over is ErrConflict.
func (s Session) endImpersonation(ctx context.Context, stored identityEnvelope) (identityEnvelope, error) {
	for stored.Identity.Impersonator != nil { // an application may have nested one before the Impersonator existed
		stored.Identity = stored.Identity.Impersonator
	}
	stored.ImpersonationEndsAt = time.Time{}
	saved, swapped, err := s.swapEnvelope(ctx, stored)
	if err == nil && !swapped {
		saved, err = s.envelope(ctx)
	}
	switch {
	case err != nil:
		return identityEnvelope{}, err
	case saved.impersonationOver(s.store.now()):
		return identityEnvelope{}, &auth.Error{Kind: auth.ErrConflict, Reason: "impersonation ended by another request"}
	}
	return saved, nil
}

// sameIdentity compares previous with the stored identity in its stored form (JSON), so nil and empty fields
// count as equal.
func sameIdentity(stored, previous *auth.Identity) (bool, error) {
	previousJSON, err := json.Marshal(previous)
	if err != nil {
		return false, fmt.Errorf("compare session identity: %w", err)
	}
	storedJSON, _ := json.Marshal(stored) // decoded from JSON with the same validation, so it encodes again
	return bytes.Equal(storedJSON, previousJSON), nil
}

func (s Session) open(key string, sealed []byte, found bool) ([]byte, bool) {
	if !found {
		return nil, false
	}
	return open(s.store.options.EncryptionKey, s.id, key, sealed)
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

// swapEnvelope saves envelope, keeping the stored lifetime, only while the stored value is still the one
// envelope was read from, and returns it as stored now (the base of a later swap); false when the session
// was saved, revoked or expired meanwhile. When the backend's swap fails, the returned envelope is still the
// one sent (sealed set): the swap may have committed with its reply lost. When nothing was sent (an expired
// session, a sealing failure), sealed is nil.
func (s Session) swapEnvelope(ctx context.Context, envelope identityEnvelope) (identityEnvelope, bool, error) {
	encoded, _, err := s.encodeEnvelope(envelope)
	if err != nil {
		return identityEnvelope{}, false, err
	}
	sealed, err := seal(s.store.options.EncryptionKey, s.id, identityKey, encoded)
	if err != nil {
		return identityEnvelope{}, false, fmt.Errorf("swap session identity: %w", err)
	}
	swapped, err := s.store.options.Backend.CompareAndSwap(ctx, s.id, identityKey, envelope.sealed, sealed)
	envelope.sealed = sealed
	if err != nil {
		return envelope, false, fmt.Errorf("swap session identity: %w", err)
	}
	return envelope, swapped, nil
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
