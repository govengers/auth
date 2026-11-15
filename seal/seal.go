// Package seal encrypts small secrets at rest, such as TOTP secrets, webhook signing secrets and API tokens of
// third parties, with AES-256-GCM under a key ring.
//
// A sealed value is the text "v1.<key ID>.<base64url ciphertext>": it names the key that sealed it, so keys
// rotate without a flag day. Seal uses the primary key (the first of Options.Keys), Open accepts every key of
// the ring, and Reseal moves a value to the primary key. Every value is bound to its AssociatedData (purpose,
// table and row): a value copied to another row, column or purpose does not open. The package does no I/O and
// reports nothing; its Sealer is safe for concurrent use.
package seal

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/govengers/auth/internal/encryption"
)

const (
	version            = "v1"
	maximumKeyIDLength = 32 // keyIDPattern's bound
	// cipherInfo starts the HKDF info of every key derived for a sealed value; a session key's info differs.
	cipherInfo = "govengers/auth seal " + version
)

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// ErrInvalid is returned by Open and Reseal for a value that is not a sealed value, was changed, or was sealed
// for other AssociatedData or under another key with the same ID.
var ErrInvalid = errors.New("seal: sealed value is malformed, tampered with or bound to other data")

// ErrUnknownKey is returned by Open and Reseal for a value sealed under a key ID the ring does not hold, e.g. a
// key removed before every value was resealed.
var ErrUnknownKey = errors.New("seal: sealed value names a key the ring does not hold")

// Key is one key of the ring.
type Key struct {
	ID     string // 1 to 32 characters of A-Z a-z 0-9 _ -; written into every value the key seals, so never reuse an ID for another secret
	Secret []byte // exactly 32 bytes, not one byte repeated; generate one with `openssl rand -base64 32`
}

// Options configures New.
type Options struct {
	// Keys is the ring, at least one key; the first is the primary key Seal uses, the others only open values.
	// IDs and secrets must be distinct. To rotate, put a new key first and keep the old ones until Reseal moved
	// every value to the new one.
	Keys []Key
}

// AssociatedData binds a sealed value to where it is stored and what it is for. Every field is required.
// Open must be given the same values as Seal, so pick values that never change for the row, such as its
// primary key, never a mutable name.
type AssociatedData struct {
	Purpose string // what the secret is, e.g. "totp_secret" or "webhook_signing_secret"
	Table   string // where it is stored, e.g. "users"
	Row     string // the row's stable ID, e.g. its UUID
}

// Sealer seals and opens values under a key ring. It is safe for concurrent use.
type Sealer struct {
	primary string
	secrets map[string][]byte
}

// New validates options and returns a Sealer working on a copy of the keys.
func New(options *Options) (*Sealer, error) {
	if options == nil || len(options.Keys) == 0 {
		return nil, errors.New("seal: at least one key is required")
	}
	secrets := make(map[string][]byte, len(options.Keys))
	for index, key := range options.Keys {
		if err := checkKey(key, secrets); err != nil {
			return nil, fmt.Errorf("seal: key %d: %w", index, err)
		}
		secrets[key.ID] = slices.Clone(key.Secret)
	}
	return &Sealer{primary: options.Keys[0].ID, secrets: secrets}, nil
}

func checkKey(key Key, known map[string][]byte) error {
	if !isKeyID(key.ID) {
		return fmt.Errorf("ID must be 1 to %d characters of A-Z a-z 0-9 _ -", maximumKeyIDLength)
	}
	if _, found := known[key.ID]; found {
		return fmt.Errorf("ID %q is used twice", key.ID)
	}
	if err := encryption.CheckKey(key.Secret, "secret"); err != nil {
		return err
	}
	for id, secret := range known {
		if bytes.Equal(secret, key.Secret) {
			return fmt.Errorf("secret repeats the one of key %q", id)
		}
	}
	return nil
}

func isKeyID(id string) bool {
	return keyIDPattern.MatchString(id)
}

// Seal encrypts plaintext under the primary key, bound to data, and returns the sealed value. Sealing the same
// plaintext twice gives different values. An AssociatedData with an empty field is an error.
func (s *Sealer) Seal(data AssociatedData, plaintext []byte) (string, error) {
	if err := data.check(); err != nil {
		return "", err
	}
	return s.seal(s.primary, data, plaintext)
}

// Open decrypts a sealed value that Seal returned for the same data under any key of the ring. A value that
// does not open is ErrInvalid; one of a key the ring lacks, ErrUnknownKey. Errors never contain the value.
func (s *Sealer) Open(data AssociatedData, sealed string) ([]byte, error) {
	if err := data.check(); err != nil {
		return nil, err
	}
	plaintext, _, err := s.open(data, sealed)
	return plaintext, err
}

// Reseal opens sealed and, when a key other than the primary one sealed it, seals it again under the primary
// key; resealed tells whether it did, so a rotation job writes back only the changed values. A value the
// primary key sealed is returned unchanged. Errors are Open's.
func (s *Sealer) Reseal(data AssociatedData, sealed string) (value string, resealed bool, err error) {
	if err := data.check(); err != nil {
		return "", false, err
	}
	plaintext, keyID, err := s.open(data, sealed)
	if err != nil {
		return "", false, err
	}
	if keyID == s.primary {
		return sealed, false, nil
	}
	value, err = s.seal(s.primary, data, plaintext)
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

func (s *Sealer) seal(keyID string, data AssociatedData, plaintext []byte) (string, error) {
	secret, found := s.secrets[keyID]
	if !found {
		// a Sealer not built by New has no key; HKDF would accept the empty one
		return "", errors.New("seal: the Sealer has no key; build it with New")
	}
	aead, err := encryption.DerivedCipher(secret, cipherInfo+" "+string(data.encode(keyID)))
	if err != nil {
		return "", fmt.Errorf("seal: %w", err)
	}
	// NewGCMWithRandomNonce generates the nonce itself and requires Seal's nonce argument to be nil.
	ciphertext := aead.Seal(nil, nil, plaintext, data.encode(keyID)) //nolint:gosec // G407 false positive, see above
	return version + "." + keyID + "." + base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// open returns the plaintext of sealed and the ID of the key that sealed it.
func (s *Sealer) open(data AssociatedData, sealed string) ([]byte, string, error) {
	keyID, ciphertext, err := parse(sealed)
	if err != nil {
		return nil, "", err
	}
	secret, found := s.secrets[keyID]
	if !found {
		return nil, "", fmt.Errorf("open sealed value of key %q: %w", keyID, ErrUnknownKey)
	}
	aead, err := encryption.DerivedCipher(secret, cipherInfo+" "+string(data.encode(keyID)))
	if err != nil {
		return nil, "", fmt.Errorf("seal: %w", err)
	}
	plaintext, err := aead.Open(nil, nil, ciphertext, data.encode(keyID))
	if err != nil {
		return nil, "", fmt.Errorf("open sealed value of key %q: %w", keyID, ErrInvalid)
	}
	return plaintext, keyID, nil
}

// parse splits "v1.<key ID>.<ciphertext>" into the key ID and the decoded ciphertext.
func parse(sealed string) (string, []byte, error) {
	parts := strings.Split(sealed, ".")
	// the base64 decoder skips \r and \n even in strict mode, so a changed value would still open
	if len(parts) != 3 || parts[0] != version || !isKeyID(parts[1]) || strings.ContainsAny(parts[2], "\r\n") {
		return "", nil, ErrInvalid
	}
	ciphertext, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		return "", nil, ErrInvalid
	}
	return parts[1], ciphertext, nil
}

func (d AssociatedData) check() error {
	if d.Purpose == "" || d.Table == "" || d.Row == "" {
		return errors.New("seal: AssociatedData needs Purpose, Table and Row")
	}
	return nil
}

// encode writes the version, keyID and every field length-prefixed, so no two different inputs encode alike.
func (d AssociatedData) encode(keyID string) []byte {
	var encoded []byte
	for _, field := range []string{version, keyID, d.Purpose, d.Table, d.Row} {
		encoded = binary.AppendUvarint(encoded, uint64(len(field)))
		encoded = append(encoded, field...)
	}
	return encoded
}

// ParseKeys parses a key ring from configuration text: comma-separated "<ID>:<base64 secret>" entries, the
// primary key first, e.g. "2026-11:<base64>,2026-01:<base64>". White space around entries is ignored. The
// secrets are decoded like session.ParseKey; errors name the entry by position and never repeat a secret.
func ParseKeys(encoded string) ([]Key, error) {
	var keys []Key
	for index, entry := range strings.Split(encoded, ",") {
		id, secret, found := strings.Cut(strings.TrimSpace(entry), ":")
		if !found || !isKeyID(id) {
			return nil, fmt.Errorf("seal: key entry %d is not \"<ID>:<base64 secret>\" with an ID of 1 to %d characters of A-Z a-z 0-9 _ -", index, maximumKeyIDLength)
		}
		decoded, err := encryption.ParseKey(secret, "secret")
		if err != nil {
			return nil, fmt.Errorf("seal: key entry %d (%s): %w", index, id, err)
		}
		keys = append(keys, Key{ID: id, Secret: decoded})
	}
	return keys, nil
}
