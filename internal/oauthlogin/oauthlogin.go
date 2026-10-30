// Package oauthlogin keeps the state of one redirect login (state, nonce, PKCE verifier, return path)
// in the server-side session, so the callback verifies it exactly once on any replica sharing the
// session backend. Shared by the oidc and github providers; its functions are safe for concurrent use.
package oauthlogin

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/random"
	"github.com/govengers/auth/internal/redirect"
	"github.com/govengers/auth/session"
)

const (
	lifetime         = 10 * time.Minute
	randomTokenBytes = 32
)

// The refusal codes of a redirect login; every provider using this package answers them, so a login page
// handles one set of codes.
const (
	CodeLoginFailed   = "login_failed"   // the code exchange or the verification of its answer failed
	CodeLoginDenied   = "login_denied"   // the provider sent error=... (the user or the provider refused)
	CodeLoginExpired  = "login_expired"  // no, an expired or an unreadable login state
	CodeStateMismatch = "state_mismatch" // the callback state does not match the stored one
)

// State is what a login start stores and its callback needs back.
type State struct {
	State      string `json:"state"`
	Nonce      string `json:"nonce"`
	Verifier   string `json:"verifier"`   // PKCE code verifier: 32 random bytes, base64url (as oauth2.GenerateVerifier)
	ReturnPath string `json:"returnPath"` // redirect.ReturnPath(request)
}

// Begin generates State (32 bytes), Nonce (32 bytes) and Verifier and stores them as JSON under key for 10 min,
// in the session startLoginSession returns.
func Begin(ctx context.Context, store *session.Store, writer http.ResponseWriter, request *http.Request, key string) (State, error) {
	state, err := newState(request)
	if err != nil {
		return State{}, err
	}
	current, err := startLoginSession(ctx, store, writer, request)
	if err != nil {
		return State{}, err
	}
	encoded, err := encodeState(state)
	if err != nil {
		return State{}, err
	}
	if err := current.Put(ctx, key, encoded, lifetime); err != nil {
		return State{}, fmt.Errorf("store login state: %w", err)
	}
	return state, nil
}

// encodeState writes state as JSON without HTML escaping: json.Marshal writes each "<", ">" and "&" of the
// return path as six bytes, and every anonymous login start stores it, so 2048 bytes of them took 12 KB.
func encodeState(state State) ([]byte, error) {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(state); err != nil {
		return nil, fmt.Errorf("encode login state: %w", err)
	}
	return encoded.Bytes(), nil
}

// Complete opens the session, pops key (single use) and compares the callback state in constant time.
// Refusals (*auth.Error): provider sent error=...: ErrUnauthenticated code "login_denied"; no or expired state:
// ErrInvalidRequest "login_expired"; mismatch: ErrInvalidRequest "state_mismatch"; no code: ErrInvalidRequest.
// A provider error is refused before the session is read, so it does not consume the state.
func Complete(ctx context.Context, store *session.Store, request *http.Request, key string) (State, error) {
	query := request.URL.Query()
	if query.Get("error") != "" {
		return State{}, &auth.Error{Kind: auth.ErrUnauthenticated, Code: CodeLoginDenied, Reason: "provider returned an error"}
	}
	stored, err := popState(ctx, store, request, key)
	if err != nil {
		return State{}, err
	}
	if err := verifyCallback(query, stored); err != nil {
		return State{}, err
	}
	return stored, nil
}

// startLoginSession keeps the request's session while it holds a live identity, so a cross-site link to a
// login route cannot end it (the callback rotates the session after authentication anyway); otherwise it
// starts a fresh one (Store.Start), which revokes the request's session.
func startLoginSession(ctx context.Context, store *session.Store, writer http.ResponseWriter, request *http.Request) (session.Session, error) {
	if current, err := store.Open(request); err == nil {
		_, err := current.Identity(ctx)
		if err == nil {
			return current, nil
		}
		if !errors.Is(err, auth.ErrUnauthenticated) {
			return session.Session{}, fmt.Errorf("read login session: %w", err)
		}
	}
	current, err := store.Start(ctx, writer, request)
	if err != nil {
		return session.Session{}, fmt.Errorf("start login session: %w", err)
	}
	return current, nil
}

func newState(request *http.Request) (State, error) {
	tokens := make([]string, 3)
	for index := range tokens {
		token, err := random.Token(randomTokenBytes)
		if err != nil {
			return State{}, fmt.Errorf("generate login state: %w", err)
		}
		tokens[index] = token
	}
	return State{State: tokens[0], Nonce: tokens[1], Verifier: tokens[2], ReturnPath: redirect.ReturnPath(request)}, nil
}

func popState(ctx context.Context, store *session.Store, request *http.Request, key string) (State, error) {
	current, err := store.Open(request)
	if err != nil {
		return State{}, loginExpired("no session cookie")
	}
	encoded, found, err := current.Pop(ctx, key)
	if err != nil {
		return State{}, fmt.Errorf("pop login state: %w", err)
	}
	if !found {
		return State{}, loginExpired("no login state")
	}
	var stored State
	if err := json.Unmarshal(encoded, &stored); err != nil || stored.State == "" {
		return State{}, loginExpired("unreadable login state")
	}
	return stored, nil
}

func verifyCallback(query url.Values, stored State) error {
	if subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(stored.State)) != 1 {
		return &auth.Error{Kind: auth.ErrInvalidRequest, Code: CodeStateMismatch, Reason: "callback state does not match"}
	}
	if query.Get("code") == "" {
		return &auth.Error{Kind: auth.ErrInvalidRequest, Reason: "callback without code"}
	}
	return nil
}

func loginExpired(reason string) error {
	return &auth.Error{Kind: auth.ErrInvalidRequest, Code: CodeLoginExpired, Reason: reason}
}
