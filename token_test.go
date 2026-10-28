package auth

import "testing"

func TestNewTokenDigestAndMatch(t *testing.T) {
	token, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 43 {
		t.Fatalf("token length = %d, want 43", len(token))
	}

	digest := DigestToken(token)
	if !TokenMatches(token, digest) {
		t.Fatal("expected token to match digest")
	}
	if TokenMatches("different token", digest) {
		t.Fatal("unexpected token match")
	}
	if TokenMatches("", digest) {
		t.Fatal("empty token must not match")
	}
}

func TestNewTokenReturnsUniqueTokens(t *testing.T) {
	first, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("generated tokens must be unique")
	}
}
