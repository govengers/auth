package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestHashPasswordAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "argon2id$v=19$") {
		t.Fatalf("unexpected hash format: %q", hash)
	}

	valid, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("expected password to match")
	}

	valid, err = VerifyPassword("wrong password", hash)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("unexpected password match")
	}
}

func TestHashPasswordRejectsEmptyPassword(t *testing.T) {
	if _, err := HashPassword(""); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("HashPassword(\"\") error = %v, want %v", err, ErrInvalidPassword)
	}
}

func TestVerifyPasswordRejectsMalformedAndExpensiveHashes(t *testing.T) {
	for _, hash := range []string{
		"not-a-hash",
		"argon2id$v=19$m=999999,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	} {
		if _, err := VerifyPassword("password", hash); !errors.Is(err, ErrInvalidHash) {
			t.Errorf("VerifyPassword error = %v, want %v", err, ErrInvalidHash)
		}
	}
}
