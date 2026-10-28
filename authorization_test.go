package auth

import (
	"errors"
	"testing"
)

func TestAuthorizeRequiresExactPermission(t *testing.T) {
	principal := Principal{Subject: "user-1", Permissions: []string{"documents:read"}}

	if err := Authorize(principal, "documents:read"); err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if err := Authorize(principal, "documents:write"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("Authorize() error = %v, want %v", err, ErrPermissionDenied)
	}
	if err := Authorize(principal, ""); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("Authorize() error = %v, want %v", err, ErrPermissionDenied)
	}
}

func TestAuthorizeRejectsUnauthenticatedPrincipal(t *testing.T) {
	if err := Authorize(Principal{Permissions: []string{"documents:read"}}, "documents:read"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Authorize() error = %v, want %v", err, ErrUnauthenticated)
	}
}
