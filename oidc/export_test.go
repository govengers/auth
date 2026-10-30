package oidc

import (
	"testing"
	"time"
)

// ShortenLogoutTimeout sets the logout timeout to timeout until the test ends.
func ShortenLogoutTimeout(t *testing.T, timeout time.Duration) {
	t.Helper()
	previous := logoutTimeout
	logoutTimeout = timeout
	t.Cleanup(func() { logoutTimeout = previous })
}
