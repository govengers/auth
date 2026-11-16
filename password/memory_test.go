package password_test

import (
	"testing"

	"github.com/govengers/auth/password"
	"github.com/govengers/auth/password/passwordtest"
)

func TestMemoryStorageConformance(t *testing.T) {
	passwordtest.Run(t, func(*testing.T) password.Storage { return password.NewMemoryStorage() })
}
