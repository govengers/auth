package passwordtest_test

import (
	"testing"

	"github.com/govengers/auth/password"
	"github.com/govengers/auth/password/passwordtest"
)

// The suite accepts a correct Storage. Other implementations run it in their own tests.
func TestRunAcceptsMemoryStorage(t *testing.T) {
	passwordtest.Run(t, func(*testing.T) password.Storage { return password.NewMemoryStorage() })
}
