package session_test

import (
	"testing"
	"time"

	"github.com/govengers/auth/internal/backendtest"
	"github.com/govengers/auth/session"
)

func TestMemoryBackendConformance(t *testing.T) {
	backendtest.Run(t, func(t *testing.T) (session.Backend, func(time.Duration)) {
		return session.NewMemoryBackendOnTestClock(t)
	})
}
