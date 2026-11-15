package postgresbackend

import "time"

// SetClock replaces the backend's clock, for the conformance run in package postgresbackend_test.
func SetClock(backend *Backend, now func() time.Time) {
	backend.now = now
}
