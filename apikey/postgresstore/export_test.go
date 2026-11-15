package postgresstore

import "time"

// SetClock replaces the store's clock, for the tests in package postgresstore_test.
func SetClock(store *Store, now func() time.Time) {
	store.now = now
}

// Intersect exposes intersect to the table test.
var Intersect = intersect
