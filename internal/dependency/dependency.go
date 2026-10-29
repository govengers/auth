// Package dependency turns the errors of third-party packages into errors of this module. Its
// functions are safe for concurrent use.
package dependency

import "fmt"

// Error returns "<operation>: <err>" with err's message but without its chain, so callers cannot start
// matching on a dependency's errors (LIB-010).
func Error(operation string, err error) error {
	return fmt.Errorf("%s: %v", operation, err) //nolint:errorlint // LIB-010: a dependency's errors are not part of this module's API
}
