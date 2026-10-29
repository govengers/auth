// Package dependency turns the errors of third-party packages into errors of this module. Its
// functions are safe for concurrent use.
package dependency

import (
	"context"
	"errors"
	"fmt"
)

// Error returns "<operation>: <err>" with err's message but without its chain, so callers cannot start
// matching on a dependency's errors (LIB-010). A cancelled or expired context stays detectable: when err
// matches context.Canceled or context.DeadlineExceeded, that standard library sentinel is wrapped and its
// text appended.
func Error(operation string, err error) error {
	message := operation + ": " + err.Error()
	for _, contextError := range []error{context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, contextError) {
			return fmt.Errorf("%s: %w", message, contextError)
		}
	}
	return errors.New(message)
}
