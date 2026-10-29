// Package hook runs the application hooks the providers call. Its functions are safe for concurrent use
// when the hook is.
package hook

import (
	"context"
	"errors"
	"fmt"

	"github.com/govengers/auth"
)

// RunOnLogin returns what onLogin makes of identity, or identity itself when onLogin is nil. A hook
// error is wrapped with %w, so a refusal keeps its kind (status); a hook returning no identity is an error.
func RunOnLogin(ctx context.Context, onLogin auth.Hook, identity *auth.Identity) (*auth.Identity, error) {
	if onLogin == nil {
		return identity, nil
	}
	mapped, err := onLogin(ctx, identity)
	if err != nil {
		return nil, fmt.Errorf("OnLogin: %w", err)
	}
	if mapped == nil {
		return nil, errors.New("OnLogin returned no identity")
	}
	return mapped, nil
}
