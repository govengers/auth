// Package authorization decides whether the identity in a request context may proceed. A Check is a
// function of the context, so the same check guards HTTP routes, WebSocket messages, jobs and tests.
// Checks compose with All, Any, Not and Real; the primitives read the auth.Identity a provider put
// into the context.
//
// Refusals are *auth.Error: ErrUnauthenticated when there is no identity, ErrForbidden otherwise,
// with a Reason for the wide event that never reaches the client. Not and every primitive except
// IsAuthenticated require an active identity, so a deactivated admin is not an admin.
// A nil Check given to a combinator refuses with ErrForbidden, so a wiring mistake fails closed.
//
// Entity checks (may this identity see this object) stay in the applications. Checks are pure and
// safe for concurrent use.
package authorization

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/govengers/auth"
)

// Check decides whether the identity in ctx may proceed: nil allows, an error refuses.
// Refusals are *auth.Error with Kind ErrUnauthenticated (no identity) or ErrForbidden (Reason says why).
type Check func(ctx context.Context) error

// All passes when every check passes and returns the first refusal otherwise. Without checks it refuses
// with ErrForbidden.
func All(checks ...Check) Check {
	checks = failClosed(checks)
	return func(ctx context.Context) error {
		if len(checks) == 0 {
			return forbidden("no checks")
		}
		for _, check := range checks {
			if err := check(ctx); err != nil {
				return err
			}
		}
		return nil
	}
}

// Any passes when one check passes. When all refuse it returns the first check's refusal; without
// checks it refuses with ErrForbidden.
func Any(checks ...Check) Check {
	checks = failClosed(checks)
	return func(ctx context.Context) error {
		if len(checks) == 0 {
			return forbidden("no checks")
		}
		var firstRefusal error
		for _, check := range checks {
			err := check(ctx)
			if err == nil {
				return nil
			}
			if firstRefusal == nil {
				firstRefusal = err
			}
		}
		return firstRefusal
	}
}

// Not inverts check for an active identity: it passes when check refuses with ErrForbidden and refuses
// with ErrForbidden when check passes; other errors pass through. Like the primitives it refuses a
// missing identity with ErrUnauthenticated and an inactive one with ErrForbidden before it evaluates
// check, so Not(HasRole(role)) never admits an anonymous or deactivated identity.
func Not(check Check) Check {
	if check == nil {
		return nilCheck
	}
	return func(ctx context.Context) error {
		if err := inactiveRefusal(auth.IdentityFrom(ctx)); err != nil {
			return err
		}
		err := check(ctx)
		switch {
		case err == nil:
			return forbidden("negated check passed")
		case errors.Is(err, auth.ErrForbidden):
			return nil
		default:
			return err
		}
	}
}

// Real evaluates check against the identity that authenticated: the impersonator while impersonating,
// the identity itself otherwise. Real(IsAdmin()) keeps an impersonating admin an admin.
func Real(check Check) Check {
	check = failClosedCheck(check)
	return func(ctx context.Context) error {
		return check(auth.WithIdentity(ctx, auth.IdentityFrom(ctx).Real()))
	}
}

// IsAuthenticated passes any identity, active or not.
func IsAuthenticated() Check {
	return func(ctx context.Context) error {
		if auth.IdentityFrom(ctx) == nil {
			return unauthenticated()
		}
		return nil
	}
}

// IsActive passes an active identity.
func IsActive() Check {
	return func(ctx context.Context) error {
		return inactiveRefusal(auth.IdentityFrom(ctx))
	}
}

// IsUser passes an active identity; it is IsActive under the name application code uses for "any user".
func IsUser() Check {
	return IsActive()
}

// IsAdmin passes an active identity with the role auth.RoleAdmin.
func IsAdmin() Check {
	return HasRole(auth.RoleAdmin)
}

// HasRole passes an active identity with role in Roles.
func HasRole(role string) Check {
	return activeIdentityWith("missing role "+role, func(identity *auth.Identity) bool {
		return slices.Contains(identity.Roles, role)
	})
}

// HasUserID passes an active identity whose UserID is id. uuid.Nil never matches, so an identity
// without an application user ID never owns anything.
func HasUserID(id uuid.UUID) Check {
	return activeIdentityWith("user ID is not "+id.String(), func(identity *auth.Identity) bool {
		return id != uuid.Nil && identity.UserID == id
	})
}

// HasOIDCRole passes an active identity with role in OIDCRoles (Keycloak realm roles).
func HasOIDCRole(role string) Check {
	return activeIdentityWith("missing OIDC role "+role, func(identity *auth.Identity) bool {
		return slices.Contains(identity.OIDCRoles, role)
	})
}

// HasOIDCGroup passes an active identity with group in Groups.
func HasOIDCGroup(group string) Check {
	return activeIdentityWith("missing OIDC group "+group, func(identity *auth.Identity) bool {
		return slices.Contains(identity.Groups, group)
	})
}

// HasGitHubTeam passes an active identity that is a member of team ("org/team-slug", matched
// case-insensitively; the GitHub provider stores Teams in lower case).
func HasGitHubTeam(team string) Check {
	team = strings.ToLower(team)
	return activeIdentityWith("missing GitHub team "+team, func(identity *auth.Identity) bool {
		return slices.Contains(identity.Teams, team)
	})
}

// HasPermission passes an active identity that Permits access on resource (auth.Permission.Grants: "*"
// covers every resource, write includes read). An empty or invalid resource, or an access other than read
// and write, refuses everything. The effective identity counts; wrap the check in Real to check the
// impersonator. Interactive users have no permissions unless an OnLogin hook grants them: compose
// Any(HasRole(role), HasPermission(resource, access)) or grant them at login.
func HasPermission(resource string, access auth.Access) Check {
	reason := "missing permission " + auth.Permission{Resource: resource, Access: access}.String()
	return activeIdentityWith(reason, func(identity *auth.Identity) bool {
		return identity.Permits(resource, access)
	})
}

// failClosed returns a copy of checks in which every nil check refuses.
func failClosed(checks []Check) []Check {
	safeChecks := make([]Check, len(checks))
	for index, check := range checks {
		safeChecks[index] = failClosedCheck(check)
	}
	return safeChecks
}

// failClosedCheck returns check, or nilCheck when check is nil.
func failClosedCheck(check Check) Check {
	if check == nil {
		return nilCheck
	}
	return check
}

// nilCheck is what a nil Check becomes: a refusal, never a panic.
func nilCheck(context.Context) error {
	return forbidden("nil check")
}

// activeIdentityWith passes an active identity for which allowed holds and refuses others with reason.
func activeIdentityWith(reason string, allowed func(identity *auth.Identity) bool) Check {
	return func(ctx context.Context) error {
		identity := auth.IdentityFrom(ctx)
		if err := inactiveRefusal(identity); err != nil {
			return err
		}
		if !allowed(identity) {
			return forbidden(reason)
		}
		return nil
	}
}

// inactiveRefusal returns the refusal of a missing (unauthenticated) or inactive (forbidden) identity, nil for an active one.
func inactiveRefusal(identity *auth.Identity) error {
	if identity == nil {
		return unauthenticated()
	}
	if !identity.Active {
		return forbidden("inactive")
	}
	return nil
}

func unauthenticated() error {
	return &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "no identity"}
}

func forbidden(reason string) error {
	return &auth.Error{Kind: auth.ErrForbidden, Reason: reason}
}
