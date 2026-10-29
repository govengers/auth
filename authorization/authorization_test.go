package authorization_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/authorization"
)

var (
	userID      = uuid.MustParse("0b6f2c1e-7a3d-4c55-9f0e-2d8b1a6c4e71")
	otherUserID = uuid.MustParse("5e2d9c8b-1f4a-4b7e-8c3d-6a0f9e1b2c43")
)

func activeIdentity() *auth.Identity {
	return &auth.Identity{
		Provider:  "keycloak",
		Subject:   "subject-1",
		UserID:    userID,
		Active:    true,
		Roles:     []string{auth.RoleAdmin, "editor"},
		OIDCRoles: []string{"realm-reader"},
		Groups:    []string{"/engineering"},
		Teams:     []string{"govengers/maintainers"},
	}
}

func inactiveIdentity() *auth.Identity {
	identity := activeIdentity()
	identity.Active = false
	return identity
}

func withIdentity(t *testing.T, identity *auth.Identity) context.Context {
	t.Helper()
	return auth.WithIdentity(t.Context(), identity)
}

// requireRefusal asserts that err is nil when want is nil and an *auth.Error of kind want otherwise.
func requireRefusal(t *testing.T, want error, err error) {
	t.Helper()
	if want == nil {
		require.NoError(t, err)
		return
	}
	var refusal *auth.Error
	require.ErrorAs(t, err, &refusal)
	require.ErrorIs(t, err, want)
	require.NotEmpty(t, refusal.Reason)
}

func TestPrimitives(t *testing.T) {
	plainUser := &auth.Identity{Provider: "github", Subject: "42", Active: true}
	nilUserID := &auth.Identity{Provider: "github", Subject: "42", Active: true, UserID: uuid.Nil}

	testCases := []struct {
		name     string
		check    authorization.Check
		identity *auth.Identity
		want     error
	}{
		{name: "IsAuthenticated allows an identity", check: authorization.IsAuthenticated(), identity: activeIdentity()},
		{name: "IsAuthenticated allows an inactive identity", check: authorization.IsAuthenticated(), identity: inactiveIdentity()},
		{name: "IsAuthenticated refuses no identity", check: authorization.IsAuthenticated(), want: auth.ErrUnauthenticated},

		{name: "IsActive allows an active identity", check: authorization.IsActive(), identity: activeIdentity()},
		{name: "IsActive refuses an inactive identity", check: authorization.IsActive(), identity: inactiveIdentity(), want: auth.ErrForbidden},
		{name: "IsActive refuses no identity", check: authorization.IsActive(), want: auth.ErrUnauthenticated},

		{name: "IsUser allows an active identity", check: authorization.IsUser(), identity: activeIdentity()},
		{name: "IsUser refuses an inactive identity", check: authorization.IsUser(), identity: inactiveIdentity(), want: auth.ErrForbidden},
		{name: "IsUser refuses no identity", check: authorization.IsUser(), want: auth.ErrUnauthenticated},

		{name: "IsAdmin allows an active admin", check: authorization.IsAdmin(), identity: activeIdentity()},
		{name: "IsAdmin refuses a user without the role", check: authorization.IsAdmin(), identity: plainUser, want: auth.ErrForbidden},
		{name: "IsAdmin refuses an inactive admin", check: authorization.IsAdmin(), identity: inactiveIdentity(), want: auth.ErrForbidden},
		{name: "IsAdmin refuses no identity", check: authorization.IsAdmin(), want: auth.ErrUnauthenticated},

		{name: "HasRole allows a holder", check: authorization.HasRole("editor"), identity: activeIdentity()},
		{name: "HasRole refuses a non-holder", check: authorization.HasRole("auditor"), identity: activeIdentity(), want: auth.ErrForbidden},
		{name: "HasRole refuses an inactive holder", check: authorization.HasRole("editor"), identity: inactiveIdentity(), want: auth.ErrForbidden},
		{name: "HasRole refuses no identity", check: authorization.HasRole("editor"), want: auth.ErrUnauthenticated},

		{name: "HasUserID allows the user", check: authorization.HasUserID(userID), identity: activeIdentity()},
		{name: "HasUserID refuses another user", check: authorization.HasUserID(otherUserID), identity: activeIdentity(), want: auth.ErrForbidden},
		{name: "HasUserID never matches uuid.Nil", check: authorization.HasUserID(uuid.Nil), identity: nilUserID, want: auth.ErrForbidden},
		{name: "HasUserID refuses the inactive user", check: authorization.HasUserID(userID), identity: inactiveIdentity(), want: auth.ErrForbidden},
		{name: "HasUserID refuses no identity", check: authorization.HasUserID(userID), want: auth.ErrUnauthenticated},

		{name: "HasOIDCRole allows a holder", check: authorization.HasOIDCRole("realm-reader"), identity: activeIdentity()},
		{name: "HasOIDCRole refuses a non-holder", check: authorization.HasOIDCRole("realm-writer"), identity: activeIdentity(), want: auth.ErrForbidden},
		{name: "HasOIDCRole ignores application roles", check: authorization.HasOIDCRole("editor"), identity: activeIdentity(), want: auth.ErrForbidden},
		{name: "HasOIDCRole refuses an inactive holder", check: authorization.HasOIDCRole("realm-reader"), identity: inactiveIdentity(), want: auth.ErrForbidden},
		{name: "HasOIDCRole refuses no identity", check: authorization.HasOIDCRole("realm-reader"), want: auth.ErrUnauthenticated},

		{name: "HasOIDCGroup allows a member", check: authorization.HasOIDCGroup("/engineering"), identity: activeIdentity()},
		{name: "HasOIDCGroup refuses a non-member", check: authorization.HasOIDCGroup("/sales"), identity: activeIdentity(), want: auth.ErrForbidden},
		{name: "HasOIDCGroup refuses an inactive member", check: authorization.HasOIDCGroup("/engineering"), identity: inactiveIdentity(), want: auth.ErrForbidden},
		{name: "HasOIDCGroup refuses no identity", check: authorization.HasOIDCGroup("/engineering"), want: auth.ErrUnauthenticated},

		{name: "HasGitHubTeam allows a member", check: authorization.HasGitHubTeam("govengers/maintainers"), identity: activeIdentity()},
		{name: "HasGitHubTeam matches case-insensitively", check: authorization.HasGitHubTeam("Govengers/Maintainers"), identity: activeIdentity()},
		{name: "HasGitHubTeam refuses a non-member", check: authorization.HasGitHubTeam("govengers/triage"), identity: activeIdentity(), want: auth.ErrForbidden},
		{name: "HasGitHubTeam refuses an inactive member", check: authorization.HasGitHubTeam("govengers/maintainers"), identity: inactiveIdentity(), want: auth.ErrForbidden},
		{name: "HasGitHubTeam refuses no identity", check: authorization.HasGitHubTeam("govengers/maintainers"), want: auth.ErrUnauthenticated},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			requireRefusal(t, testCase.want, testCase.check(withIdentity(t, testCase.identity)))
		})
	}
}

func allow() authorization.Check {
	return func(context.Context) error { return nil }
}

func refuse(err error) authorization.Check {
	return func(context.Context) error { return err }
}

func TestCombinators(t *testing.T) {
	unauthenticated := &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "first"}
	forbidden := &auth.Error{Kind: auth.ErrForbidden, Reason: "second"}
	internal := errors.New("membership lookup failed")

	testCases := []struct {
		name  string
		check authorization.Check
		want  error // nil: allowed; otherwise errors.Is target
	}{
		{name: "All without checks refuses", check: authorization.All(), want: auth.ErrForbidden},
		{name: "All allows when every check allows", check: authorization.All(allow(), allow())},
		{name: "All returns the first refusal", check: authorization.All(allow(), refuse(unauthenticated), refuse(forbidden)), want: unauthenticated},
		{name: "All passes internal errors through", check: authorization.All(refuse(internal), refuse(forbidden)), want: internal},

		{name: "Any without checks refuses", check: authorization.Any(), want: auth.ErrForbidden},
		{name: "Any allows when one check allows", check: authorization.Any(refuse(forbidden), allow())},
		{name: "Any returns the first refusal when all refuse", check: authorization.Any(refuse(unauthenticated), refuse(forbidden)), want: unauthenticated},
		{name: "Any returns a first internal error", check: authorization.Any(refuse(internal), refuse(forbidden)), want: internal},

		{name: "nested All in Any allows", check: authorization.Any(refuse(forbidden), authorization.All(allow(), allow()))},
		{name: "nested Any in All refuses", check: authorization.All(allow(), authorization.Any(refuse(forbidden))), want: forbidden},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.check(withIdentity(t, activeIdentity()))

			if testCase.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, testCase.want)
		})
	}
}

func TestNot(t *testing.T) {
	unauthenticated := &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "inner"}
	internal := errors.New("membership lookup failed")

	testCases := []struct {
		name     string
		check    authorization.Check
		identity *auth.Identity
		want     error // nil: allowed; otherwise errors.Is target
	}{
		{name: "allows when the check forbids", check: authorization.Not(authorization.HasRole("auditor")), identity: activeIdentity()},
		{name: "refuses when the check allows", check: authorization.Not(authorization.HasRole("editor")), identity: activeIdentity(), want: auth.ErrForbidden},
		{name: "refuses no identity", check: authorization.Not(authorization.HasRole("auditor")), want: auth.ErrUnauthenticated},
		{name: "refuses an inactive identity", check: authorization.Not(authorization.HasRole("auditor")), identity: inactiveIdentity(), want: auth.ErrForbidden},
		{name: "refuses an inactive identity even when the check forbids", check: authorization.Not(refuse(&auth.Error{Kind: auth.ErrForbidden})), identity: inactiveIdentity(), want: auth.ErrForbidden},
		{name: "passes unauthenticated through", check: authorization.Not(refuse(unauthenticated)), identity: activeIdentity(), want: unauthenticated},
		{name: "passes internal errors through", check: authorization.Not(refuse(internal)), identity: activeIdentity(), want: internal},
		{name: "Not of Not allows", check: authorization.Not(authorization.Not(allow())), identity: activeIdentity()},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.check(withIdentity(t, testCase.identity))

			if testCase.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, testCase.want)
		})
	}
}

func TestNilChecksFailClosed(t *testing.T) {
	testCases := []struct {
		name  string
		check authorization.Check
	}{
		{name: "All", check: authorization.All(allow(), nil)},
		{name: "Any", check: authorization.Any(nil)},
		{name: "Not", check: authorization.Not(nil)},
		{name: "Real", check: authorization.Real(nil)},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.check(withIdentity(t, activeIdentity()))

			var refusal *auth.Error
			require.ErrorAs(t, err, &refusal)
			require.ErrorIs(t, err, auth.ErrForbidden)
			require.Equal(t, "nil check", refusal.Reason)
		})
	}
	require.NoError(t, authorization.Any(nil, allow())(t.Context()), "a nil check is one refusal, not a veto")
}

func TestCombinatorsKeepTheirChecks(t *testing.T) {
	checks := []authorization.Check{allow()}
	allCheck := authorization.All(checks...)
	anyCheck := authorization.Any(checks...)

	checks[0] = refuse(auth.ErrForbidden)

	require.NoError(t, allCheck(t.Context()))
	require.NoError(t, anyCheck(t.Context()))
}

func TestCombinatorsOverIdentities(t *testing.T) {
	ownerOrAdmin := authorization.Any(authorization.IsAdmin(), authorization.HasUserID(userID))
	owner := &auth.Identity{Provider: "password", Subject: "owner", UserID: userID, Active: true}
	stranger := &auth.Identity{Provider: "password", Subject: "stranger", UserID: otherUserID, Active: true}
	notReadOnly := authorization.Not(authorization.HasRole("read-only"))
	readOnly := &auth.Identity{Provider: "password", Subject: "reader", Active: true, Roles: []string{"read-only"}}

	requireRefusal(t, nil, ownerOrAdmin(withIdentity(t, owner)))
	requireRefusal(t, nil, ownerOrAdmin(withIdentity(t, activeIdentity())))
	requireRefusal(t, auth.ErrForbidden, ownerOrAdmin(withIdentity(t, stranger)))
	requireRefusal(t, auth.ErrUnauthenticated, ownerOrAdmin(t.Context()))

	requireRefusal(t, nil, notReadOnly(withIdentity(t, owner)))
	requireRefusal(t, auth.ErrForbidden, notReadOnly(withIdentity(t, readOnly)))
	requireRefusal(t, auth.ErrForbidden, notReadOnly(withIdentity(t, inactiveIdentity())))
	requireRefusal(t, auth.ErrUnauthenticated, authorization.Not(authorization.IsAuthenticated())(t.Context()))
}

func TestReal(t *testing.T) {
	admin := &auth.Identity{Provider: "password", Subject: "admin", Active: true, Roles: []string{auth.RoleAdmin}}
	user := &auth.Identity{Provider: "password", Subject: "user", Active: true}
	impersonated := user.Clone()
	impersonated.Impersonator = admin

	testCases := []struct {
		name     string
		check    authorization.Check
		identity *auth.Identity
		want     error
	}{
		{name: "the impersonated identity is no admin", check: authorization.IsAdmin(), identity: impersonated, want: auth.ErrForbidden},
		{name: "the impersonating admin is", check: authorization.Real(authorization.IsAdmin()), identity: impersonated},
		{name: "without impersonation the identity itself counts", check: authorization.Real(authorization.IsAdmin()), identity: admin},
		{name: "without impersonation a user stays a user", check: authorization.Real(authorization.IsAdmin()), identity: user, want: auth.ErrForbidden},
		{name: "no identity stays unauthenticated", check: authorization.Real(authorization.IsAuthenticated()), want: auth.ErrUnauthenticated},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			requireRefusal(t, testCase.want, testCase.check(withIdentity(t, testCase.identity)))
		})
	}
}

func TestHasPermission(t *testing.T) {
	withPermissions := func(texts ...string) *auth.Identity {
		identity := &auth.Identity{Provider: "apikey", Subject: "ci", Active: true}
		for _, text := range texts {
			permission, err := auth.ParsePermission(text)
			require.NoError(t, err)
			identity.Permissions = append(identity.Permissions, permission)
		}
		return identity
	}
	inactiveWriter := withPermissions("*:write")
	inactiveWriter.Active = false

	testCases := []struct {
		name       string
		resource   string
		access     auth.Access
		identity   *auth.Identity
		want       error // nil: allowed; otherwise the refusal kind
		wantReason string
	}{
		{name: "exact resource read", resource: "builds", access: auth.AccessRead, identity: withPermissions("builds:read")},
		{name: "exact resource write", resource: "builds", access: auth.AccessWrite, identity: withPermissions("builds:write")},
		{name: "write grants read", resource: "builds", access: auth.AccessRead, identity: withPermissions("builds:write")},
		{name: "read refuses write", resource: "builds", access: auth.AccessWrite, identity: withPermissions("builds:read"), want: auth.ErrForbidden, wantReason: "missing permission builds:write"},
		{name: "wildcard read grants read", resource: "builds", access: auth.AccessRead, identity: withPermissions("*:read")},
		{name: "wildcard read refuses write", resource: "builds", access: auth.AccessWrite, identity: withPermissions("*:read"), want: auth.ErrForbidden, wantReason: "missing permission builds:write"},
		{name: "wildcard write grants write", resource: "builds", access: auth.AccessWrite, identity: withPermissions("*:write")},
		{name: "one of several permissions grants", resource: "builds", access: auth.AccessRead, identity: withPermissions("deployments:write", "builds:read")},
		{name: "another resource refuses", resource: "builds", access: auth.AccessRead, identity: withPermissions("deployments:write"), want: auth.ErrForbidden, wantReason: "missing permission builds:read"},
		{name: "requiring every resource needs the wildcard", resource: "*", access: auth.AccessRead, identity: withPermissions("builds:write"), want: auth.ErrForbidden, wantReason: "missing permission *:read"},
		{name: "the wildcard grants every resource", resource: "*", access: auth.AccessRead, identity: withPermissions("*:read")},
		{name: "no permissions refuse", resource: "builds", access: auth.AccessRead, identity: withPermissions(), want: auth.ErrForbidden, wantReason: "missing permission builds:read"},
		{name: "inactive identity refuses", resource: "builds", access: auth.AccessRead, identity: inactiveWriter, want: auth.ErrForbidden, wantReason: "inactive"},
		{name: "no identity is unauthenticated", resource: "builds", access: auth.AccessRead, want: auth.ErrUnauthenticated, wantReason: "no identity"},
		{name: "empty resource refuses", resource: "", access: auth.AccessRead, identity: withPermissions("*:write"), want: auth.ErrForbidden, wantReason: "missing permission :read"},
		{name: "invalid resource refuses", resource: "Builds", access: auth.AccessRead, identity: withPermissions("*:write"), want: auth.ErrForbidden, wantReason: "missing permission Builds:read"},
		{name: "invalid access refuses", resource: "builds", access: auth.Access("admin"), identity: withPermissions("*:write"), want: auth.ErrForbidden, wantReason: "missing permission builds:admin"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := authorization.HasPermission(testCase.resource, testCase.access)(withIdentity(t, testCase.identity))

			if testCase.want == nil {
				require.NoError(t, err)
				return
			}
			var refusal *auth.Error
			require.ErrorAs(t, err, &refusal)
			require.ErrorIs(t, err, testCase.want)
			require.Equal(t, testCase.wantReason, refusal.Reason)
		})
	}
}

func TestHasPermissionChecksTheEffectiveIdentity(t *testing.T) {
	impersonated := &auth.Identity{
		Provider: "password", Subject: "user-7", Active: true,
		Impersonator: &auth.Identity{Provider: "password", Subject: "admin-1", Active: true, Permissions: []auth.Permission{{Resource: "*", Access: auth.AccessWrite}}},
	}
	ctx := withIdentity(t, impersonated)

	requireRefusal(t, auth.ErrForbidden, authorization.HasPermission("builds", auth.AccessRead)(ctx))
	requireRefusal(t, nil, authorization.Real(authorization.HasPermission("builds", auth.AccessRead))(ctx))
}

func TestReasonsStayServerSide(t *testing.T) {
	err := authorization.HasRole("payroll-auditor")(withIdentity(t, activeIdentity()))

	var refusal *auth.Error
	require.ErrorAs(t, err, &refusal)
	require.Contains(t, refusal.Reason, "payroll-auditor")
	status, response := auth.ResponseFor(err)
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, auth.ErrorResponse{Code: "forbidden", Message: "access denied"}, response)

	err = authorization.HasPermission("payroll", auth.AccessWrite)(withIdentity(t, activeIdentity()))

	require.ErrorAs(t, err, &refusal)
	require.Equal(t, "missing permission payroll:write", refusal.Reason)
	status, response = auth.ResponseFor(err)
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, auth.ErrorResponse{Code: "forbidden", Message: "access denied"}, response)
}
