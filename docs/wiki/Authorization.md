# Authorization

An `authorization.Check` is `func(ctx context.Context) error` over the `auth.Identity` in the context: `nil` allows, `*auth.Error` refuses (401 without identity, 403 otherwise), a plain error is a wiring mistake (500, fails closed): a `nil` check, `All()` or `Any()` without checks, `HasPermission` with an invalid resource or access. The same check guards HTTP routes, WebSocket messages and jobs.

## Identity fields and who fills them

| Field | Filled by |
|---|---|
| `Provider`, `Subject` | every provider (`password`, an OIDC `Name`, `github`, `apikey`; a verified JWT keeps the provider it was signed for) |
| `UserID` | password provider (the `Storage` ID); otherwise `uuid.Nil` until your `OnLogin` hook sets it |
| `Active` | providers set `true`; hooks and `apikey.Resolver` decide; every check except `IsAuthenticated` refuses an inactive identity, and an identity whose impersonator is inactive (403, Reason `inactive`) |
| `Roles` | application roles: `github` `AdminTeams` (`auth.RoleAdmin`), API keys, JWT, your `OnLogin` hook |
| `OIDCRoles`, `OIDCClientRoles`, `Groups` | OIDC tokens or `keycloak.Client.Enrich` |
| `Teams` | `github` |
| `Permissions` | API keys, the JWT `permissions` claim, your `OnLogin` hook; browser sessions have none by default |
| `Claims`, `Attributes`, `Data` | ID token or JWT claims, Keycloak attributes, your hooks; never in `IdentityResponse` |
| `Impersonator` | your code, while one identity acts as another |

Read it with `auth.IdentityFrom(ctx)` (nil without one); never mutate it, `Clone()` first.

## Checks

Primitives: `IsAuthenticated`, `IsActive`, `IsUser`, `IsAdmin`, `HasRole`, `HasUserID`, `HasOIDCRole`, `HasOIDCGroup`, `HasGitHubTeam`, `HasPermission`. Combinators: `All`, `Any`, `Not`, `Real` (evaluate against the impersonator). Tested ([authorization/example_test.go](../../authorization/example_test.go)):

```go
	ownerID := uuid.MustParse("0b6f2c1e-7a3d-4c55-9f0e-2d8b1a6c4e71")
	ownerOrAdmin := authorization.Any(authorization.IsAdmin(), authorization.HasUserID(ownerID))
```

```go
	editor := authorization.All(authorization.HasOIDCGroup("/engineering"), authorization.Not(authorization.HasOIDCRole("read-only")))
```

`Not` refuses a missing or inactive identity before it inverts and inverts only a refusal answered 403 (the kind of the outermost `*auth.Error`, as `auth.ResponseFor` decides), never a 401 that wraps a forbidden cause, so `Not(HasRole("x"))` never admits anonymous or deactivated users and never turns a wiring mistake into a pass. `All` returns the first refusal; `Any` returns a failed check (500) in preference to a refusal for the same reason.

## Mounting a check

gin: `ginadapter.Require(check)` after `ginadapter.Middleware(guard.RequireAPI())` ([Gin](Gin.md)). net/http has no built-in middleware; the examples use this one ([examples/password/main.go](../../examples/password/main.go)):

```go
func authorize(check authorization.Check) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if err := check(request.Context()); err != nil {
				auth.WriteError(writer, err) // generic body; the Reason stays server-side
				return
			}
			next.ServeHTTP(writer, request)
		})
	}
}
```

```go
	serveMux.Handle("DELETE /api/notes", guard.RequireAPI()(authorize(authorization.IsAdmin())(http.HandlerFunc(deleteNotes))))
```

## Permissions

`auth.Permission{Resource, Access}`, text form `<resource>:<access>` (`builds:write`, `*:read`) in Go (`auth.ParsePermission`, `String`), JSON, the JWT claim and the image's `API_KEY_PERMISSIONS`. `write` includes `read`; resource `*` (`auth.AllResources`) covers all; a resource matches `[a-z0-9][a-z0-9._-]{0,63}`, case-sensitive, so a typo fails at startup. No permission means no access.

- `authorization.HasPermission(resource, access)`; gin: `ginadapter.RequireMethodPermission(resource)` (GET, HEAD, OPTIONS need read, the rest write).
- `HasPermission` checks the effective identity; wrap it in `Real` to check the impersonator.
- In your own code: `identity.Permits(resource, access)` applies the same rule, `auth.AccessForMethod(method)` maps an HTTP method to the access it needs.
- Interactive users carry permissions only when `OnLogin` grants them; otherwise combine `Any(HasRole(role), HasPermission(resource, access))`.

## Roles from your application

Grant roles and permissions in `OnLogin` (an `auth.Hook`): return `identity.Clone()` with changes, keep `UserID` for password users. Tested hook: `grantRoles` in [examples/password/main.go](../../examples/password/main.go). They are frozen for the session's lifetime; nothing re-reads them.

## Own checks

A check is any function of the `authorization.Check` type: call `authorization.IsActive()(ctx)` first, then read `auth.IdentityFrom(ctx)` and return `&auth.Error{Kind: auth.ErrForbidden, Reason: "..."}` to refuse. The `Reason` never reaches the client. Entity checks (may this user see this order) belong in your application, as such checks. Tenant roles and broadcast filters too. Loading your own user record per request is a middleware after the Guard, see [Your application user](#your-application-user).

## Your application user

`go-basicauth`'s `UserTransformer` swapped the stored user for your own type. Now the Guard puts an `auth.Identity` in the context and your own middleware loads your user after it; a hook cannot add your user object to the context. Tested ([example_application_user_test.go](../../example_application_user_test.go)):

```go
func WithUser(users UserRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			identity := auth.IdentityFrom(request.Context())
			if identity == nil {
				auth.WriteError(writer, &auth.Error{Kind: auth.ErrUnauthenticated})
				return
			}
			user, err := users.ByID(request.Context(), identity.UserID)
			if err != nil {
				auth.WriteError(writer, err) // plain errors answer 500
				return
			}
			if !user.Active {
				auth.WriteError(writer, &auth.Error{Kind: auth.ErrForbidden, Reason: "inactive user"})
				return
			}
			next.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), userKey{}, user)))
		})
	}
}
```

Mount the Guard first, then `WithUser`: `guard.RequireAPI()(WithUser(users)(handler))`; on gin `ginadapter.Middleware(WithUser(users))` after `ginadapter.Middleware(guard.RequireAPI())`.

The password provider sets `UserID` itself (the `Storage` user ID) and its `OnLogin` must keep it. For OIDC and GitHub, provision the user in `OnLogin` so the identity carries your user ID (call `keycloak.Client.Enrich` first when you use it; it returns a copy):

```go
	return func(_ context.Context, identity *auth.Identity) (*auth.Identity, error) {
		provisioned := identity.Clone() // hooks must not mutate their argument
		provisioned.UserID = uuid.NewSHA1(uuid.NameSpaceURL, []byte(identity.Provider+"/"+identity.Subject))
```

An `*auth.Error` from a hook answers with its status (403 refuses the login), anything else with 500; no session is created either way. `OnLogout` gets a context a disconnecting client cannot cancel (every provider; the password provider ends it after 10 s, with its session reads); set your own deadline for slow work in it.

Source: [authorization/authorization.go](../../authorization/authorization.go), [identity.go](../../identity.go), [permission.go](../../permission.go).
