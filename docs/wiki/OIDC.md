# OIDC

OpenID Connect authorization code flow with PKCE and nonce against any IdP (Keycloak, Google, ...), RP-initiated and front-channel logout, optional enrichment from the Keycloak Admin API. One `oidc.Provider` per IdP, all on one `session.Store`.

## Wiring

From [examples/oidc/main.go](../../examples/oidc/main.go) (tested against the in-repo fake issuer, with and without Keycloak):

```go
	var onLogin auth.Hook
	if options.Keycloak != nil {
		enricher, err := keycloak.New(options.Keycloak)
		if err != nil {
			return nil, err
		}
		onLogin = enricher.Enrich // replaces OIDCRoles, OIDCClientRoles, Groups and Attributes; 403 for missing Required* roles
	}
	provider, err := oidc.New(ctx, &oidc.Options{
		Name:         "sso", // Identity.Provider and the route prefix /auth/oidc/sso
		Issuer:       options.Issuer,
		ClientID:     options.ClientID,
		ClientSecret: options.ClientSecret,
		ExternalURL:  options.ExternalURL,
		Sessions:     store,
		OnLogin:      onLogin,
	})
	if err != nil {
		return nil, err
	}
	guard, err := session.NewGuard(&session.GuardOptions{Store: store, LoginURL: provider.LoginURL()})
	if err != nil {
		return nil, err
	}

	serveMux := http.NewServeMux()
	auth.RegisterRoutes(serveMux, provider.Routes()) // GET /auth/oidc/sso/{login,callback,logout,frontchannel-logout}
```

`oidc.New` runs discovery with `ctx` and fails fast when the IdP is unreachable. Register `ExternalURL + PathPrefix + "/callback"` (here `https://app.example.com/auth/oidc/sso/callback`) as redirect URI at the IdP.

## Routes

Prefix `PathPrefix`, default `/auth/oidc/<Name>`. All `GET`.

| Path | Purpose |
|---|---|
| `/login` | starts the login, 302 to the IdP; `?return_to=<path>` is where the user lands afterwards (the Guard's `RequireUI` sets it) |
| `/callback` | the IdP's redirect target; rotates the session, stores the identity, 302 to the return path |
| `/logout` | ends the session, 302 to the IdP's end-session endpoint (or `PostLogoutURL` without a stored ID token); link to it from your UI |
| `/frontchannel-logout` | OIDC front-channel logout, loaded by the IdP in an iframe |

## Options that matter

| Option | Default | Note |
|---|---|---|
| `Name` | required | `[a-z0-9-]{1,32}`; becomes `Identity.Provider`; not `password`, `github`, `apikey`, `session`, `jwt` |
| `Issuer` | required | https (http only on loopback); the endpoints discovery names must be https too |
| `ClientID`, `ClientSecret` | required | confidential client |
| `ExternalURL` | required | public origin; the redirect URI derives from it |
| `Scopes` | `openid profile email` | |
| `ClaimMapper` | `oidc.DefaultClaimMapper` | `oidc.GoogleClaimMapper` for Google |
| `AllowedEmailDomains` | none | requires `email_verified`; set it for Google or any Google account gets in |
| `PostLogoutURL` | `ExternalURL + "/"` | path or absolute URL, no fragment |
| `ErrorURL` | none (JSON answers) | callback failures redirect to `ErrorURL?code=<code>` |
| `OnLogin`, `OnLogout` | none | `OnLogin` is where you provision your application user and set `UserID` |

Without Keycloak, `OIDCRoles` (`realm_access.roles`), `OIDCClientRoles` (`resource_access.<client>.roles`) and `Groups` (`groups`) come from the access token, per claim from the ID token when the access token lacks it.

## Keycloak enrichment

`keycloak.New(&keycloak.Options{...})` returns a client whose `Enrich` is an `auth.Hook`; set it as `OnLogin` (or call it first inside your own hook). It replaces `OIDCRoles` (composite realm roles), `OIDCClientRoles` (of `ClientRolesClientID`), `Groups` (paths) and `Attributes` with the Admin API's answer and refuses the login with 403 when `RequiredRealmRoles`, `RequiredClientRoles` or `RequiredGroups` are missing. It authenticates with the client credentials grant of a service account (`ClientID`, `ClientSecret`), which needs the `realm-management` roles `view-users`, `query-users` and `query-groups`, plus `view-clients` and `query-clients` with `ClientRolesClientID` ([README](../../README.md#oidc-with-keycloak)). Tested excerpt: [oidc/keycloak/example_test.go](../../oidc/keycloak/example_test.go).

## Refusal codes

`login_expired`, `state_mismatch` (400), `login_denied`, `login_failed` (401) on the callback; `forbidden` (403) for a disallowed email domain, a missing required Keycloak role or group, an `OnLogin` refusal and a cross-site `/logout`; `internal` (500) when the IdP is down. With `ErrorURL` the same codes arrive as `?code=`.

## Gotchas

- `oidc.New` refuses a `Sessions` store whose cookie is SameSite Strict: the callback would arrive without it.
- OIDC has no `Refresher`: roles and groups are read at login and stay until the session ends (`StoreOptions.MaximumAge`, default 24 h).
- `/logout` refuses `Sec-Fetch-Site: cross-site` with 403: logout links must live on the app's own site.
- Front-channel logout needs `StoreOptions.SameSite: http.SameSiteNoneMode` (https only), else the IdP's iframe gets no cookie.
- No component follows a redirect of the issuer's endpoints: point `Issuer` at the final URL.
- Google: `Issuer: "https://accounts.google.com"`, `ClaimMapper: oidc.GoogleClaimMapper`, `AllowedEmailDomains`; the `hd` claim is not checked.

Source: [oidc/](../../oidc/) ([provider.go](../../oidc/provider.go), [login.go](../../oidc/login.go), [logout.go](../../oidc/logout.go), [claims.go](../../oidc/claims.go)), [oidc/keycloak/keycloak.go](../../oidc/keycloak/keycloak.go).
