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
| `/logout` | ends the local session and sends the browser to the IdP's end-session endpoint with the stored ID token as hint; without a stored ID token (the local session had already expired) straight to `PostLogoutURL`, and the IdP session stays; link to it from your UI |
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
| `AllowedEmailDomains` | none | requires `email_verified`; ASCII domains, an internationalized one in its `xn--` form; with `oidc.GoogleIssuer` a listed domain other than `gmail.com`/`googlemail.com` also requires the `hd` claim to equal it (see Google below) |
| `AllowAnyAccount` | `false` | with `oidc.GoogleIssuer` and neither `AllowedEmailDomains` nor `OnLogin`, `oidc.New` refuses to start; set it to admit every Google account on purpose |
| `PostLogoutURL` | `ExternalURL + "/"` | path or absolute `http(s)` URL without fragment; a path is made absolute with `ExternalURL` |
| `ErrorURL` | none (JSON answers) | every callback failure redirects to `ErrorURL?code=<code>` (`code=internal` for a server-side failure); same URL rules as `PostLogoutURL` |
| `OnLogin`, `OnLogout` | none | `OnLogin` is where you provision your application user and set `UserID` |

Without Keycloak, `OIDCRoles` (`realm_access.roles`), `OIDCClientRoles` (`resource_access.<client>.roles`) and `Groups` (`groups`) come from the access token, per claim from the ID token when the access token lacks it. Only a JWT access token signed by the issuer whose `sub` equals the verified ID token's `sub` counts; an opaque token, one that does not verify or one issued to another subject is ignored, and the claims come from the ID token alone.

## Keycloak enrichment

`keycloak.New(&keycloak.Options{...})` returns a client whose `Enrich` is an `auth.Hook`; set it as `OnLogin` (or call it first inside your own hook). It replaces `OIDCRoles` (composite realm roles), `OIDCClientRoles` (of `ClientRolesClientID`), `Groups` (paths) and `Attributes` with the Admin API's answer and refuses the login with 403 (the role name stays server-side) when `RequiredRealmRoles`, `RequiredClientRoles` or `RequiredGroups` are missing; `RequiredClientRoles` needs `ClientRolesClientID`. It authenticates with the client credentials grant of a service account (`ClientID`, `ClientSecret`), which needs the `realm-management` roles `view-users`, `query-users` and `query-groups` (it reads the user, its role mappings, groups and attributes) and, with `ClientRolesClientID`, `view-clients` and `query-clients` (it looks the client up by its client ID). The `password` grant (`GrantType: keycloak.GrantTypePassword`, client `admin-cli` by default) breaks as soon as the admin user gets an OTP credential. Tested excerpt: [oidc/keycloak/example_test.go](../../oidc/keycloak/example_test.go).

## Refusal codes

`login_expired`, `state_mismatch` (400), `login_denied`, `login_failed` (401) on the callback; `forbidden` (403) for a disallowed email domain, a missing required Keycloak role or group, an `OnLogin` refusal and a cross-site `/logout`; `internal` (500) when the IdP is down. With `ErrorURL` the same codes arrive as `?code=`.

- The IdP rejecting the authorization code (an error answer below 500) is 401 `login_failed`; a 5xx answer or an IdP that cannot be reached is 500.
- An ID token without `sub` is refused; one that does not verify is 401 `login_failed` with the fixed Reason `ID token expired` or `ID token verification` on the outcome (an unreachable JWKS reads like an invalid token: go-oidc's message quotes the token and the server's text).

## Gotchas

- `oidc.New` refuses a `Sessions` store whose cookie is SameSite Strict: the callback would arrive without it.
- OIDC has no `Refresher`: roles and groups are read at login and stay until the session ends (`StoreOptions.MaximumAge`, default 24 h).
- `/logout` refuses `Sec-Fetch-Site: cross-site` with 403 and ends nothing: logout links must live on the app's own site. Front-channel logout from the IdP's iframe still works.
- Front-channel logout needs `StoreOptions.SameSite: http.SameSiteNoneMode` (https only), else the IdP's iframe gets no cookie.
- No component follows a redirect of the issuer's endpoints: point `Issuer` at the final URL.
- Google: `Issuer: oidc.GoogleIssuer` (`https://accounts.google.com`), `ClaimMapper: oidc.GoogleClaimMapper`, and an admission: `AllowedEmailDomains`, an `OnLogin` that refuses strangers, or `AllowAnyAccount: true`; `oidc.New` refuses the Google issuer with none of them, because anyone can create a Google account. The rule keys on the issuer, not the claim mapper: a mapper only reads the profile.
- Google sets `hd` only for Workspace (Cloud Identity) accounts, and a consumer Google account can carry a verified address of any domain (a former employee can create one with the company address and keep it after leaving the Workspace). So with the Google issuer every allowed domain except `gmail.com` and `googlemail.com` also requires `hd` to equal the email's domain; a consumer account with a company address is refused 403 (Reason `hosted domain mismatch`). Admit such accounts through `OnLogin` instead.

Source: [oidc/](../../oidc/) ([provider.go](../../oidc/provider.go), [login.go](../../oidc/login.go), [logout.go](../../oidc/logout.go), [claims.go](../../oidc/claims.go)), [oidc/keycloak/keycloak.go](../../oidc/keycloak/keycloak.go).
