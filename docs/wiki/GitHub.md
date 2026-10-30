# GitHub

GitHub OAuth login with PKCE; access only for members of `AllowedTeams`, `auth.RoleAdmin` for `AdminTeams` members, teams re-checked every minute. The OAuth token stays server-side; `Provider.HTTPClient` calls the GitHub API as the user.

## Wiring

From [examples/github/main.go](../../examples/github/main.go) (gin; tested against the in-repo fake GitHub). On `net/http` mount the routes with `auth.RegisterRoutes` as on the [Password](Password.md#wiring) page.

```go
	provider, err := github.New(&github.Options{
		ClientID:     options.ClientID,
		ClientSecret: options.ClientSecret,
		ExternalURL:  options.ExternalURL,
		AllowedTeams: options.AllowedTeams,
		AdminTeams:   options.AdminTeams,
		AuthorizeURL: options.AuthorizeURL,
		TokenURL:     options.TokenURL,
		APIURL:       options.APIURL,
		Sessions:     store,
		Observer:     ginadapter.Observe, // auth.* fields on the request's wide event
	})
	if err != nil {
		return nil, err
	}
	guard, err := session.NewGuard(&session.GuardOptions{
		Store:      store,
		LoginURL:   provider.LoginURL(),
		Refreshers: []session.Refresher{provider}, // refetches teams every minute
		Observer:   ginadapter.Observe,
	})
```

Register `ExternalURL + "/auth/github/callback"` as the OAuth app's callback URL. Empty `AuthorizeURL`, `TokenURL` and `APIURL` mean github.com; set all three for GitHub Enterprise.

## Routes

Prefix `PathPrefix`, default `/auth/github`.

| Method and path | Purpose |
|---|---|
| `GET /login` | starts the login, 302 to GitHub; `?return_to=<path>` as for OIDC |
| `GET /callback` | checks teams, rotates the session, stores identity and token, 302 to the return path |
| `GET /logout` | ends the session, revokes the token at GitHub (best effort), 302 to `PostLogoutURL` |
| `POST /refresh-teams` | re-checks teams now; 200 identity, 401/403 ends the session, 409 `conflict` when another request changed the session meanwhile |

## Identity

`Provider` `github`, `Subject` the numeric GitHub user ID, `Username` the login, `Teams` only the teams named in `AllowedTeams`, `AdminTeams` or `RelevantTeams` (`org/team-slug`, lower-case, sorted), `Roles` `[admin]` for admin team members.

## Options that matter

| Option | Default | Note |
|---|---|---|
| `ClientID`, `ClientSecret`, `ExternalURL`, `Sessions` | required | `Sessions` must not be SameSite Strict |
| `AllowedTeams` | required, at least one | `org/team-slug`, case-insensitive; everybody else gets 403 and no session |
| `AdminTeams` | none | admin only together with an allowed team |
| `RelevantTeams` | none | extra teams kept in `Identity.Teams` for your own checks |
| `Scopes` | `read:org` | must include `read:org`, `write:org`, `admin:org`, `user` or `repo` |
| `PostLogoutURL`, `ErrorURL` | `ExternalURL + "/"`, none | as for [OIDC](OIDC.md#options-that-matter) |

## Refresh

The provider as `Refresher` refetches teams once per `GuardOptions.RefreshInterval` (default 1 min). Removed from every allowed team or token revoked: the session ends. GitHub down or rate-limiting: the session keeps its teams for at most `GuardOptions.MaximumUnverifiedAge` (default 1 h) since the last successful check, then ends. See [Sessions](Sessions.md#refresh).

## Refusal codes

`login_expired`, `state_mismatch` (400), `login_denied`, `login_failed` (401) on the callback; `forbidden` (403) for users outside `AllowedTeams` and cross-site `/logout` or `/refresh-teams`; `conflict` (409) on `/refresh-teams`; `internal` (500) when GitHub is down.

## Gotchas

- Do not forget `Refreshers: []session.Refresher{provider}`: without it team removals never reach running sessions.
- `HTTPClient(ctx, session)` needs the session handle from `store.Open(request)`; it sends the token only to `APIURL`'s host. Example: `ExampleProvider_HTTPClient` in [github/example_test.go](../../github/example_test.go).
- Logout and refresh-teams refuse `Sec-Fetch-Site: cross-site` with 403.

Source: [github/](../../github/) ([provider.go](../../github/provider.go), [handlers.go](../../github/handlers.go), [teams.go](../../github/teams.go), [api.go](../../github/api.go)).
