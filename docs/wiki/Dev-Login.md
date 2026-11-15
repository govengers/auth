# Dev login

`github.com/govengers/auth/devlogin`: a one-click login as any of your application's users, for local development. The login page lists the users, a click logs in as one of them, and the result is a normal session in your `session.Store`: the Guard, authorization checks, impersonation and logout behave exactly as after a real login.

**Never enable it outside local development.** Anyone who reaches the routes becomes any user, admins included, without a credential.

## Wiring

```go
// main: the only place that reads configuration
if config.DevLogin {
	// The guard in main: dev login only together with a plain-HTTP cookie, which a deployment behind TLS never sets.
	if !config.SessionInsecureCookie {
		return errors.New("DEV_LOGIN needs SESSION_INSECURE_COOKIE: dev login is for local plain HTTP only")
	}
	dev, err := devlogin.New(&devlogin.Options{
		Enabled:  true,
		Sessions: store,
		Users:    users.DevLoginList, // func(ctx) ([]devlogin.User, error)
		Load:     users.DevLoginIdentity, // func(ctx, id) (*auth.Identity, error)
		Observer: observer,
	})
	if err != nil {
		return err
	}
	auth.RegisterRoutes(serveMux, dev.Routes()) // or ginadapter.RegisterRoutes; never behind the Guard
}
```

- `Enabled` must be `true`: `New` fails otherwise. Without your flag there is no provider and no route; a disabled dev login answers 404 because it does not exist.
- `Users` returns the list (`ID`, `Name`, optional `Description` such as "admin"). Keep it short: seed users, not your whole table.
- `Load` returns the identity a real login of that user gets: `UserID`, `Username`, `Roles`, `Active: true`, whatever your `OnLogin` hook would set. Return `nil, nil` for an unknown ID. The provider overwrites `Provider` with `"dev_login"` (`auth.ProviderDev`) and `Subject` with the ID, so audit logs and the wide event show that the session came from the dev login, and the password provider's `Refresher` never claims it.

## Routes

| Route | Body | Answer |
|---|---|---|
| `GET /auth/dev/users` | | `200 {"users":[{"id","name","description"}]}` |
| `POST /auth/dev/login` | `{"id":"<user ID>"}` (`Content-Type: application/json`) | `200` identity JSON (like `GET /auth/me`) and the session cookie |
| `POST /auth/dev/logout` | | `204`, the session ended |

`PathPrefix` moves them (default `/auth/dev`). Refusals use the library's JSON error shape:

| Status, code | When |
|---|---|
| 403 `dev_login_not_local` | the local-only check failed (below) |
| 400 `unknown_dev_user` | `Load` returned nil |
| 400 `invalid_request` | not strict JSON, unknown field, empty ID |
| 403 `forbidden` | the identity is inactive, `Load` refused with an `*auth.Error` of that kind, or a cross-site request |
| 500 `internal` | `Users` or `Load` failed, the session backend failed |

## The local-only check (on by default)

Every route refuses a request unless all of these hold:

- the `Host` header is `localhost`, `*.localhost`, a loopback address or one of `AllowedHosts`, which stops a DNS-rebinding page from using your local server under its own name;
- the TCP peer is a loopback address (`127.0.0.0/8`, `::1`);
- no `Forwarded`, `Via`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Port`, `X-Forwarded-Proto`, `X-Forwarded-Server` or `X-Real-IP` header is present, which catches a reverse proxy on the same machine that announces itself (its requests come from loopback for every client).

`AllowRemote: true` drops the last two conditions and keeps the Host check. Stacks where the browser's request arrives from a container network (docker port publishing, devcontainers) need it; the browser still sends `Host: localhost` there. A stack behind a named local proxy (say `https://app.test`) also lists that name in `AllowedHosts`. Keep the insecure-cookie guard in `main` in both cases, it is the remaining barrier.

The check is a seat belt, not a boundary. It cannot see a proxy on the same machine that rewrites `Host` to its loopback upstream and sends no forwarding header; every client of such a proxy passes as local. Known shapes: `httputil.ReverseProxy` with a `Rewrite` that calls `SetURL` (it strips forwarding headers), nginx `proxy_pass http://127.0.0.1:8080` without `proxy_set_header`, and a Vite or Quasar dev server proxy with `changeOrigin: true` that listens on the LAN (`--host`), which lets every LAN client in. A Vite dev server on localhost proxying to the Go server passes, as intended.

## Observability

Every request reports one `auth.Outcome` with provider `dev_login`: action `list_users`, `login` or `logout`. With `prometheusadapter` that is `<namespace>_auth_outcomes_total{provider="dev_login",...}`; with `ginadapter.Observe` the wide event names the provider. Alert on any `provider="dev_login"` outcome in a production metric source.

## Gotchas

- There is no `Refresher`: a dev session keeps what `Load` returned until `MaximumAge` or logout. Log in again after changing a seed user's roles.
- `Load` must not return an impersonating identity (`Impersonator` set): the session refuses to save it (500). Impersonate through `session.Impersonator` after logging in.
- The login route needs `Content-Type: application/json` and refuses `Sec-Fetch-Site: cross-site`, so a page on another site cannot log a browser in or out.
