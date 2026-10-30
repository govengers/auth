# Errors and observability

Every refusal is an `*auth.Error` and every response the library writes is `{"code","message"}` with `Cache-Control: no-store`. Components never log; they report one `auth.Outcome` per action to an optional `auth.Observer`.

## auth.Error

`&auth.Error{Kind, Code, Reason, Err}`: `Kind` is one of the four sentinels and decides status and message; `Code` replaces the default code (stable, for frontends); `Reason` and `Err` stay server-side (wide event, outcome), never in the body. Branch with `errors.Is(err, auth.ErrForbidden)`; the kind survives `%w` wrapping.

| Kind | Status | Default code | Message |
|---|---|---|---|
| `auth.ErrUnauthenticated` | 401 | `unauthenticated` | `authentication required` |
| `auth.ErrForbidden` | 403 | `forbidden` | `access denied` |
| `auth.ErrInvalidRequest` | 400 | `invalid_request` | `invalid request` |
| `auth.ErrConflict` | 409 | `conflict` | `conflict` |
| anything else | 500 | `internal` | `internal error` |

`auth.ResponseFor(err)` returns status and body (the outermost `*auth.Error` decides); `auth.WriteError(writer, err)` writes them. Tested ([example_test.go](../../example_test.go)):

```go
	refusal := &auth.Error{Kind: auth.ErrForbidden, Reason: "missing role admin"}

	status, response := auth.ResponseFor(fmt.Errorf("open report: %w", refusal))
```

The output is `403 forbidden access denied`: the Reason is gone. Your own code returns the same type with its own `Code`, e.g. `&auth.Error{Kind: auth.ErrForbidden, Code: "plan_limit", Reason: "..."}`: `Code` replaces the default code, `Reason` and the wrapped cause never reach the client.

## Client codes

Stable codes for frontends; the kind decides the status.

| Code | Kind | Raised by |
|---|---|---|
| `invalid_credentials` | unauthenticated | password login, TOTP enable and disable |
| `no_pending_login`, `invalid_totp_code` | unauthenticated | password TOTP verify (`invalid_totp_code` also on enable) |
| `totp_setup_missing` | invalid request | password TOTP enable |
| `totp_already_enabled`, `totp_not_enabled` | conflict | password TOTP setup, enable, disable |
| `user_exists` | conflict | password register |
| `weak_password`, `invalid_username`, `invalid_email` | invalid request | password register |
| `login_expired`, `state_mismatch` | invalid request | OIDC and GitHub callback |
| `login_denied`, `login_failed` | unauthenticated | OIDC and GitHub callback |
| `invalid_api_key` | unauthenticated | `apikey` |
| `invalid_token` | unauthenticated | `jwt` verifier |
| `already_impersonating`, `not_impersonating` | conflict | `session.Impersonator` start, stop |
| `unknown_impersonation_target`, `self_impersonation` | invalid request | `session.Impersonator` start |
| `not_found`, `unavailable` | (404, 503) | forward-auth binary only: unknown route, readiness while shutting down or Redis down |

With `ErrorURL` set, OIDC and GitHub callbacks send the same codes as `?code=<code>`, `internal` included.

## Observer and Outcome

`type Observer func(ctx context.Context, outcome auth.Outcome)`, an option on every provider, `session.Guard`, `session.Impersonator`, `apikey.Authenticator` and `jwt.Verifier`. Called synchronously, at most once per action per request; it must not block.

`Outcome{Provider, Action, Result, Err, Identity}`:

- `Provider`: the provider's name (`password`, an OIDC `Name`, `github`, `apikey`, `jwt`, or `session` when the Guard found no identity).
- `Action`: `login`, `callback`, `logout`, `frontchannel_logout`, `register`, `totp_*`, `refresh_teams`, `authenticate` (per request: Guard, `apikey`, `jwt`), `refresh` (Guard calling a Refresher), `impersonation_start`, `impersonation_stop` (`session.Impersonator`).
- `Result`: `success`, `challenge` (TOTP pending), `denied` (an `*auth.Error` was answered), `error` (500).
- `Err` with `Result` `success`: a degraded success (e.g. GitHub token revocation failed, a refresh failed but the identity was kept).

Ready-made observers: `ginadapter.Observe` (fields on the request's wide event, [Gin](Gin.md#wide-events)) and `prometheusadapter.OutcomeCounter.Observe` (`<namespace>_auth_outcomes_total{provider,action,result}`, [Gin](Gin.md#prometheus)). Combine several in one closure.

## What is never recorded

Tokens, secrets, session IDs, passwords, TOTP codes, emails and names never appear in an error message, an `Outcome`, a wide-event field or a metric label; IDs (`Subject`, `UserID`) do. Errors of outbound calls name method, origin and a classified cause, never path, query or response bytes. The exception is your own wiring: the wide-event middleware's `request.query` unless you mount `ginadapter.RedactQuery` (see [Gin](Gin.md#wide-events)) and the text of your `apikey.Resolver` and hook errors.

Source: [errors.go](../../errors.go), [response.go](../../response.go), [outcome.go](../../outcome.go), [design section 5](../design.md#5-errors-json-shape-status-mapping-wide-event-recording).
