# Password

Username or email plus password (Argon2id) against users in your database, with optional TOTP second factor, backup codes and self-registration. JSON endpoints only; your frontend renders the forms.

## Wiring

From [examples/password/main.go](../../examples/password/main.go) (tested by its `main_test.go`):

```go
	provider, err := password.New(&password.Options{
		Sessions:           store,
		Storage:            options.Storage,
		EnableRegistration: true,                                                   // POST /auth/password/register
		TOTP:               password.TOTPOptions{Enabled: true, Issuer: "Example"}, // optional second factor
		OnLogin:            grantRoles(options.AdministratorID),
	})
	if err != nil {
		return nil, err
	}
	guard, err := session.NewGuard(&session.GuardOptions{
		Store:      store,
		LoginURL:   "/login",                      // where RequireUI sends anonymous browsers
		Refreshers: []session.Refresher{provider}, // a deleted user loses access within a minute
	})
	if err != nil {
		return nil, err
	}

	serveMux := http.NewServeMux()
	auth.RegisterRoutes(serveMux, provider.Routes()) // the provider reads the session itself: no Guard in front
```

`LoginURL` is your frontend's login page: the password provider has no redirect flow.

## Storage

You implement [`password.Storage`](../../password/storage.go) (11 methods) on your users table; `password.NewMemoryStorage()` is for tests and examples only. Contracts that matter:

- Usernames and emails are unique and matched ignoring case (unique indexes on `lower(...)`); a duplicate is `password.ErrUserExists` from the unique constraint, not from a lookup before the insert.
- `UpdatePasswordHash`, `ConsumeTOTPAttempt`, `ConsumeTOTPStep`, `ConsumeBackupCode` and `SetTOTP` are each one atomic statement (compare-and-swap); `SetTOTP` returns `(bool, error)` and enables only while TOTP is off.
- Not found is `password.ErrUserNotFound`.
- SQL for every method: [docs/migration.md](../migration.md#recipe). Create users with `password.Hash(plain, password.DefaultParameters())`; keep roles and flags in your own columns.

## Routes

Prefix `PathPrefix`, default `/auth/password`. Bodies are JSON (`Content-Type: application/json`, at most 64 KiB, unknown fields refused). Full answer table: [README, Password login](../../README.md#password-login).

| Method and path | Purpose | Registered when |
|---|---|---|
| `POST /login` `{"identifier","password"}` | 200 identity, or 202 `{"challenge":"totp"}` / `{"challenge":"totp_setup"}` | always |
| `POST /logout` | 204, ends the session | always |
| `POST /register` `{"username","email","password"}` (at least one of username, email) | 201 identity, logged in | `EnableRegistration` |
| `POST /totp/verify` `{"code","backupCode":false}` | second step of a 202 `totp` login | `TOTP.Enabled` |
| `GET /totp` | `{"enabled"}` | `TOTP.Enabled` |
| `POST /totp/setup` `{}`, `POST /totp/enable` `{"code","password"}` | enroll; enable returns the backup codes | `TOTP.Enabled` |
| `POST /totp/disable` `{"password"}` | 204 | `TOTP.Enabled` |

## Options that matter

| Option | Default | Note |
|---|---|---|
| `Sessions`, `Storage` | required | |
| `PathPrefix` | `/auth/password` | segments of `A-Z a-z 0-9 . _ ~ -`, no trailing `/` |
| `EnableRegistration` | off | off means the route is not registered at all |
| `Policy.MinimumLength` | 12 characters | composition rules opt-in; maximum 128 bytes |
| `TOTP.Enabled`, `TOTP.Issuer` | off | Issuer required when enabled |
| `TOTP.Required` | off | users without TOTP enroll during login (202 `totp_setup`) |
| `TOTP.MaximumAttempts` | 5 | wrong codes in a row across logins; then locked until `Storage.ResetTOTPAttempts` |
| `LegacyVerifier` | none | `password.VerifyBcrypt` upgrades bcrypt hashes at the next login |
| `OnLogin` | none | must keep `UserID` |

## Refusal codes

`invalid_credentials` (401: login, TOTP enable and disable), `no_pending_login` and `invalid_totp_code` (401: verify, enable), `totp_setup_missing` (400), `totp_already_enabled`, `totp_not_enabled` (409), `user_exists` (409), `weak_password`, `invalid_username`, `invalid_email` (400: register), `forbidden` (403: cross-site logout). Shape and mapping: [Errors-and-Observability](Errors-and-Observability.md).

## Gotchas

- `OnLogin` must keep `identity.UserID` (the `Storage` user ID); return `identity.Clone()` with changes. A replaced `UserID` fails the login with 500.
- The provider as `Refresher` re-reads the user every minute and updates only `Username` and `Email`; a deleted user loses the session. Roles added by `OnLogin` stay until the session ends.
- `TOTP.Enabled` off while users have TOTP enrolled: their logins fail with 500. Clear their TOTP first.
- Anyone with the password can lock the second factor (`MaximumAttempts`); rate-limit `/login` and `/totp/verify` at the edge. There is no in-process rate limit.
- With `TOTP.Required`, enrollment is trust-on-first-use.
- Usernames are 3-50 of `[a-zA-Z0-9_]` and never contain `@`; the one `identifier` field is an email when it contains `@`.

Source: [password/](../../password/) ([provider.go](../../password/provider.go), [options.go](../../password/options.go), [storage.go](../../password/storage.go), [login.go](../../password/login.go), [totp_routes.go](../../password/totp_routes.go)).
