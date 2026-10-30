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

Prefix `PathPrefix`, default `/auth/password`. The provider reads sessions itself, so its routes need no Guard. Bodies are JSON (`Content-Type: application/json`, at most 64 KiB, unknown fields refused).

| Method and path | Answer | Registered when |
|---|---|---|
| `POST /login` `{"identifier","password"}` | 200 identity, or 202 `{"challenge":"totp"}` / `{"challenge":"totp_setup"}` | always |
| `POST /logout` | 204; 403 `forbidden` for a request the browser marks `Sec-Fetch-Site: cross-site` | always |
| `POST /register` `{"username","email","password"}` (at least one of username, email) | 201 identity (logged in), or 202 `{"challenge":"totp_setup"}` with `TOTP.Required` | `EnableRegistration` |
| `POST /totp/verify` `{"code","backupCode":false}` | 200 identity; `"backupCode":true` checks the code against the backup codes only, `false` against the TOTP codes only | `TOTP.Enabled` |
| `GET /totp` | 200 `{"enabled"}` | `TOTP.Enabled` |
| `POST /totp/setup` `{}` | 200 `{"secret","otpauthUrl","issuer","accountName"}` | `TOTP.Enabled` |
| `POST /totp/enable` `{"code","password"}` | 200 `{"backupCodes":[...]}`; a wrong code can be retried with the same setup; 409 `totp_already_enabled` when a concurrent enrollment won | `TOTP.Enabled` |
| `POST /totp/disable` `{"password"}` | 204; a pending setup is dropped, so enable needs a new one | `TOTP.Enabled` |

## TOTP and hashes

- `TOTP.Required` enrolls users without a second factor during login and registration (the 202 `totp_setup` challenge, then `/totp/setup` and `/totp/enable`) instead of failing every route.
- Limits: `TOTP.Digits` 6 or 8, `Period` at most 3600 s, `Skew` at most 10, `BackupCodeCount` at most 20; backup codes are at most 128 bytes and the alphabet and length must give at least 1,000,000 distinct codes.
- Every TOTP code is accepted once (`Storage.ConsumeTOTPStep`). `MaximumAttempts` (default 5, no "unlimited") counts wrong codes in a row across logins; then the second factor stays locked until a code is verified or your application calls `Storage.ResetTOTPAttempts`.
- `Policy.MinimumLength` counts characters; passwords are 1-128 bytes. Stable client codes replace translated messages.
- Existing Argon2id hashes verify unchanged; `LegacyVerifier: password.VerifyBcrypt` upgrades bcrypt hashes at the next login, and Argon2id hashes on other parameters than `HashParameters` are rehashed too (only login rehashes, not the password checks of the TOTP routes). A stored hash nothing can verify answers like a wrong password (401 `invalid_credentials`, same cost); unknown users cost the same Argon2id verification as real ones.

## Options that matter

| Option | Default | Note |
|---|---|---|
| `Sessions`, `Storage` | required | |
| `PathPrefix` | `/auth/password` | segments of `A-Z a-z 0-9 . _ ~ -`, no trailing `/`, no `.` or `..` segment |
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
