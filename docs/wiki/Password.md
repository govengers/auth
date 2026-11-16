# Password

Username or email plus password (Argon2id) against users in your database, with optional TOTP second factor, backup codes and self-registration. JSON endpoints only; your frontend renders the forms.

## Wiring

From [examples/password/main.go](../../examples/password/main.go) (tested by its `main_test.go`):

```go
	provider, err := password.New(&password.Options{
		Sessions:           store,
		Storage:            options.Storage,
		EnableRegistration: true,                                                   // POST /auth/password/register: open sign-up for the demo
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

You implement [`password.Storage`](../../password/storage.go) (11 methods) on your users table, or use the PostgreSQL one below; `password.NewMemoryStorage()` is for tests and examples only. Contracts that matter:

- Usernames and emails are unique and matched ignoring case (unique indexes on `lower(...)`); a duplicate is `password.ErrUserExists` from the unique constraint, not from a lookup before the insert.
- The provider passes login identifiers as typed, always valid UTF-8 (JSON decoding replaces invalid bytes). One with a NUL byte, which PostgreSQL refuses as `text`, never reaches your storage: the provider answers it as an unknown user, so a scanner probing the login form gets a 401, not a 500. Registration caps emails at 254 bytes (RFC 5321), which also keeps them below the btree row limit.
- `UpdatePasswordHash`, `ConsumeTOTPAttempt`, `ConsumeTOTPStep`, `ConsumeBackupCode` and `SetTOTP` are each one atomic statement (compare-and-swap); `SetTOTP` returns `(bool, error)` and enables only while TOTP is off.
- Not found is `password.ErrUserNotFound`.
- SQL for every method: [docs/migration.md](../migration.md#recipe). Create users with `password.Hash(plain, password.DefaultParameters())`; keep roles and flags in your own columns.
- Run the conformance suite [`password/passwordtest`](../../password/passwordtest/passwordtest.go) on your implementation: `passwordtest.Run(t, func(t *testing.T) password.Storage { return newStorage(t) })`, a fresh empty storage per subtest.

### Storage on PostgreSQL

`password/postgresstorage` implements every method on PostgreSQL 18 (`postgresstorage.New(&postgresstorage.Options{Pool: pool})`). Run `postgresstorage.MigrationV1` in one of your goose migrations; it creates `govengers_auth_password_credentials` (user ID, username, email, hash, TOTP state, attempt counter, last TOTP step) with unique indexes on `lower(username COLLATE "C")` and `lower(email COLLATE "C")`.

- Case is folded for ASCII letters only, on every database whatever its default collation: under a Turkish default, plain `lower()` would make `ADMIN` and `admin` two users. Registration allows ASCII usernames and emails only; a user your code creates with non-ASCII letters is matched case-sensitively for those letters (`MemoryStorage` folds them).
- The table holds credentials, not the profile. Keep the profile in your own table under the same ID (`auth.Identity.UserID`) and join on it. With password-only users, reference the credentials (`id uuid PRIMARY KEY REFERENCES govengers_auth_password_credentials (user_id) ON DELETE CASCADE`) and create the profile row in `OnLogin` (`INSERT ... ON CONFLICT DO NOTHING`); when users also come from OIDC or GitHub, point the foreign key the other way or leave it out.
- The storage names every column it reads and writes, so columns your migrations add (nullable or with a default) do not break it; your own table is still the better home.
- The library never deletes users: delete the credentials row in your own statement.
- Relies on READ COMMITTED, PostgreSQL's default: the compare-and-swap statements re-check their condition on the row a concurrent call left. Under a REPEATABLE READ server or role default a race fails with an error instead (never a wrong result).
- The TOTP secret is stored as the provider hands it over (plaintext base32), unless you set `Options.Sealer`: then `CreateUser` and `SetTOTP` seal it with [`seal`](Seal.md) (purpose `totp_secret`, table `govengers_auth_password_credentials`, row the user ID) and reads open it. Plaintext rows written before keep working; `storage.ResealTOTPSecrets(ctx)` seals them, and after a key rotation moves every secret to the new primary key (it returns how many rows it changed; rerun it until it answers 0 before you remove the old key). It stops at the first secret that does not open (copied from another row, or sealed by a key no longer in the ring) and names the user; no row after it is processed until you repair it (`ClearTOTP` for that user, who enrolls again, or restore the value), then rerun. Without a Sealer a sealed value fails to read, so never remove the option once rows are sealed. Sessions survive sealing and rotation: the credential stamp is computed over the plaintext.

Rollout order: first deploy the Sealer (and, for a rotation, the new key first in the ring) to every replica; only then run `ResealTOTPSecrets` once, from a one-off job or admin command, not from `main` of each replica. A replica still without the Sealer answers every login of a user with a sealed secret with 500, and one unopenable row would fail every start of an application that treats the error as fatal.

```go
keys, err := seal.ParseKeys(os.Getenv("SEAL_KEYS")) // "2026-11:<base64>", primary first
sealer, err := seal.New(&seal.Options{Keys: keys})
storage, err := postgresstorage.New(&postgresstorage.Options{Pool: pool, Sealer: sealer})

// Separate step (one-off job or admin command), after every replica runs with the Sealer:
changed, err := storage.ResealTOTPSecrets(ctx)
```

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
- Existing Argon2id hashes verify unchanged; `LegacyVerifier: password.VerifyBcrypt` upgrades bcrypt hashes at the next login, and Argon2id hashes on other parameters than `HashParameters` are rehashed too (only login rehashes, not the password checks of the TOTP routes). A stored hash nothing can verify answers like a wrong password (401 `invalid_credentials`, same cost); unknown users cost the same Argon2id verification as real ones, except users whose hash is still a legacy one: they cost the legacy verification until their first login ([Security](Security.md#known-limits)).

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

## Changing a password

The provider has no password-change or reset route; your application does it: confirm the current password (`password.Verify` against the stored hash, or a fresh login), check the new one with `Policy.Validate` (the provider's `Options.Policy`), then `Storage.UpdatePasswordHash(ctx, id, currentHash, password.Hash(newPassword, parameters))`. Every session of the user, including the one that asked for the change, ends within `RefreshInterval` (default 1 minute), and the TOTP routes refuse them at once; let the user log in again with the new password.

## Refusal codes

`invalid_credentials` (401: login, TOTP enable and disable), `no_pending_login` and `invalid_totp_code` (401: verify, enable), `totp_setup_missing` (400), `totp_already_enabled`, `totp_not_enabled` (409), `user_exists` (409), `weak_password`, `invalid_username`, `invalid_email` (400: register), `forbidden` (403: cross-site logout; the TOTP routes for an impersonating or inactive identity). Shape and mapping: [Errors-and-Observability](Errors-and-Observability.md).

## Gotchas

- `OnLogin` must keep `identity.UserID` (the `Storage` user ID); return `identity.Clone()` with changes. A replaced `UserID` fails the login with 500.
- The provider as `Refresher` re-reads the user every minute and updates only `Username` and `Email`; a deleted user loses the session, and so does a session opened before the user's password hash or second factor changed (`UpdatePasswordHash`, a login's rehash, TOTP enable or disable in another session); the TOTP routes refuse such a session at once. The session that enabled or disabled TOTP, or whose login rehashed the password, stays. Sessions from before this check (no credential stamp) end at their first refresh: users log in once more after the upgrade. A login pending its second factor (or its enrollment) is bound the same way: after a password or second-factor change it ends with `no_pending_login`, so a TOTP or backup code alone never completes a login with the old password. Roles added by `OnLogin` stay until the session ends.
- `TOTP.Enabled` off while users have TOTP enrolled: their logins fail with 500. Clear their TOTP first.
- Anyone with the password can lock the second factor (`MaximumAttempts`); rate-limit `/login` and `/totp/verify` at the edge, and `/register` too (each costs an anonymous Argon2id). There is no in-process rate limit.
- With `TOTP.Required`, enrollment is trust-on-first-use.
- Usernames are 3-50 of `[a-zA-Z0-9_]` and never contain `@`; the one `identifier` field is an email when it contains `@`.

Source: [password/](../../password/) ([provider.go](../../password/provider.go), [options.go](../../password/options.go), [storage.go](../../password/storage.go), [login.go](../../password/login.go), [totp_routes.go](../../password/totp_routes.go)).
