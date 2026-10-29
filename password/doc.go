// Package password is the password login provider: JSON endpoints over net/http for login by username or
// email, an optional TOTP second factor with backup codes, optional self-registration (off by default) and
// logout. Passwords are hashed with Argon2id; hashes of another scheme (bcrypt with VerifyBcrypt) verify
// through Options.LegacyVerifier and are upgraded to Argon2id at the next login.
//
// Users live in the application's database behind Storage; MemoryStorage serves tests and examples. A
// successful login stores an auth.Identity in a session.Store session, which a session.Guard then
// authenticates; the Provider is also the session.Refresher that ends the sessions of deleted users.
//
// Login answers 200 with the identity, or 202 {"challenge":"totp"} when the user has TOTP (verify the code
// at POST {prefix}/totp/verify) and 202 {"challenge":"totp_setup"} when TOTPOptions.Required makes a user
// without TOTP enroll first (POST {prefix}/totp/setup, then /totp/enable). Refusals are the JSON shape of
// auth.ErrorResponse with stable codes such as invalid_credentials and invalid_totp_code.
//
// The provider never logs and never starts goroutines; it reports every request to the optional
// auth.Observer. It is safe for concurrent use.
package password
