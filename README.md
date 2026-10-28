# auth

A small Go library for common authentication and authorization primitives. It
provides Argon2id password hashing, opaque bearer-token helpers, and exact
permission checks without tying applications to an HTTP framework or storage
backend.

## Quick start

```go
passwordHash, err := auth.HashPassword(password)
if err != nil {
    return err
}

valid, err := auth.VerifyPassword(password, passwordHash)
if err != nil || !valid {
    return ErrInvalidCredentials
}

token, err := auth.NewToken()
if err != nil {
    return err
}
tokenDigest := auth.DigestToken(token)
// Persist tokenDigest (not token), with an expiry and revocation state.

principal := auth.Principal{
    Subject:     userID,
    Permissions: []string{"documents:read"},
}
if err := auth.Authorize(principal, "documents:read"); err != nil {
    return err
}
```

## Security boundaries

- Password hashes use Argon2id with a random salt. Treat malformed stored hashes
  as data/integrity errors; do not silently accept them.
- Tokens are random opaque bearer credentials. Persist their digest, compare
  presented tokens with `TokenMatches`, and implement expiry, revocation,
  transport, and rate limiting in the application or its store.
- `Authorize` checks exact permission strings only. Authentication, loading a
  principal's permissions, and enforcing authorization on every protected
  operation remain the caller's responsibility.
- Never log passwords, bearer tokens, or other credentials. Use TLS when
  transmitting credentials.

## Development

Run the test suite with `go test ./...`.