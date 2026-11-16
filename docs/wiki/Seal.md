# Seal

`github.com/govengers/auth/seal`: authenticated encryption of small secrets at rest, such as TOTP secrets, webhook signing secrets and API tokens of third-party services. A database dump, a backup or a read-only SQL injection then reveals ciphertext, not the secrets.

## Model

- AES-256-GCM with a random nonce under a key derived per value (HKDF-SHA256), the same construction as the session values.
- A sealed value is text: `v1.<key ID>.<base64url>`. It fits a `text` column, JSON and environment values, and names the key that sealed it.
- A key ring: the first key seals, every key opens. Keys rotate without a flag day.
- Every value is bound to `AssociatedData{Purpose, Table, Row}`. A value copied to another row, another column or another purpose does not open (`seal.ErrInvalid`), so whoever can write the table cannot give their own account another user's secret.

## Wiring

```go
// main: SEAL_KEYS="2026-11:<base64 32 bytes>,2026-01:<base64 32 bytes>", primary first; mark it sensitive in config
keys, err := seal.ParseKeys(config.SealKeys)
if err != nil {
	return err
}
sealer, err := seal.New(&seal.Options{Keys: keys})
```

Generate a key with `openssl rand -base64 32`. Key IDs are 1 to 32 characters of `A-Z a-z 0-9 _ -`; a date such as `2026-11` works well. Never reuse an ID for another secret.

## Sealing a column

```go
data := seal.AssociatedData{Purpose: "totp_secret", Table: "users", Row: user.ID.String()}

sealed, err := sealer.Seal(data, []byte(secret)) // store sealed
plaintext, err := sealer.Open(data, sealed)      // read it back
```

Pick values that never change for the row: its primary key, not a name or an email address. Use one `Purpose` per column. All three fields are required.

With the password provider, seal inside your `password.Storage`: `SetTOTP` seals the secret before the `UPDATE`, the `GetUserBy*` methods open it after the `SELECT`. The provider never sees the sealed form. `password/postgresstorage` does exactly that with `Options.Sealer` and brings old rows along with `ResealTOTPSecrets` ([Password](Password.md#storage-on-postgresql)). A column holding sealed and legacy plaintext values tells them apart with `seal.IsSealed(value)` (the `v1.` prefix; base32 and hex never contain a dot).

## Rotation

1. Generate a new key and put it first: `SEAL_KEYS="2026-12:<new>,2026-11:<old>"`. Deploy. New values use the new key, old ones still open.
2. Run a job over every sealed column: `value, resealed, err := sealer.Reseal(data, stored)`; write `value` back only when `resealed` is true (an `UPDATE ... WHERE secret = <stored>` keeps a concurrent change). Values that need it start with `v1.<old ID>.`, so `WHERE secret LIKE 'v1.2026-11.%'` finds what is left.
3. When nothing names the old key, remove it from `SEAL_KEYS`. A value still sealed by a removed key fails with `seal.ErrUnknownKey`.

## Errors

| Error | Meaning |
|---|---|
| `seal.ErrInvalid` | not a sealed value, changed, sealed for other `AssociatedData`, or another secret was configured under the same key ID |
| `seal.ErrUnknownKey` | the value names a key ID the ring does not hold |
| other | an `AssociatedData` field is empty (a programming error) |

Errors never contain the plaintext or a secret; they name the key ID.

## Limits

- For small secrets: a sealed value is about 4/3 of the plaintext plus about 40 characters and the key ID. Large data belongs in encrypted storage, not in a column.
- The keys live in the process. Whoever reads the process environment or memory can open every value; sealing protects data at rest, not a compromised server.
- No metrics or Observer: the package does no I/O, so the returned errors are the whole story. Count `ErrInvalid` in your repository if you want to see tampering.
