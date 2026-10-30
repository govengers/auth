# govengers/auth v1.0.0 - design

Status: 29.10.2026, synced with the implementation on `feat/v1` (every work package, the cleanup pass and the fixes of review rounds 1, 2 and 3 merged). The document describes the code as built; decisions taken during implementation and review are folded into the sections and listed in 7.2 (D22-D34). Inputs: `../auth-analysis.md` (A-x.y refers to its sections), the three source repos, `govengers/standards` (rule IDs in brackets), config v2 (`github.com/govengers/config/v2` v2.0.0, tagged). Infrastructure specifics (CI caller workflow, Dockerfile, GHCR release workflow, compose e2e stack) live in `docs/infrastructure-notes.md`; this document only fixes the contracts code depends on, and that file wins on infra details.

Every exported name below is binding. Unexported names are suggestions unless marked binding. Where this document and a standards rule disagree, the rule wins and the conflict is reported. Where code and this document disagree, one of them has a bug: report it.

---

## 1. Overview and conventions

One module `github.com/govengers/auth` (`go 1.26.0`, tagged `v1.0.0`) replaces `mxcd/go-basicauth`, `mxcd/oidc-fwd-auth` and `mxcd/github-fwd-auth` and adds the generic authorization checks. It also ships the forward-auth binary `cmd/forwardauth` (image `ghcr.io/govengers/forwardauth`).

Core model, in one paragraph: every provider (password, OIDC, GitHub, API key, JWT) produces the same `auth.Identity`. Redirect and password providers store it in one server-side session (`session.Store`, cookie carries only a random ID). One provider-independent `session.Guard` turns a request with a session into a request with `auth.Identity` in its `context.Context`, or refuses it (401 JSON for APIs, 302 to a login URL for UIs). Authorization is `authorization.Check func(context.Context) error` over that identity. Core packages are `net/http` only, never log, never start goroutines; they report outcomes through an optional `auth.Observer` callback. Gin and the wide-event logger are confined to `ginadapter`, Prometheus to `prometheusadapter`.

### 1.1 Rules every work package applies (not repeated per package)

- Constructors: `New(options *Options) (*X, error)` or `NewX(options *XOptions) (*X, error)`; nil options is an error unless the section says "nil allowed"; validate, apply defaults to a copy, store the copy unexported, clone every slice and map the component keeps (`slices.Clone`, `maps.Clone`), never write to the caller's struct [DES-001, FUN-002]. No exported fields on components [DES-006].
- No logging of any kind, no stdout/stderr [LIB-003]. No goroutines, no `init()`, no mutable package-level state [LIB-004, DES-002, DES-003]. Compiled regexes and constants are fine.
- `ctx context.Context` first on everything doing I/O; never store a context in a struct [CON-002]. Outbound HTTP only through the component's `HTTPClient` option, default `&http.Client{Timeout: 10 * time.Second}`, requests built with `http.NewRequestWithContext` [RES-001]. Every component's own calls run on `internal/dependency.WithoutRedirects(HTTPClient)`, a copy that fails a redirected call with `redirect refused` (`*url.Error` naming the target, which `dependency.Error` reduces to its origin): net/http resends a 307/308 request's body and, to the same host, its Authorization header, also from https to http, so a redirect would hand the client secret, code and PKCE verifier (or Keycloak's admin credentials and token) to an endpoint no URL check has seen, and the target of a redirected read (GitHub's `/user`, `/user/teams`) could forge the answer the component trusts, e.g. a team membership (D16, D35). GitHub's `Provider.HTTPClient(ctx, session)` for the app keeps the caller's redirect policy; its transport sends the token to APIURL's scheme and host only. No retries anywhere [RES-002].
- Refusals are `*auth.Error` (section 5). Third-party errors (go-oidc, oauth2, go-redis, jwx, pquerna/otp, bcrypt) never reach callers through `%w`: they pass through `internal/dependency.Error` (message only, chain dropped; `context.Canceled` and `context.DeadlineExceeded` stay detectable with `errors.Is`) or are translated [LIB-010]. An OAuth token endpoint's error answer (`*oauth2.RetrieveError`) goes through `internal/tokenendpoint.Error`: its HTTP status and a well-formed OAuth error code only, never its description, URI or body, which are the server's free text [LOG-009]; an answer that is not a readable token response (a malformed 200, whose oauth2 parse error quotes its values) becomes the fixed text `<operation>: token endpoint answered an unreadable token response`, and only a failed call (`*url.Error`) or a context error keeps `dependency.Error`'s reduced message. For the same reason go-oidc's discovery and JWKS requests run on a copy of the `HTTPClient` that rebuilds every answer's status line from its code and drops every body except a 200 JSON one, and the Content-Type of a dropped one, so go-oidc's discovery errors carry the status code only (`oidc`). An ID token that does not verify is refused `login_failed` with the fixed Reason `ID token expired` or `ID token verification`, never go-oidc's message, which quotes the token header and claims and the JWKS request's error [LOG-009]. An HTTP call's error (the `*url.Error` of `HTTPClient.Do`, also inside a go-oidc or oauth2 error) goes through `dependency.Error` as well, which reduces it to method, origin and a classified cause (`dependency.TransportFailure`): its path and query may carry personal data and its transport text may repeat bytes the server sent [LOG-009]. Other standard library errors (encoding/json, ...) and own errors wrap with `%w` and say what was done [ERR-004]. No panics outside tests [ERR-001], except `RegisterRoutes` on a conflicting route (a startup wiring mistake, like `http.ServeMux.Handle`).
- Never put tokens, secrets, session IDs, passwords, codes, emails or names into an error message, an `Outcome`, a wide-event field or a metric label [LOG-009, MET-004]. IDs (`Subject`, `UserID`) are fine.
- Every response the library writes carries `Cache-Control: no-store`; the one exception is the JWKS (`public, max-age=300`).
- Names [NAM-001..006]: spelled out, initialisms upper-case (`ID URL URI HTTP JSON OIDC JWT JWKS API TOTP PKCE TTL UI`), no stutter, no `Get` on getters. Data-access lookups on `password.Storage` keep `Get` (NAM-006 exception).
- Every package has a package comment and every exported identifier a doc comment starting with its name, stating concurrency safety [LIB-005]; main entry points get an `Example*` [LIB-006]. All components are safe for concurrent use after construction.
- Tests: testify `require` only [TST-008], `httptest` [TST-006], table tests [TST-007], `-race` clean [TST-004]. Time-dependent code takes its clock from an unexported field `now func() time.Time` (set to `time.Now` by the constructor, overridden by in-package tests) [TST-005]. No `time.Sleep` in tests.
- Formatting gofumpt + goimports [TCH-006]; lint with the standards `.golangci.yml` [TCH-004].
- Never use the character U+2014 anywhere (code, comments, docs).

### 1.2 Fixed constants (binding values)

| Constant | Value | Used by |
|---|---|---|
| login state TTL (state, nonce, PKCE verifier, return path) | 10 min | `internal/oauthlogin` |
| TOTP setup secret TTL | 10 min | `password` |
| JSON request body limit | 64 KiB | `internal/httpjson` |
| default outbound HTTP timeout | 10 s | oidc, keycloak, github, jwt verifier |
| GitHub team pages (100 per page) / API response limit | max 50 / 10 MiB | `github` |
| JWKS refresh / unknown-kid refetch minimum spacing / refetch timeout | 1 h (at least 1 min) / 1 min / 10 s | `jwt` verifier |
| JWKS response | 1 MiB | `jwt` verifier |
| `Store.End` revocation timeout (detached from the request) | 10 s | `session` |
| Pop receipt for a retried Pop | 1 min | `session/redisbackend` |
| JWKS response cache lifetime | 300 s | `jwt` signer |
| JWT `nbf` backdating / verifier clock skew | 30 s / 30 s | `jwt` |
| return path maximum length | 2048 bytes | `internal/redirect` |
| return path query parameter | `return_to` | `internal/redirect` |
| static API key minimum length | 16 bytes | `apikey` |
| session cookie value | 32 random bytes, base64url without padding (43 chars) | `session` |

---

## 2. Package tree and dependency rules

```
github.com/govengers/auth
├── auth (root)                identity, context helpers, errors + JSON error shape, outcomes/observer, hook types, routes, identity endpoint
├── session                    server-side sessions (Store, Session, Backend, MemoryBackend), Guard middleware, Refresher seam, key parsing
│   └── redisbackend           session.Backend on Redis (go-redis)
├── jwt                        RS512 Signer (+ JWKS endpoint) and JWKS Verifier (+ middleware)
├── password                   password provider: Argon2id, TOTP + backup codes, legacy bcrypt, Storage seam
├── oidc                       OIDC provider: code flow + PKCE + nonce, RP-initiated and front-channel logout, claim mappers
│   └── keycloak               Keycloak Admin API enrichment as an auth.Hook (net/http + oauth2, no gocloak)
├── github                     GitHub OAuth provider: PKCE, teams allowed/admin/relevant, token server-side, API client, refresh
├── apikey                     provider-independent API key authenticator: static hashed keys + resolver
├── authorization              Check combinators and primitives over auth.Identity
├── ginadapter                 gin: net/http middleware and routes on gin, authorization gate, wide-event observer
├── prometheusadapter          auth.Observer that counts outcomes on a caller-supplied prometheus.Registerer
├── internal
│   ├── random                 random tokens
│   ├── redirect               return paths, login locations, external URLs, redirect targets, provider endpoint URLs, path prefixes, 302 answers
│   ├── httpjson               strict JSON request decoding, JSON response writing
│   ├── oauthlogin             state + nonce + PKCE login state bound to the session (shared by oidc and github)
│   ├── dependency             LIB-010 wrapper for third-party errors
│   ├── failure                Outcome Result of a failed action (denied vs error); Reporter answering and reporting a provider's requests
│   ├── tokenendpoint          OAuth token endpoint errors without the endpoint's free text (oidc, keycloak, github)
│   ├── fetchmetadata          Sec-Fetch-Site check refusing cross-site logout requests
│   ├── hook                   runs an OnLogin hook
│   ├── impersonation          writes a refreshed real identity back into an impersonating one
│   ├── backendtest            conformance suite for session.Backend implementations
│   ├── fakeprovider           fake OIDC issuer (+ Keycloak admin API) and fake GitHub for tests and e2e
│   └── forwardauth            the forward-auth server (service code of the binary)
├── cmd/forwardauth            main: configuration (config v2), wiring, run
├── docker/forwardauth.Dockerfile
└── test/e2e                   build tag e2e: binary-subprocess suite; test/e2e/compose: Traefik docker-compose suite
```

### 2.1 Allowed imports (binding; lint by review)

| Package | Own module imports | Third-party | Heavy deps it pulls |
|---|---|---|---|
| `auth` | `internal/httpjson` | `google/uuid` | none |
| `session` | `auth`, `internal/random`, `internal/redirect`, `internal/failure`, `internal/impersonation` | none | none |
| `session/redisbackend` | `session`, `internal/dependency` | `redis/go-redis/v9` | go-redis |
| `jwt` | `auth`, `internal/dependency`, `internal/failure` | `lestrrat-go/jwx/v3`, `google/uuid` | jwx |
| `password` | `auth`, `session`, `internal/{httpjson, random, redirect, dependency, failure, fetchmetadata, hook}` | `golang.org/x/crypto` (argon2, bcrypt), `pquerna/otp`, `google/uuid` | x/crypto, otp |
| `oidc` | `auth`, `session`, `internal/{oauthlogin, redirect, dependency, failure, fetchmetadata, hook, tokenendpoint}` | `coreos/go-oidc/v3`, `golang.org/x/oauth2` | go-oidc (go-jose) |
| `oidc/keycloak` | `auth`, `internal/{redirect, dependency, tokenendpoint}` | `golang.org/x/oauth2` (incl. `clientcredentials`) | none |
| `github` | `auth`, `session`, `internal/{oauthlogin, redirect, httpjson, dependency, failure, fetchmetadata, hook, impersonation, tokenendpoint}` | `golang.org/x/oauth2` | none |
| `apikey` | `auth`, `internal/{dependency, failure}` | none | none |
| `authorization` | `auth` | `google/uuid` | none |
| `ginadapter` | `auth`, `authorization` | `gin-gonic/gin`, `mxcd/go-wide-event-logger`, `google/uuid` | gin |
| `prometheusadapter` | `auth`, `internal/dependency` | `prometheus/client_golang` | client_golang |
| `internal/random`, `internal/redirect`, `internal/httpjson`, `internal/dependency` | none | none | none |
| `internal/hook`, `internal/impersonation`, `internal/fetchmetadata` | `auth` | none | none |
| `internal/failure` | `auth`, `internal/redirect` | none | none |
| `internal/tokenendpoint` | `internal/dependency` | `golang.org/x/oauth2` (apart from `internal/dependency`, so packages without OAuth do not link it [LIB-007]) | none |
| `internal/oauthlogin` | `auth`, `session`, `internal/random`, `internal/redirect` | none (the PKCE verifier is `random.Token(32)`) | none |
| `internal/backendtest` | `session` | testify | test-only |
| `internal/fakeprovider` | none | none (stdlib only, RS256 fake tokens) | test-only |
| `internal/forwardauth` | `auth`, `apikey`, `ginadapter`, `jwt`, `session`, `prometheusadapter`, `internal/{httpjson, redirect, dependency}` | gin, wideevent, client_golang (incl. `promhttp`) | binary-only |
| `cmd/forwardauth` | every provider, `session/redisbackend`, `prometheusadapter`, `internal/{forwardauth, redirect, dependency}` | `govengers/config/v2`, gin (`gin.SetMode`), wideevent (emitters), client_golang (collectors), go-redis | binary-only: config v2 |

- No package imports gin or `go-wide-event-logger` except `ginadapter`, `internal/forwardauth`, `cmd/forwardauth` [LIB-007]. The logger's root package imports gin (DeepThought: go-wide-event-logger-root-package-imports-gin), so only gin-side code may record on wide events.
- No package except `prometheusadapter`, `internal/forwardauth` and `cmd/forwardauth` imports `client_golang` [LIB-011].
- `gocloak`, `gorilla/sessions`, `gorilla/securecookie`, `golang-lru`, `blake3`, `zerolog`, `go-config` v1 and jwx v2 are gone. `expirable.NewLRU` starts a goroutine that never exits (v2.0.7 `expirable_lru.go:79`), which LIB-004 forbids.
- Test-only deps: testify, `alicebob/miniredis/v2`, `prometheus/client_golang/prometheus/testutil`, `go.uber.org/goleak` (`internal/forwardauth`).

---

## 3. Package APIs

### 3.1 Root package `auth` (`github.com/govengers/auth`)

Files: `doc.go`, `identity.go`, `context.go`, `errors.go`, `response.go`, `outcome.go`, `hook.go`, `route.go`.

```go
// RoleAdmin is the application role that authorization.IsAdmin requires. The GitHub provider grants it to AdminTeams members.
const RoleAdmin = "admin"

// Identity is who a request acts as, whichever provider authenticated it. It is a value type:
// providers build it, hooks may return a modified copy, the session stores it as JSON (the tags are a
// persistence format; never rename them).
type Identity struct {
	Provider        string              `json:"provider"`                  // provider instance: "password", "github", "apikey" or an OIDC provider Name; a verified JWT keeps the provider it was signed for
	Subject         string              `json:"subject"`                   // stable ID at the provider: OIDC sub, GitHub numeric user ID, password user UUID, API key name
	UserID          uuid.UUID           `json:"userId"`                    // application user ID; uuid.Nil until the password provider or an OnLogin hook sets it
	Username        string              `json:"username,omitempty"`        // preferred_username, GitHub login, password username, API key name
	Name            string              `json:"name,omitempty"`
	Email           string              `json:"email,omitempty"`
	Picture         string              `json:"picture,omitempty"`         // OIDC picture claim, GitHub avatar_url
	Active          bool                `json:"active"`                    // providers set true at login; hooks may set false
	Roles           []string            `json:"roles,omitempty"`           // application roles (RoleAdmin)
	OIDCRoles       []string            `json:"oidcRoles,omitempty"`       // Keycloak realm roles
	OIDCClientRoles []string            `json:"oidcClientRoles,omitempty"` // Keycloak client roles of the configured client
	Groups          []string            `json:"groups,omitempty"`          // OIDC groups (path or name, per IdP mapper)
	Teams           []string            `json:"teams,omitempty"`           // GitHub "org/team-slug", lower-case
	Permissions     []Permission        `json:"permissions,omitempty"`     // resource permissions, text form in JSON ("builds:write"); from API keys, JWTs or hooks
	Attributes      map[string][]string `json:"attributes,omitempty"`      // Keycloak user attributes
	Claims          map[string]any      `json:"claims,omitempty"`          // OIDC ID token claims, or all claims of a verified JWT
	Data            map[string]any      `json:"data,omitempty"`            // application data from hooks and resolvers; JSON round trip (numbers become float64)
	Impersonator    *Identity           `json:"impersonator,omitempty"`    // the real identity while it impersonates this one; nil otherwise
}

// Real returns the identity that authenticated: the Impersonator while impersonating, the receiver otherwise. Nil-safe (nil in, nil out).
func (i *Identity) Real() *Identity
// Clone returns a deep copy: slices (Permissions included), Attributes and the Impersonator chain are copied; Claims and Data are copied one level (values shared). Nil-safe.
func (i *Identity) Clone() *Identity

// WithIdentity returns a copy of ctx carrying identity (private key type) [AUTH-006].
func WithIdentity(ctx context.Context, identity *Identity) context.Context
// IdentityFrom returns the identity in ctx, or nil.
func IdentityFrom(ctx context.Context) *Identity
```

Permissions (`permission.go`, implemented; binding). A generic resource permission any identity can carry (API keys, JWTs, or set by an OnLogin hook for interactive users). One text form everywhere: Go `String`, JSON (session, `IdentityResponse`), the JWT `permissions` claim and the forwardauth configuration.

```go
// Access is what a Permission allows on its resource. AccessWrite includes AccessRead.
type Access string
const (
	AccessRead  Access = "read"
	AccessWrite Access = "write"
)
// AllResources is the Permission resource that matches every resource.
const AllResources = "*"

// Permission grants Access on one resource, or on every resource when Resource is AllResources.
// Its text form "<resource>:<access>" ("builds:write", "*:read") is also its JSON form.
type Permission struct {
	Resource string
	Access   Access
}
// ParsePermission parses "<resource>:<access>". Case-sensitive: resource is "*" or matches
// [a-z0-9][a-z0-9._-]{0,63}; access is "read" or "write". Anything else is an error (plain, not *Error).
func ParsePermission(text string) (Permission, error)
// Validate reports whether resource and access are valid (same rules as ParsePermission).
func (p Permission) Validate() error
// String returns "<resource>:<access>".
func (p Permission) String() string
// Grants reports whether p grants access on resource: resource equal or p.Resource == AllResources, and
// AccessWrite includes AccessRead. Requiring AllResources needs a "*" permission. An invalid p, an empty or
// invalid resource, or an access other than read/write grants nothing (fail closed).
// The only implementation of the matching rule: no other package copies it.
func (p Permission) Grants(resource string, access Access) bool
// Permits reports whether one of i.Permissions Grants access on resource. Permissions only: it ignores
// Active and the Impersonator (callers decide those). Nil-safe: false for a nil identity.
func (i *Identity) Permits(resource string, access Access) bool
// MarshalText encodes the text form; an invalid permission is an error (an identity with one cannot be stored).
func (p Permission) MarshalText() ([]byte, error)
// UnmarshalText decodes with ParsePermission.
func (p *Permission) UnmarshalText(text []byte) error
// AccessForMethod: GET, HEAD, OPTIONS need AccessRead; every other method (exact, upper-case match) AccessWrite.
func AccessForMethod(method string) Access
```

Errors (`errors.go`):

```go
var (
	ErrUnauthenticated = errors.New("unauthenticated")  // 401
	ErrForbidden       = errors.New("forbidden")        // 403
	ErrInvalidRequest  = errors.New("invalid request")  // 400
	ErrConflict        = errors.New("conflict")         // 409
)

// Error is a refusal. Kind is one of the four sentinels; Code is the stable client-facing code
// (empty means the Kind's default code); Reason is server-side detail for the wide event and is
// never sent to a client (it may name a missing role); Err is an optional cause.
type Error struct {
	Kind   error
	Code   string
	Reason string
	Err    error
}
// ReasonInactive is the Reason of the ErrForbidden refusal of an inactive identity, shared by every
// authorization check and jwt.Signer.Sign.
const ReasonInactive = "inactive"
// Error returns "<kind>[: <code>][: <reason>][: <cause>]".
func (e *Error) Error() string
// Unwrap returns the non-nil of Kind and Err, so errors.Is(err, ErrForbidden) matches.
func (e *Error) Unwrap() []error
```

Responses (`response.go`):

```go
// ErrorResponse is the one JSON error shape of every library response [API-001].
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"` // fixed per kind, safe to show; never err.Error()
}
// ResponseFor maps an error to its status and body (pure; table in section 5.2). The Kind of the outermost
// *Error decides status and message, its Code replaces the default code; a bare sentinel maps by errors.Is;
// anything else (an *Error with an unknown Kind included, whose Code is then ignored) is 500 "internal".
func ResponseFor(err error) (int, ErrorResponse)
// WriteError writes ResponseFor(err) as JSON with Cache-Control: no-store.
func WriteError(writer http.ResponseWriter, err error)

// IdentityResponse is the public view of an Identity: Claims, Attributes and Data are never exposed.
type IdentityResponse struct {
	Provider        string            `json:"provider"`
	Subject         string            `json:"subject"`
	UserID          string            `json:"userId,omitempty"` // empty for uuid.Nil
	Username        string            `json:"username,omitempty"`
	Name            string            `json:"name,omitempty"`
	Email           string            `json:"email,omitempty"`
	Picture         string            `json:"picture,omitempty"`
	Active          bool              `json:"active"`
	Roles           []string          `json:"roles"`             // never null
	OIDCRoles       []string          `json:"oidcRoles,omitempty"`
	OIDCClientRoles []string          `json:"oidcClientRoles,omitempty"`
	Groups          []string          `json:"groups,omitempty"`
	Teams           []string          `json:"teams,omitempty"`
	Permissions     []Permission      `json:"permissions,omitempty"` // text form: ["builds:write"]
	Impersonator    *IdentityResponse `json:"impersonator,omitempty"`
}
func NewIdentityResponse(identity *Identity) IdentityResponse
// IdentityHandler answers 200 with the IdentityResponse of the identity in the request context and
// 401 without one; an identity that does not encode (an invalid Permission set by application code) is 500.
// Mount it behind a Guard (recommended path "/auth/me").
func IdentityHandler() http.Handler
```

Outcomes and hooks (`outcome.go`, `hook.go`):

```go
type Action string
const (
	ActionLogin              Action = "login"               // redirect start (oidc, github) or credential check (password)
	ActionCallback           Action = "callback"
	ActionLogout             Action = "logout"
	ActionFrontChannelLogout Action = "frontchannel_logout"
	ActionRegister           Action = "register"
	ActionTOTPVerify         Action = "totp_verify"
	ActionTOTPStatus         Action = "totp_status"         // password GET {prefix}/totp
	ActionTOTPSetup          Action = "totp_setup"
	ActionTOTPEnable         Action = "totp_enable"
	ActionTOTPDisable        Action = "totp_disable"
	ActionRefreshTeams       Action = "refresh_teams"       // github route
	ActionAuthenticate       Action = "authenticate"        // per request: Guard, apikey, jwt verifier
	ActionRefresh            Action = "refresh"             // Guard calling a Refresher
)

// The fixed provider names (Identity.Provider, Outcome.Provider); an OIDC provider uses its own Name, which must
// not be one of them (oidc builds its reserved names from these, without importing the providers).
const (
	ProviderPassword = "password"
	ProviderGitHub   = "github"
	ProviderAPIKey   = "apikey"
	ProviderJWT      = "jwt"     // a JWT verifier's outcomes; its identities keep the provider they were signed for
	ProviderSession  = "session" // the Guard's outcomes when it finds no identity
)

type Result string
const (
	ResultSuccess   Result = "success"
	ResultChallenge Result = "challenge" // password step done, second factor or enrollment pending
	ResultDenied    Result = "denied"    // a refusal (*Error) was answered
	ResultError     Result = "error"     // an internal failure was answered (500)
)

// Outcome is one authentication decision. Err is the refusal for denied, the failure for error,
// and a handled failure for a degraded success (e.g. GitHub token revocation failed, legacy hash upgrade failed).
type Outcome struct {
	Provider string     // provider instance name; "session" when the Guard finds no identity
	Action   Action
	Result   Result
	Err      error
	Identity *Identity  // the identity concerned, nil when unknown
}

// Observer receives outcomes synchronously, at most once per action per request, with the request
// context. It must not block and must be safe for concurrent use. nil Observer options mean no reporting [LIB-003].
type Observer func(ctx context.Context, outcome Outcome)

// Hook maps an identity. OnLogin hooks run after the provider authenticated the user and before a
// session exists: the returned identity is stored; an error aborts the login (an *Error answers with
// its status, anything else 500; providers wrap it with %w, so the kind survives) and no session is
// created; a nil identity without error is a failure (500). Hooks must not mutate the argument;
// return identity.Clone() with changes. Providers may call a hook from concurrent requests.
type Hook func(ctx context.Context, identity *Identity) (*Identity, error)

// LogoutHook runs after a session was ended (all providers, RP-initiated and front-channel logout).
// It cannot fail the logout and has no access to the response.
type LogoutHook func(ctx context.Context, identity *Identity)
```

Routes (`route.go`):

```go
// Route is one endpoint a provider serves. Path is absolute from the server root and includes the provider prefix.
type Route struct {
	Method  string
	Path    string
	Handler http.Handler
}
// RegisterRoutes registers each route on serveMux as the Go 1.22 pattern "<Method> <Path>". Like
// http.ServeMux.Handle it panics on a pattern that conflicts with one already registered.
func RegisterRoutes(serveMux *http.ServeMux, routes []Route)
```

### 3.2 `session`

Files: `doc.go`, `key.go`, `backend.go`, `memory.go`, `store.go`, `session.go`, `crypto.go` (unexported), `guard.go`.

```go
// ParseKey decodes a base64 (standard or URL alphabet, padding optional) encryption key and requires exactly 32 bytes.
// Generate one with `openssl rand -base64 32`.
func ParseKey(encoded string) ([]byte, error)

// ErrRevoked is returned by Backend.Put for a session that carries a revocation marker.
var ErrRevoked = errors.New("session revoked")

// Backend stores the server-side half of sessions: one opaque, already encrypted value per (sessionID, key).
// sessionID is a non-secret identifier derived from the cookie (SHA-256), never the cookie value.
// Every operation is atomic per key; Put is serialized against Revoke of the same sessionID, so after
// Revoke returned no Put for that sessionID succeeds until the marker expires or a full backend evicts it
// (MemoryBackend; Redis under its own eviction policy). A marker never outlives the
// values it replaced, and a sessionID without values gets none: revoking unknown IDs stores nothing. Values
// expire after their own ttl, which is always positive. Applications may implement it (e.g. on Postgres);
// share one backend between replicas. Implementations must be safe for concurrent use.
type Backend interface {
	Put(ctx context.Context, sessionID, key string, value []byte, ttl time.Duration) error // ErrRevoked when revoked
	Get(ctx context.Context, sessionID, key string) (value []byte, found bool, err error)
	Pop(ctx context.Context, sessionID, key string) (value []byte, found bool, err error)   // of two concurrent Pops at most one finds the value
	// CompareAndSwap replaces the live value with value in one step, keeping its expiry, only while it still
	// equals previous; swapped is false when it changed, expired or was revoked meanwhile.
	CompareAndSwap(ctx context.Context, sessionID, key string, previous, value []byte) (swapped bool, err error)
	// Revoke deletes every key; when there was any, it writes a marker living ttl, or until the latest
	// deleted value would have expired when that is sooner.
	Revoke(ctx context.Context, sessionID string, ttl time.Duration) error
}

type MemoryBackendOptions struct {
	// MaximumSessions default 100000, MaximumBytes (session IDs, keys and values held) default 64 MiB; when a
	// write would pass either (a replacement counts only what it adds): expired entries are dropped, then the entries expiring soonest are evicted, a
	// live revocation marker included (a full backend never fails a Put; only a value larger than MaximumBytes)
	MaximumSessions int
	MaximumBytes    int
}
// NewMemoryBackend returns the in-process backend: correct for exactly one replica. nil options allowed.
func NewMemoryBackend(options *MemoryBackendOptions) (*MemoryBackend, error)
// MemoryBackend implements Backend with a map and one mutex; expiry is lazy (no goroutine). A full backend evicts
// revocation markers like sessions, so a flood of login starts cannot block every new session; an evicted marker
// no longer refuses a Put (a provider or application value may land in the revoked session), but nothing gives it an
// identity again (SaveIdentity and the Guard swap against a live identity; only the first save of a Start handle
// writes without one). Meant for one replica at non-production scale; use Redis in production.
// ponytail: O(n) eviction scan when full; shard or use Redis if that ever shows in profiles.
type MemoryBackend struct{ /* unexported */ }

type StoreOptions struct {
	Backend        Backend       // required
	EncryptionKey  []byte        // required, exactly 32 bytes (AES-256-GCM); see ParseKey
	CookieName     string        // default "auth_session"; Secure, host-only and on "/": sent as "__Host-" + CookieName (an own "__Host-"/"__Secure-" prefix is kept and validated)
	CookieDomain   string        // default "" (host-only cookie)
	CookiePath     string        // default "/"
	SameSite       http.SameSite // Lax (default), Strict or None; None requires InsecureCookie false (front-channel logout needs None); Strict only for password-only stores (oidc and github refuse it, D41); SameSiteDefaultMode (no attribute) is refused
	InsecureCookie bool          // drops the Secure attribute; local HTTP development only
	MaximumAge     time.Duration // default 24h, at least 1s; absolute session lifetime, also the cookie Max-Age
}
// NewStore validates options (cookie name, domain and path through http.Cookie.Valid, CookiePath starting with "/").
func NewStore(options *StoreOptions) (*Store, error)

// Start issues a new session: revokes the request's current session (if any), sets a fresh cookie, returns the handle.
// Used by a login start without a live identity (oauthlogin.Begin keeps a live one) and after authentication
// (session ID rotation, fixation defense).
func (s *Store) Start(ctx context.Context, writer http.ResponseWriter, request *http.Request) (Session, error)
// Open returns the handle of the request's session from its cookie (no I/O). No or malformed cookie: *auth.Error ErrUnauthenticated.
func (s *Store) Open(request *http.Request) (Session, error)
// End revokes the request's session (with context.WithoutCancel and its own 10 s timeout, so a disconnecting client cannot keep it
// and a hung backend cannot hold the request) and expires the cookie. No cookie: only expires it.
// The cookie is expired even when the revocation fails; that error is returned.
func (s *Store) End(ctx context.Context, writer http.ResponseWriter, request *http.Request) error
// MaximumAge returns the configured absolute session lifetime.
func (s *Store) MaximumAge() time.Duration
// SameSite returns the cookie's SameSite mode; oidc.New and github.New refuse http.SameSiteStrictMode (D41).
func (s *Store) SameSite() http.SameSite

// Session is a handle on one server-side session (value type, unexported fields: the backend ID, the store
// and, on a handle Start returned, its one first save: the time Start issued it, shared by every copy and usable once). Values are AES-256-GCM sealed with a key derived per session
// (HKDF-SHA256 from EncryptionKey, info "govengers/auth session <sessionID>"), a random 12-byte nonce and
// additional data "<sessionID>\x00<key>"; a value that does not decrypt (moved, tampered, other key)
// counts as absent. The per-session key keeps the 2^32 random-nonce limit of GCM per session.
type Session struct{ /* unexported */ }
// Put refuses an empty key or a ttl <= 0; a revoked session refuses with ErrUnauthenticated.
func (s Session) Put(ctx context.Context, key string, value []byte, ttl time.Duration) error
func (s Session) Get(ctx context.Context, key string) ([]byte, bool, error)
func (s Session) Pop(ctx context.Context, key string) ([]byte, bool, error)
// SaveIdentity stores identity under key "identity". The first save of a session sets authenticatedAt to the
// time Start issued it; later saves (refresh, TOTP enable, impersonation) keep it. refreshedAt=now.
// TTL = authenticatedAt + MaximumAge - now; a ttl <= 0 refuses with ErrUnauthenticated.
// Only a handle returned by Store.Start may have a first save, and only one (copies of the handle included):
// without a live identity (never authenticated, expired, revoked) any other save refuses with ErrUnauthenticated,
// so neither a planted cookie, a save racing the expiry nor a retained Start handle gets a fresh lifetime (D8, D22).
// A later save writes by Backend.CompareAndSwap against the envelope it read (last writer wins: a lost swap
// re-reads, at most 3 tries, then an error), so a save racing a logout cannot write the identity back even where
// the backend forgot the revocation (a full MemoryBackend).
func (s Session) SaveIdentity(ctx context.Context, identity *auth.Identity) error
// Identity returns the stored identity; none, expired (now > authenticatedAt + MaximumAge) or revoked: *auth.Error ErrUnauthenticated.
func (s Session) Identity(ctx context.Context) (*auth.Identity, error)
// SwapIdentity saves identity in place of previous (an identity Identity returned) only while the session still
// holds an identity equal to it (same JSON, so nil and empty fields are equal); swapped is false when another request
// saved a different one or changed the session between the read and the swap (Backend.CompareAndSwap on the sealed
// envelope read). It keeps authenticatedAt and the expiry, refreshedAt=now. A session without a live identity refuses
// with ErrUnauthenticated, like Identity; a nil identity is an error. For read-modify-write saves that must not
// overwrite a concurrent change (github refresh-teams; the Guard keeps its own claim on the whole envelope).
func (s Session) SwapIdentity(ctx context.Context, previous, identity *auth.Identity) (bool, error)
```

Reserved session keys (binding): `identity` (envelope `{"identity", "authenticatedAt", "refreshedAt", "verifiedAt"}`, unexported type; `Session.Put` and `Pop` refuse it, so only SaveIdentity and SwapIdentity write it), `<provider name>.<anything>` for provider state (`password.pending`, `password.totp_setup`, `<oidc name>.login`, `<oidc name>.id_token`, `github.login`, `github.token`). Applications prefix their own keys with `app.`.

Guard:

```go
// Refresher re-validates identities of one provider. The Guard calls it for identities whose last
// refresh is older than RefreshInterval, always with the real identity (identity.Real()).
// Return a copy with provider-owned fields updated; keep every other field (roles set by OnLogin etc.).
// ErrUnauthenticated or ErrForbidden end the session; any other error keeps the identity (degraded).
// Refresh runs without the request's cancellation, bounded by 30 s.
type Refresher interface {
	Name() string // the Identity.Provider it refreshes
	Refresh(ctx context.Context, current Session, identity *auth.Identity) (*auth.Identity, error)
}

type GuardOptions struct {
	Store            *Store        // required
	LoginURL         string        // RequireUI target; absolute http(s) URL with a host, or a path SafeReturnPath accepts, without a fragment (redirect.IsTarget); default "/"
	ReturnPathHeader string        // header carrying the original request URI (forward auth: "X-Forwarded-Uri"); default: request.URL.RequestURI()
	Refreshers       []Refresher   // optional; names must be non-empty and unique
	RefreshInterval  time.Duration // default 1 min; negative is an error
	// a refresh failing for longer than this since the login or the last successful refresh ends the session;
	// default 1 h (RefreshInterval when that is longer), at least RefreshInterval
	MaximumUnverifiedAge time.Duration
	Observer             auth.Observer // optional
}
func NewGuard(options *GuardOptions) (*Guard, error)
// RequireAPI refuses unauthenticated requests with 401 JSON, forbidden ones with 403 JSON.
// A request that already carries an identity (e.g. from an API key) passes untouched.
func (g *Guard) RequireAPI() func(http.Handler) http.Handler
// RequireUI redirects unauthenticated requests 302 to LoginURL?return_to=<path> (path omitted when unsafe); forbidden ones get 403 JSON (a redirect would loop).
// A request that already carries an identity passes untouched.
func (g *Guard) RequireUI() func(http.Handler) http.Handler
```

`ReturnPathHeader`: when set, only that header is the return path source; a missing header omits the return path (behind forward auth the request URI would be `{prefix}/ui`). Without it the request URI is used.

Guard semantics (both variants): see flow F11.

### 3.3 `session/redisbackend`

```go
type Options struct {
	Client    redis.UniversalClient // required; caller owns and closes it (Client, ClusterClient or FailoverClient)
	KeyPrefix string                // default "session"; must not contain '{' or '}' (they delimit the hash tag)
}
func New(options *Options) (*Backend, error)
type Backend struct{ /* unexported */ } // implements session.Backend
```
Key layout (binding, Redis Cluster safe through the `{}` hash tag): index set `<prefix>:{<sessionID>}`, value `<prefix>:{<sessionID>}:<key>`, marker `<prefix>:{<sessionID>}#revoked`, Pop and CompareAndSwap receipts `<prefix>:{<sessionID>}#popped:<token>` and `<prefix>:{<sessionID>}#swapped:<token>` (one minute). Four Lua scripts, started from oidc-auth `pkg/oidc/backend.go:118-141`: `putScript` (refuses a marked session, stores and indexes), `popScript` (returns and deletes the value and keeps it under a receipt named by a random token per Pop call, so go-redis retrying the same call after a lost reply gets the value again instead of "not found" [RES-004]; a retry answers from the receipt before it reads the value, so it never consumes a value written after the lost attempt; works with any client retry setting), `swapScript` (`SET ... KEEPTTL` only while the value equals the expected one, with a receipt under a random token per call like `popScript`, so a retry after a lost reply reports the swap the lost attempt made even when the value changed since) and `revokeScript` (deletes every indexed value and writes the marker for `min(ttl, the latest PTTL of the values still stored)`, none when no value lives; the index TTL only ever grows, so it outlives replaced, popped and expired values). `redis.Nil` becomes "not found"; other errors go through `dependency.Error` [LIB-010]. Every method refuses an empty sessionID or one containing a brace; a TTL below 1 ms is sent as 1 ms (`PX 0` is a Redis error).

### 3.4 `jwt`

```go
type SignerOptions struct {
	PrivateKey []byte        // required: PEM RSA private key, PKCS#1 or PKCS#8, at least 2048 bits
	Issuer     string        // required: iss of every token, also what verifiers expect
	Audience   []string      // optional aud
	Lifetime   time.Duration // default 5 min
}
func NewSigner(options *SignerOptions) (*Signer, error)
// Sign mints an RS512 token for identity (claims table below). kid is the RFC 7638 SHA-256 thumbprint of the key.
// An inactive identity is refused with *auth.Error{Kind: ErrForbidden, Reason: "inactive"}: Verify returns every
// identity as active, so no token may exist for an inactive one.
func (s *Signer) Sign(identity *auth.Identity) (string, error)
// JWKSHandler serves {"keys":[{kty,n,e,kid,alg:"RS512",use:"sig"}]} (precomputed) with Cache-Control: public, max-age=300.
func (s *Signer) JWKSHandler() http.Handler

type VerifierOptions struct {
	JWKSURL         string        // required: absolute http(s) URL (http allowed: in-cluster JWKS), at most 1 MiB; only its RSA keys with an RSA signature alg (RS*, PS*), a kid and use "sig" (or none) count, a JWKS without one fails NewVerifier ("JWKS has no RSA signing key with alg and kid")
	Issuer          string        // required: expected iss
	Audience        string        // optional: when set, aud must contain it
	RefreshInterval time.Duration // default 1 h, at least 1 min; an unknown kid triggers a refetch at most once per minute
	HTTPClient      *http.Client  // default 10 s timeout
	HeaderName      string        // default "Authorization", value "Bearer <token>"
	Observer        auth.Observer // optional; Middleware reports one ActionAuthenticate outcome per request (Provider "jwt")
}
// NewVerifier fetches the JWKS once and fails when it cannot (fail fast). ctx bounds that fetch only.
func NewVerifier(ctx context.Context, options *VerifierOptions) (*Verifier, error)
// Verify checks signature (with the JWKS key named by kid, under the key's algorithm), iss, aud, exp (required),
// nbf and iat (30 s skew) and returns the identity.
// Invalid token: *auth.Error{Kind: ErrUnauthenticated, Code: "invalid_token"} with a Reason from a fixed vocabulary
// (malformed token, token header has no kid, unknown key ID, signature invalid, token expired, token not yet valid,
// token issued in the future, issuer mismatch, audience mismatch, expiry missing, token invalid), never jwx's message,
// which quotes token material. JWKS fetch failure for an unknown kid: plain error; a verification waiting for another
// request's fetch stops when its own ctx ends (plain error wrapping context.Canceled/DeadlineExceeded). A failed periodic refresh keeps
// the previous keys and the token verifies with them.
func (v *Verifier) Verify(ctx context.Context, token string) (*auth.Identity, error)
// Middleware requires a valid token in HeaderName ("Bearer <token>", scheme matched case-insensitively, spaces around the token trimmed): identity
// into the context; missing: 401 "unauthenticated", invalid: 401 "invalid_token", both with WWW-Authenticate: Bearer
// (RFC 6750); JWKS fetch failure for an unknown kid: 500 (no challenge). A failed periodic refresh is a degraded
// success (Outcome Result success with Err); when the token is then refused, Outcome.Err joins the refusal and the
// refresh error (Result and answer follow the refusal).
func (v *Verifier) Middleware() func(http.Handler) http.Handler
```
No background goroutine and no token cache: keys refresh lazily inside `Verify`. One request claims the refetch (a mutex guards only the keys and the claim) and fetches outside the mutex on `context.WithoutCancel` of the triggering request with its own 10 s timeout (CON-003), so a cancelled request cannot use up the once-per-minute fetch; meanwhile a token with a known kid verifies with the current keys, one with an unknown kid waits for the fetch in flight, or until its own request ends, and then decides. NewVerifier's first fetch uses the caller's ctx. A JWKS over 1 MiB fails the fetch; entries jwx cannot parse are ignored like other unusable keys (a document that is no JSON JWK set still fails, with the fixed text "parse JWKS <URL>: not a JSON JWK set"; a failed body read reports the classified transport cause, `dependency.TransportFailure`). Errors name the JWKS URL without user info, query and fragment and never repeat the response bytes (LOG-009). RSA verification per request is cheap, so the old cache (and its missing `exp` recheck) is dropped. No `Close` is needed.

Claims written by `Sign` and read back by `Verify` (binding):

| Claim | From `Identity` | Notes |
|---|---|---|
| `iss`, `aud` | options | |
| `sub` | `Subject` | |
| `iat`, `nbf`, `exp`, `jti` | now, now - 30 s, now + Lifetime, random UUID | |
| `provider` | `Provider` | |
| `user_id` | `UserID` | omitted for uuid.Nil |
| `preferred_username`, `name`, `email`, `picture` | `Username`, `Name`, `Email`, `Picture` | omitted when empty |
| `roles`, `realm_roles`, `client_roles`, `groups`, `teams` | `Roles`, `OIDCRoles`, `OIDCClientRoles`, `Groups`, `Teams` | JSON arrays, omitted when empty |
| `permissions` | `Permissions` | JSON array of text forms (`["builds:write","*:read"]`), omitted when empty; `Sign` fails on an invalid permission; `Verify` parses each entry with `auth.ParsePermission` and drops entries that do not parse or are not strings (fail closed per entry) |
| every other key of `Claims` | `Claims` | copied; never copied: `iss sub aud exp nbf iat jti nonce at_hash c_hash auth_time sid azp` and every claim name of the rows above (`provider`, `user_id`, `preferred_username`, `name`, `email`, `picture`, `roles`, `realm_roles`, `client_roles`, `groups`, `teams`, `permissions`), matched case-insensitively (decoders like encoding/json read `Roles` into a `roles` field), so an identity field left empty cannot come back from `Claims` (an IdP `roles` claim must not become application roles) |

`Verify` sets `Active=true`, the fields above, and `Claims` = all claims of the token. Wrong claim types are skipped, never asserted (no panics). `Attributes`, `Data` and `Impersonator` are not carried.

### 3.5 `password`

```go
type Policy struct {
	MinimumLength    int  // in characters (runes), 1..128; default 12; maximum length is fixed at 128 bytes
	RequireUppercase bool
	RequireLowercase bool
	RequireDigit     bool
	RequireSpecial   bool // any rune that is neither letter nor digit
}

type TOTPOptions struct {
	Enabled            bool          // routes the TOTP endpoints and challenges users who enabled TOTP; while off, their logins fail (500)
	Required           bool          // users without TOTP enroll during login (flow F3); needs Enabled
	Issuer             string        // required when Enabled (otpauth issuer)
	Period             uint          // default 30 s; at most 3600
	Digits             uint          // 6 or 8; default 6
	Skew               uint          // periods accepted before and after the current one; default 1 (0 means the default); at most 10
	MaximumAttempts    int           // default 5 wrong codes in a row, across logins; then the second factor stays locked until Storage.ResetTOTPAttempts; 0 means the default, negative is an error (no "unlimited")
	PendingTTL         time.Duration // default 5 min (password step to code step)
	DisableBackupCodes bool
	BackupCodeCount    int           // default 10; at most 20 (bounds the Argon2id runs per enable and per backup-code attempt)
	BackupCodeLength   int           // default 10; at most 128 bytes per code (widest alphabet rune) and at least 1,000,000 distinct codes
	BackupCodeAlphabet string        // default "0123456789"; at least 2 distinct runes, no white space; stored lower-case, repeated runes count once
}

// Parameters are Argon2id cost parameters.
type Parameters struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}
// DefaultParameters returns m=64 MiB, t=3, p=2, salt 16, key 32.
func DefaultParameters() Parameters

type Options struct {
	Sessions             *session.Store // required
	Storage              Storage        // required
	PathPrefix           string         // default "/auth/password"; redirect.IsPathPrefix (segments of A-Z a-z 0-9 . _ ~ -, no trailing "/", no "." or ".." segment)
	DisableUsernameLogin bool
	DisableEmailLogin    bool           // both true: error
	EnableRegistration   bool           // off by default: POST {prefix}/register is not even routed
	Policy               Policy
	TOTP                 TOTPOptions
	HashParameters       Parameters     // zero value: DefaultParameters(); at least 32 MiB, 1 iteration, salt and key 16 bytes
	LegacyVerifier       func(password, storedHash string) (bool, error) // optional, e.g. VerifyBcrypt; consulted for stored hashes that are not Argon2id
	OnLogin              auth.Hook      // must keep UserID (the Storage user ID Refresh and the TOTP routes look users up by); a hook replacing it fails the login (500)
	OnLogout             auth.LogoutHook
	Observer             auth.Observer
}
// New validates and precomputes the dummy hash used for unknown users (timing-safe lookups).
func New(options *Options) (*Provider, error)
func (p *Provider) Name() string            // "password"
func (p *Provider) Routes() []auth.Route    // table below: login and logout always, register with EnableRegistration, the TOTP routes with TOTP.Enabled
// Refresh implements session.Refresher: re-reads the user; ErrUserNotFound becomes ErrUnauthenticated; updates Username and Email only.
func (p *Provider) Refresh(ctx context.Context, current session.Session, identity *auth.Identity) (*auth.Identity, error)

func Hash(password string, parameters Parameters) (string, error)       // "$argon2id$v=19$m=..,t=..,p=..$salt$hash"; 1..128 bytes
func Verify(password, encodedHash string) (bool, error)                 // ErrInvalidHash for anything not argon2id or outside the limits (memory 128 MiB, 50 iterations, parallelism 8, salt and key 16..1024 bytes)
func VerifyBcrypt(password, storedHash string) (bool, error)            // ready-made LegacyVerifier (port of legacy_bcrypt.go)

var (
	ErrUserNotFound          = errors.New("user not found")           // Storage contract
	ErrUserExists            = errors.New("user already exists")      // Storage contract (unique constraint)
	ErrTOTPAttemptsExhausted = errors.New("totp attempts exhausted")  // Storage contract
	ErrInvalidHash           = errors.New("invalid password hash")
)

// User is the record the provider reads from Storage. The library never deletes users and never writes profile fields.
type User struct {
	ID               uuid.UUID
	Username         *string
	Email            *string
	PasswordHash     string
	TOTPEnabled      bool
	TOTPSecret       *string
	BackupCodeHashes []string
}

// Storage persists users; implemented by the application. Every method is atomic on its own. Usernames and
// emails are matched ignoring case (CreateUser uniqueness and both lookups, e.g. unique indexes on lower(x) and
// WHERE lower(x) = lower($1)); the provider passes identifiers as typed.
type Storage interface {
	CreateUser(ctx context.Context, user *User) error                                   // ErrUserExists on a duplicate username or email, ignoring case (a unique constraint decides)
	GetUserByUsername(ctx context.Context, username string) (*User, error)              // ErrUserNotFound
	GetUserByEmail(ctx context.Context, email string) (*User, error)                    // ErrUserNotFound
	GetUserByID(ctx context.Context, id uuid.UUID) (*User, error)                       // ErrUserNotFound
	UpdatePasswordHash(ctx context.Context, id uuid.UUID, currentHash, newHash string) error // writes only while the stored hash still equals currentHash; a mismatch is not an error
	ConsumeTOTPAttempt(ctx context.Context, id uuid.UUID, maximum int) (remaining int, err error) // ErrTOTPAttemptsExhausted; check+increment atomic (A-1.5)
	ResetTOTPAttempts(ctx context.Context, id uuid.UUID) error                          // after a verified second factor; the application calls it to unlock a user
	// ConsumeTOTPStep records step when it is later than the last used one (or none is held) and returns true;
	// otherwise false and no change. Atomic, e.g. UPDATE ... SET totp_step = $2 WHERE id = $1 AND (totp_step IS NULL
	// OR totp_step < $2). SetTOTP and ClearTOTP keep it. Time-based, so a Period change cannot lock users out.
	ConsumeTOTPStep(ctx context.Context, id uuid.UUID, step time.Time) (bool, error)
	ConsumeBackupCode(ctx context.Context, id uuid.UUID, hash string) (bool, error)     // false when already consumed
	// SetTOTP enables TOTP with secret and backupCodeHashes and resets attempts, only while TOTP is disabled, and
	// reports whether it did; check and write are one atomic step, e.g. UPDATE ... SET totp_enabled = true, ...
	// WHERE id = $1 AND NOT totp_enabled, so a concurrent enrollment never replaces a second factor just set.
	SetTOTP(ctx context.Context, id uuid.UUID, secret string, backupCodeHashes []string) (bool, error)
	ClearTOTP(ctx context.Context, id uuid.UUID) error                                  // disables TOTP, clears secret and codes, resets attempts
}

// NewMemoryStorage returns an in-memory Storage for tests and examples (mutex-guarded, honours every contract above).
func NewMemoryStorage() *MemoryStorage
```

Routes (`{prefix}` = PathPrefix; all bodies JSON with `Content-Type: application/json`, else 400 `invalid_request`):

| Method + path | Auth | Request | Success |
|---|---|---|---|
| `POST {prefix}/register` (only with EnableRegistration) | none | `{"username"?, "email"?, "password"}` | 201 `IdentityResponse`, session started; with `TOTP.Required` 202 `{"challenge":"totp_setup"}` (pending enrollment) |
| `POST {prefix}/login` | none | `{"identifier", "password"}` | 200 `IdentityResponse`; 202 `{"challenge":"totp"}` or `{"challenge":"totp_setup"}` |
| `POST {prefix}/totp/verify` (this and every TOTP route only with `TOTP.Enabled`) | pending (verify) | `{"code", "backupCode": bool}` (`true`: the code is a backup code, else a TOTP code; no fallthrough) | 200 `IdentityResponse` |
| `GET {prefix}/totp` (Action `totp_status`) | full | | 200 `{"enabled": bool}` |
| `POST {prefix}/totp/setup` | full or pending (enrollment) | `{}` | 200 `{"secret","otpauthUrl","issuer","accountName"}` |
| `POST {prefix}/totp/enable` | full or pending (enrollment) | `{"code","password"}` | 200 `{"backupCodes":[...]}` (empty when disabled); enrollment: session becomes full |
| `POST {prefix}/totp/disable` | full | `{"password"}` | 204 |
| `POST {prefix}/logout` | any or none | | 204, session ended |

"full" = the session identity has `Provider == "password"` and no `Impersonator` (TOTP changes while impersonating are 403; another provider's session is 401). The provider reads sessions itself (`Store.Open` + `Session.Identity`), so its routes need no Guard in front. Username: 3-50 runes of `[a-zA-Z0-9_]`; email: the basicauth regex (`validation.go:9`); both compiled once. Account label for otpauth: username, else email, else ID. TOTP via `pquerna/otp/totp` (port `tfa.go`); every accepted code's time step is consumed through `Storage.ConsumeTOTPStep`, so a code is accepted once and never after a later one. Backup codes are Argon2id-hashed (port `generateBackupCodes`, `findBackupCodeMatch`) and drawn again on a duplicate, so no code maps to two hashes.

Challenge type (binding):
```go
type Challenge string
const (
	ChallengeTOTP      Challenge = "totp"
	ChallengeTOTPSetup Challenge = "totp_setup"
)
```

### 3.6 `oidc`

```go
// Profile is what a ClaimMapper reads from ID token claims.
type Profile struct {
	Username, Name, Email, Picture string
}
// ClaimMapper is a pure function from ID token claims to a Profile [FUN-005].
type ClaimMapper func(claims map[string]any) Profile
// DefaultClaimMapper reads preferred_username, name, email, picture (safe type assertions).
func DefaultClaimMapper(claims map[string]any) Profile
// GoogleClaimMapper reads name, email, picture; Username is the part of email before "@".
func GoogleClaimMapper(claims map[string]any) Profile

type Options struct {
	Name                         string            // required; [a-z0-9-]{1,32}; not "password", "github", "apikey", "session", "jwt"; becomes Identity.Provider
	Issuer                       string            // required; https, or http on a loopback host; discovery at <Issuer>/.well-known/openid-configuration
	ClientID, ClientSecret       string            // required (confidential client)
	Scopes                       []string          // default ["openid","profile","email"]; "openid" added first when missing; order kept, duplicates dropped; empty or space-containing entries are an error
	ExternalURL                  string            // required: absolute public base URL; redirect URI = ExternalURL + PathPrefix + "/callback"
	PathPrefix                   string            // default "/auth/oidc/" + Name; redirect.IsPathPrefix (segments of A-Z a-z 0-9 . _ ~ -, no trailing "/", no "." or ".." segment)
	PostLogoutURL                string            // default ExternalURL + "/"; a safe path or an absolute http(s) URL, no fragment; a path is made absolute with ExternalURL
	ErrorURL                     string            // optional: every callback failure (refusals and code=internal) redirects to ErrorURL?code=<code> instead of answering JSON; same rules as PostLogoutURL
	ClaimMapper                  ClaimMapper       // default DefaultClaimMapper
	AllowedEmailDomains          []string          // optional: requires email_verified=true and a matching domain (ASCII only, case-insensitive, exact; an IDN in its xn-- form)
	DisableIframeLogoutDetection bool              // stop treating Sec-Fetch-Dest: iframe on /logout as front-channel (A-2.4); a cross-site iframe load of /logout is then refused (403)
	Sessions                     *session.Store    // required; not SameSite Strict (D41)
	HTTPClient                   *http.Client      // default 10 s timeout; used for discovery, token exchange, JWKS
	OnLogin                      auth.Hook         // e.g. keycloak.Client.Enrich, or an app closure calling it and then provisioning
	OnLogout                     auth.LogoutHook
	Observer                     auth.Observer
}
// New runs discovery (network I/O, hence ctx; fails fast) and reads end_session_endpoint and the token
// endpoint's client authentication methods from the provider metadata. The discovered authorization_endpoint,
// token_endpoint, jwks_uri (all required) and end_session_endpoint (when present) must pass redirect.IsSecureURL
// like the Issuer (D16): "discovered <field> must be an https URL, or http on a loopback host". No
// credential-bearing request happens before. The JWKS is fetched on the first callback.
func New(ctx context.Context, options *Options) (*Provider, error)
func (p *Provider) Name() string
func (p *Provider) Routes() []auth.Route // GET {prefix}/login, /callback, /logout, /frontchannel-logout
func (p *Provider) LoginURL() string     // ExternalURL + PathPrefix + "/login"
```
Several providers share one `session.Store`; there is no MultiHandler (one `oidc.New` per IdP, distinct Names). Discovery uses `gooidc.ClientContext(ctx, client)` so the remote key set keeps the client after ctx ends; for discovery and the JWKS `client` is a copy of HTTPClient whose transport rebuilds the status line from the code and passes a body only for a 200 answer holding JSON of at most 1 MiB (a dropped body takes its Content-Type with it; another answer's body is never read, a 200 one only up to the limit, so an IdP cannot fill the memory), so go-oidc's discovery errors carry the status code, never the IdP's text, and an ID token that does not verify is refused with a fixed Reason (F5 step 3) (LOG-009; the token exchange keeps HTTPClient, oauth2 needs the body's error code). The oauth2 auth style is fixed from the discovery metadata (HTTP Basic unless `token_endpoint_auth_methods_supported` lists only `client_secret_post`): oauth2's auto-detection would resend a failed code exchange [RES-002]. Roles and groups without Keycloak: access token claims first, ID token claims second (port `token_claims.go` unchanged: `realm_access.roles`, `resource_access.<ClientID>.roles`, `groups`). Logout and front-channel logout look at `identity.Real()`, so they also work while impersonating.

### 3.7 `oidc/keycloak`

```go
type GrantType string
const (
	GrantTypeClientCredentials GrantType = "client_credentials" // default: the client's service account
	GrantTypePassword          GrantType = "password"           // admin-cli password grant; breaks when the user gets an OTP credential (DeepThought 09.10.2026)
)
type Options struct {
	URL                 string    // required: Keycloak base URL; https without query, or http on a loopback host
	Realm               string    // required: realm of the users
	AuthenticationRealm string    // realm the service account logs into; default Realm (e.g. "master" for a master admin)
	GrantType           GrantType // default GrantTypeClientCredentials
	ClientID            string    // required for client credentials; password grant default "admin-cli"
	ClientSecret        string    // required for client credentials; optional for the password grant
	Username, Password  string    // required for the password grant
	ClientRolesClientID string    // optional: clientId whose client roles become OIDCClientRoles (without it: none)
	RequiredRealmRoles  []string
	RequiredClientRoles []string  // needs ClientRolesClientID (New fails otherwise)
	RequiredGroups      []string  // group paths ("/parent/child")
	HTTPClient          *http.Client
}
// New validates options; it does no I/O.
func New(options *Options) (*Client, error)
// Enrich has the auth.Hook shape. identity.Subject is the Keycloak user ID. Returns a Clone with OIDCRoles
// (composite realm roles), OIDCClientRoles, Groups (paths) and Attributes replaced by the Admin API's answer;
// a missing required role or group: *auth.Error{Kind: ErrForbidden, Reason: "missing realm role <name>"}; API failure: plain error.
func (c *Client) Enrich(ctx context.Context, identity *auth.Identity) (*auth.Identity, error)
```
Replaces gocloak with five GETs (`/admin/realms/{realm}/users/{id}/role-mappings/realm/composite`, `/clients?clientId=`, `/users/{id}/role-mappings/clients/{uuid}/composite`, `/users/{id}/groups`, `/users/{id}`) plus the token endpoint `/realms/{authRealm}/protocol/openid-connect/token` via `clientcredentials.Config.Token(ctx)` or `oauth2.Config.PasswordCredentialsToken(ctx, ...)` with `oauth2.HTTPClient` in ctx. Token cached under a mutex until 30 s before expiry, or until the Admin API answers 401 to it (dropped then, unless renewed meanwhile; no retry within the call); client UUID cached after the first success (retried after a failure). Errors of the admin calls' `HTTPClient.Do` go through `dependency.Error` (method, origin and cause only; a cancelled context stays detectable); a non-200 answer is `admin API <path> answered HTTP <code>` (never the reason phrase; a 401 adds `: admin token refused`, which tells the token owner to drop it); token request errors go through `tokenendpoint.Error("request admin token", err)` and are always a plain error (500): the admin token is the server's own credential, so keycloak classifies no refusal.

### 3.8 `github`

```go
type Options struct {
	ClientID, ClientSecret string        // required
	Scopes                 []string      // default ["read:org"]; must include a scope that lists the user's teams (read:org, write:org, admin:org, user or repo), New refuses otherwise
	AuthorizeURL           string        // default "https://github.com/login/oauth/authorize"
	TokenURL               string        // default "https://github.com/login/oauth/access_token"
	APIURL                 string        // default "https://api.github.com"; GHE e.g. https://ghe.example.com/api/v3; no query or fragment (API paths are appended)
	ExternalURL            string        // required; redirect URI = ExternalURL + PathPrefix + "/callback"
	PathPrefix             string        // default "/auth/github"; same rule as oidc
	PostLogoutURL          string        // default ExternalURL + "/"; same rules as oidc (path made absolute, no fragment)
	ErrorURL               string        // as in oidc: every callback failure, code=internal included
	AllowedTeams           []string      // required, >= 1, "org/team-slug" (one "/", no white space or control characters), case-insensitive
	AdminTeams             []string      // members get auth.RoleAdmin; they still need an AllowedTeams membership
	RelevantTeams          []string      // extra teams kept in Identity.Teams
	Sessions               *session.Store // required; not SameSite Strict (D41)
	HTTPClient             *http.Client  // default 10 s timeout (token exchange, API, revocation)
	OnLogin                auth.Hook
	OnLogout               auth.LogoutHook
	Observer               auth.Observer
}
func New(options *Options) (*Provider, error)
func (p *Provider) Name() string         // "github"
func (p *Provider) Routes() []auth.Route // GET {prefix}/login, GET /callback, GET /logout, POST /refresh-teams
func (p *Provider) LoginURL() string
// Refresh implements session.Refresher: refetches teams with the stored token (flow F9).
func (p *Provider) Refresh(ctx context.Context, current session.Session, identity *auth.Identity) (*auth.Identity, error)
// HTTPClient returns a client that sends the session's GitHub token to APIURL's scheme and host only: a redirect
// to another host (an archive download, uploads.github.com) goes without it (static token source; an expired token
// makes GitHub answer 401 and the next Refresh ends the session). Session without a GitHub token: ErrUnauthenticated.
func (p *Provider) HTTPClient(ctx context.Context, current session.Session) (*http.Client, error)
```
- Teams lists are lower-cased copies; the caller's slices are never touched (A-3.4 bug). `Identity.Teams` = user teams intersected with Allowed ∪ Admin ∪ Relevant (bounded JWT size, data minimisation), sorted and unique. `Roles` gets `auth.RoleAdmin` for admin team members.
- URLs must be `https`, except loopback hosts (`localhost`, `127.0.0.0/8`, `::1`; no zoned IPv6) which may use `http` (tests and e2e); a host name is required.
- GitHub DTOs are unexported and minimal (`login id name email avatar_url`; team `slug` + `organization.login`). The 40-field `UserProfile` and friends are gone; apps use `HTTPClient`.
- API calls send `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`, read at most 10 MiB; 401 maps to ErrUnauthenticated, other non-200 to a plain error. The provider's own API client (teams, user) uses the same host-scoped transport as `HTTPClient`.
- Code exchange: GitHub refusing the code (an error answer below 500, `tokenendpoint.Refused`) is `login_failed` (401); a 5xx or an unreachable token endpoint is a plain error (500). The error is `tokenendpoint.Error("github: exchange code", err)`.

### 3.9 `apikey`

```go
type Key struct {
	Name        string            // required, unique, not blank; becomes Identity.Subject and Username
	Secret      string            // required, >= 16 bytes, unique, no surrounding whitespace; SHA-256 pre-hashed at construction
	Roles       []string          // optional, e.g. auth.RoleAdmin for the old "AllowedAPIKeys bypass admin" behaviour
	Permissions []auth.Permission // optional, each must pass Validate (New fails otherwise); every identity of the key gets a copy
}
// Resolver resolves application-issued keys. Unknown or revoked: return an error matching auth.ErrUnauthenticated.
// A returned identity with empty Provider gets "apikey"; it carries its own Permissions (the Authenticator clones the identity).
// Any other error is answered 500, whatever its kind (through dependency.Error: chain dropped, context.Canceled and
// context.DeadlineExceeded stay detectable); a nil identity without error is 401. Set Active: the Authenticator does not,
// and every check but IsAuthenticated refuses an inactive identity (403, Reason "inactive"). Every error's text is
// reported in Outcome.Err and recorded on the wide event, so it must not repeat the key.
type Resolver func(ctx context.Context, key string) (*auth.Identity, error)

type Options struct {
	Keys       []Key         // two keys with the same name or the same secret: New fails; errors name a key by its position, counting from 1
	Resolver   Resolver      // at least one of Keys and Resolver
	HeaderName string        // default "X-API-Key"; must not be Authorization; "Authorization: Bearer <key>" is always accepted too
	Observer   auth.Observer
}
func New(options *Options) (*Authenticator, error)
// Middleware: no key in the request: passes through untouched. Valid key: identity into the context.
// Invalid key: 401 JSON (invalid_api_key), never falls through to other authenticators. Resolver error: 500.
func (a *Authenticator) Middleware() func(http.Handler) http.Handler
```
Static key identity: `{Provider: "apikey", Subject: Name, Username: Name, Active: true, Roles: clone(Roles), Permissions: clone(Permissions)}`. A key without Permissions has none: `authorization.HasPermission` refuses it (fail closed). The key is read from HeaderName, else from `Authorization` with the `Bearer` scheme, matched case-insensitively (RFC 9110, as the jwt verifier does), both trimmed. Static keys are checked first, by comparing the SHA-256 of the presented key with every stored hash using `subtle.ConstantTimeCompare`, without early exit. Mount it before a `session.Guard`: the Guard passes requests that already carry an identity. Do not mount it in front of a `jwt.Verifier` middleware (both read `Authorization: Bearer`).

### 3.10 `authorization`

```go
// Check decides whether the identity in ctx may proceed: nil allows, an error refuses.
// Refusals are *auth.Error with Kind ErrUnauthenticated (no identity) or ErrForbidden (Reason says why).
type Check func(ctx context.Context) error

func All(checks ...Check) Check // every check passes; empty: fails (500); returns the first refusal or failure
func Any(checks ...Check) Check // one check passes; empty: fails (500); none passes: the first failure (500) if a check failed, else the first refusal
// Not refuses a missing identity (401) and an inactive one (403, Reason "inactive") before it evaluates check;
// then it passes when check refuses with ErrForbidden, refuses with ErrForbidden when check passes, and passes
// every other error through. The refusal is classified like auth.ResponseFor (Kind of the outermost *auth.Error,
// a bare sentinel by errors.Is), so an unauthenticated refusal with a forbidden cause is no 403 and passes through.
// Not(HasRole(x)) therefore never admits an anonymous or deactivated identity.
func Not(check Check) Check
func Real(check Check) Check    // evaluates check against identity.Real() (the impersonator while impersonating)

func IsAuthenticated() Check            // identity present, active or not
func IsActive() Check                   // present and Active
func IsUser() Check                     // same as IsActive (AUTH-003 vocabulary)
func IsAdmin() Check                    // active and has auth.RoleAdmin
func HasRole(role string) Check         // active and role in Roles
func HasUserID(id uuid.UUID) Check      // active and UserID == id; uuid.Nil never matches
func HasOIDCRole(role string) Check     // active and role in OIDCRoles
func HasOIDCGroup(group string) Check   // active and group in Groups
func HasGitHubTeam(team string) Check   // active and team in Teams, matched case-insensitively
// HasPermission: no identity: 401; inactive: 403 (Reason "inactive"); !identity.Permits(resource, access):
// 403 with Reason "missing permission <resource>:<access>". The matching rule is auth.Permission.Grants, never
// re-implemented here. An empty or invalid resource or an access other than read/write is a wiring mistake,
// validated once: every request fails with a plain error (500), which Not passes through. The effective identity
// counts (wrap in Real to check the impersonator). Interactive users have no permissions unless an OnLogin
// hook grants them: compose Any(HasRole(...), HasPermission(...)) or grant e.g. "*:write" at login.
func HasPermission(resource string, access auth.Access) Check
```
Every primitive except `IsAuthenticated` refuses a missing identity with 401 and an inactive one with 403 and the shared Reason `"inactive"`. A wiring mistake (a nil Check, `All()` or `Any()` without checks, `HasPermission` with an invalid resource or access) fails with a plain error (500) instead of a refusal, so it fails closed and `Not` cannot invert it into a pass (`Not(Real(nil))`, `Not(All())` fail). `Any` prefers a failure to a refusal for the same reason: `Not(Any(HasRole("blocked"), failingLookup))` fails in both check orders. Entity checks (`CanViewX`), broadcast filters and tenant roles stay in the applications (DeepThought go-authorization-package-lineage). A Check sees only the context, so the HTTP-method-derived variant lives in `ginadapter.RequireMethodPermission`.

### 3.11 `ginadapter`

One package for every gin integration (authentication and authorization), see decision D3.

```go
// Middleware runs net/http middleware in a gin chain: when it calls its next handler, ginContext.Request
// becomes the (possibly enriched) request and the rest of the chain runs inside it; otherwise the chain is aborted.
// Like a net/http chain it wraps once, here, so state the middleware keeps across requests survives. Each request
// finds its gin chain through its context: a middleware that passes on a request whose context does not derive
// from the one it got is answered 500. Gin handlers keep writing to ginContext.Writer, so a writer the middleware
// wraps for its next handler is not seen.
func Middleware(middleware func(http.Handler) http.Handler) gin.HandlerFunc
// RegisterRoutes registers each route with router.Handle(route.Method, route.Path, gin.WrapH(route.Handler)),
// so gin route templates (and therefore metric labels) are the provider paths. Register on the engine root.
// Like gin it panics on a conflicting path.
func RegisterRoutes(router gin.IRoutes, routes []auth.Route)
// Observe is an auth.Observer that records the outcome on the request's wide event (fields in section 5.4).
// A Guard reports a refresh on the same event before the request's authenticate outcome, so an ActionRefresh
// outcome goes under auth.refresh.* (no user.id): no key is set twice. Without a wide event in ctx it does nothing [LOG-007].
func Observe(ctx context.Context, outcome auth.Outcome)
// Require runs check against the request context: allowed continues; refused aborts with auth.ResponseFor
// (401/403/500) and records authorization.denied / authorization.reason / authorization.error and we.Failure(err).
// A nil check is a wiring mistake: every request is answered 500.
func Require(check authorization.Check) gin.HandlerFunc
// RequireMethodPermission is Require(authorization.HasPermission(resource, auth.AccessForMethod(ginContext.Request.Method)))
// evaluated per request: one gate for a route group, GET/HEAD/OPTIONS need read, everything else write
// (build-api's read_only/read_write behaviour). Same recording and responses as Require.
func RequireMethodPermission(resource string) gin.HandlerFunc
// RedactQuery is a wide-event pre-enricher (wideevent.WithPreEnricher): it sets request.query again with every
// parameter name kept and every value replaced by "redacted", cut to 512 bytes, because the middleware records
// the raw query and OAuth callbacks carry code and state [LOG-009]. JSON emitters print the latest value of a key,
// dev emitters every value (D40).
func RedactQuery(we *wideevent.Event, ginContext *gin.Context)
```

### 3.12 `prometheusadapter`

```go
type Options struct {
	Registerer prometheus.Registerer // required
	Namespace  string                // required, e.g. "forwardauth"
}
// New registers <namespace>_auth_outcomes_total{provider,action,result} (help text required) and returns the registration error [LIB-011].
func New(options *Options) (*OutcomeCounter, error)
// Observe has the auth.Observer shape and increments the counter.
func (c *OutcomeCounter) Observe(ctx context.Context, outcome auth.Outcome)
```
Labels are closed sets: configured provider names, `Action`, `Result` [MET-004].

### 3.13 Internal packages (contracts between work packages)

```go
package random
// Token returns byteCount crypto/rand bytes, base64url without padding.
func Token(byteCount int) (string, error)

package redirect
const ReturnParameter = "return_to"
// SafeReturnPath accepts only same-origin relative paths: starts with "/", second byte not "/" or "\",
// valid UTF-8, no control characters or "\" anywhere, url.Parse succeeds with empty Scheme, Host and Opaque, <= 2048 bytes.
// Returns the path as sent (never re-escaped) plus "?"+RawQuery when present (fragment dropped).
func SafeReturnPath(raw string) (string, bool)
// ReturnPath returns SafeReturnPath(request query return_to) or "/".
func ReturnPath(request *http.Request) string
// LoginLocation appends return_to=<returnPath> to loginURL (keeps an existing query); empty returnPath appends nothing.
func LoginLocation(loginURL, returnPath string) string
// ExternalURL validates an absolute http(s) URL without user info, query or fragment and trims a trailing "/".
// Errors never repeat the value.
func ExternalURL(raw string) (string, error)
// IsSecureURL: an absolute https URL with a host name, or http on a loopback host (localhost, 127.0.0.0/8, ::1;
// net.ParseIP, so no zoned IPv6), without user info (design D16). Used for issuer, Keycloak and GitHub URLs.
func IsSecureURL(raw string) bool
// IsAbsoluteHTTPURL: parses as an http or https URL with a host name.
func IsAbsoluteHTTPURL(raw string) bool
// IsTarget: a SafeReturnPath path or an IsAbsoluteHTTPURL URL, without a fragment (AbsoluteTarget's rule; Guard LoginURL).
func IsTarget(raw string) bool
// AbsoluteTarget validates a configured redirect target (ErrorURL, PostLogoutURL) and returns it absolute: a safe
// path is prefixed with externalURL (an ExternalURL result), an absolute http(s) URL is kept; a fragment is refused,
// so a query appended later (ErrorURL?code=...) stays in the query. Errors never repeat the value.
func AbsoluteTarget(raw, externalURL string) (string, error)
// IsPathPrefix: "/"-separated segments of A-Z a-z 0-9 . _ ~ -, no trailing "/", no "." or ".." segment, so the
// routes are neither ServeMux or gin wildcards nor removed by path cleaning (password, oidc, github PathPrefix).
func IsPathPrefix(prefix string) bool
// To answers 302 Found to location with Cache-Control no-store.
func To(writer http.ResponseWriter, location string)
// WithQuery appends the encoded values to target, keeping a query target already has.
func WithQuery(target string, values url.Values) string

package httpjson
// Decode requires Content-Type application/json, reads at most 64 KiB, rejects unknown fields and trailing data.
// Errors are plain fixed texts that never repeat request text (no field name, no value); callers wrap them as
// *auth.Error{Kind: auth.ErrInvalidRequest}.
func Decode(writer http.ResponseWriter, request *http.Request, target any) error
// Write writes body as JSON with status, Content-Type application/json and Cache-Control no-store. It encodes
// first: a body that does not encode is answered 500 {"code":"internal","message":"internal error"} instead.
func Write(writer http.ResponseWriter, status int, body any)

package oauthlogin
type State struct {
	State      string `json:"state"`
	Nonce      string `json:"nonce"`
	Verifier   string `json:"verifier"`   // PKCE verifier: random.Token(32), the same form as oauth2.GenerateVerifier
	ReturnPath string `json:"returnPath"` // redirect.ReturnPath(request)
}
// Begin generates State (32 bytes), Nonce (32 bytes) and Verifier and stores them as JSON under key for 10 min:
// in the request's session while it holds a live identity (no Set-Cookie, nothing revoked, so a cross-site link to
// a login route ends no session; D14), else in a fresh one (Store.Start). A backend error reading the identity is
// returned. The callbacks call Store.Start after authentication, so the session ID still rotates at every login.
func Begin(ctx context.Context, store *session.Store, writer http.ResponseWriter, request *http.Request, key string) (State, error)
// Codes of the login refusals, shared by oauthlogin, oidc and github (wire values, binding).
const (
	CodeLoginFailed   = "login_failed"   // the code exchange or the verification of its answer failed
	CodeLoginDenied   = "login_denied"   // the provider sent error=... (the user or the provider refused)
	CodeLoginExpired  = "login_expired"  // no, an expired or an unreadable login state
	CodeStateMismatch = "state_mismatch" // the callback state does not match the stored one
)
// Complete opens the session, pops key (single use) and compares the callback state in constant time.
// Refusals (*auth.Error): provider sent error=...: ErrUnauthenticated code "login_denied" (checked before the
// session is read, so it does not consume the state); no, empty or expired state: ErrInvalidRequest "login_expired";
// mismatch: ErrInvalidRequest "state_mismatch"; no code: ErrInvalidRequest.
func Complete(ctx context.Context, store *session.Store, request *http.Request, key string) (State, error)

package backendtest
// Run exercises every session.Backend contract (put/get/pop/compare-and-swap/revoke, TTL, atomic pop and swap under
// -race, revoke marker vs put, no marker for an unknown session, a marker never outliving the revoked values, a
// marker ignoring replaced and popped values).
// newBackend returns a fresh, empty backend per subtest and the function that moves its clock forward
// (miniredis: FastForward; the memory backend: its test clock), so TTL tests never sleep.
func Run(t *testing.T, newBackend func(t *testing.T) (session.Backend, func(duration time.Duration)))

package dependency
// Error returns "<operation>: <err>" with err's message but without its chain, so callers cannot match on a
// third-party error (LIB-010). When err matches context.Canceled or context.DeadlineExceeded, that sentinel is
// wrapped, so errors.Is keeps working for cancellation. An HTTP call's *url.Error in err (also wrapped by a
// dependency) is reduced to `<operation>: <method> "<scheme>://<host>": <TransportFailure>`: no path, query, user
// info, outer wrapper text or server bytes [LOG-009]. Used for go-redis, go-oidc, jwx errors, every outbound HTTP
// call (github, keycloak, jwt JWKS fetch), token requests that got no answer (through tokenendpoint.Error) and
// apikey Resolver errors (D23).
func Error(operation string, err error) error
// TransportFailure reduces an HTTP transport error to what is safe to record: context.Canceled and
// context.DeadlineExceeded (an http.Client timeout too) as they are, a dial error with its text (address, system
// error), another timeout as "timeout", anything else "transport failure (<type of the innermost error>)".
// Used by Error and by the forward-auth binary's dependency recorder.
func TransportFailure(err error) error

package failure
// Result is the Outcome Result of an action that failed with err: ResultError when auth.ResponseFor answers 500,
// ResultDenied (a refusal) otherwise. Used by the Guard, every provider, apikey and the jwt verifier.
func Result(err error) auth.Result
type ReporterOptions struct {
	Provider string        // required; set as Outcome.Provider
	Observer auth.Observer // optional; nil reports nothing
	ErrorURL string        // optional; where RefuseCallback sends the browser: "" or redirect.IsTarget (path or absolute http(s) URL, no fragment)
}
// NewReporter validates options (nil or empty Provider: error) and returns a Reporter working on a copy of them.
// password, oidc (Provider = Options.Name, before discovery) and github each call it in New and return its error.
func NewReporter(options *ReporterOptions) (*Reporter, error)
// Reporter answers a provider's failed requests and reports the outcome of every request. Safe for concurrent use.
type Reporter struct{ /* unexported */ }
// Refuse answers outcome.Err as JSON (auth.WriteError) and reports the outcome as a failure.
func (r *Reporter) Refuse(ctx context.Context, writer http.ResponseWriter, outcome auth.Outcome)
// RefuseCallback is Refuse, except that with ErrorURL set the failure (a refusal or code=internal) redirects
// 302 to ErrorURL?code=<code> (redirect.WithQuery).
func (r *Reporter) RefuseCallback(ctx context.Context, writer http.ResponseWriter, outcome auth.Outcome)
// UnlessAbsent returns err unless it only says there is nothing (auth.ErrUnauthenticated: no session, no identity
// in it); github and oidc logout use it to tell a read failure from an absent session.
func UnlessAbsent(err error) error
// ReportFailure reports outcome with Result denied (a refusal) or error (answered with 500).
func (r *Reporter) ReportFailure(ctx context.Context, outcome auth.Outcome)
// Report sets Provider on outcome and passes it to the Observer.
func (r *Reporter) Report(ctx context.Context, outcome auth.Outcome)

package tokenendpoint
// Error returns "<operation>: token endpoint answered HTTP <status> [<OAuth error code>]" for an error answer of
// the endpoint (*oauth2.RetrieveError; the code only when it is a-z/"_" and at most 64 bytes, nothing of
// ErrorDescription, ErrorURI or Body; no Response: no status). A failed call (*url.Error) or a cancelled or expired
// context goes through dependency.Error, so the context error stays detectable. Anything else is an answer oauth2
// could not read (its parse error quotes the answer's values): "<operation>: token endpoint answered an unreadable
// token response". Used by oidc, oidc/keycloak and github.
func Error(operation string, err error) error
// Refused reports whether err is an error answer of the endpoint below 500 (an invalid code, verifier or client),
// as opposed to a failure or an unreachable endpoint. oidc and github answer it with 401 login_failed.
func Refused(err error) bool

package fetchmetadata
// RefuseCrossSite refuses a request the browser marks Sec-Fetch-Site: cross-site with *auth.Error{Kind:
// ErrForbidden, Reason: "cross-site request"} (403 forbidden); same-origin, same-site, none and requests without
// the header (older browsers, non-browser clients) pass with nil. First step of every logout route (D14).
func RefuseCrossSite(request *http.Request) error

package hook
// RunOnLogin returns what onLogin makes of identity, or identity itself when onLogin is nil. A hook error is
// wrapped with %w (a refusal keeps its kind and status); a hook returning no identity is an error.
func RunOnLogin(ctx context.Context, onLogin auth.Hook, identity *auth.Identity) (*auth.Identity, error)

package impersonation
// WithReal returns identity with its real identity replaced by refreshed: while impersonating a copy whose
// Impersonator is refreshed, otherwise refreshed itself. Neither input is modified. Used by the Guard refresh
// and github refresh-teams.
func WithReal(identity, refreshed *auth.Identity) *auth.Identity
```

`internal/fakeprovider` (test support, stdlib only, excluded from coverage; owners per file in section 9):
- `oidc.go`: `NewOIDCHandler(options *OIDCOptions) (*OIDCHandler, error)` (an `http.Handler`, needs `options.IssuerURL`; copies every slice and map of its options) and `StartOIDC(tb testing.TB, options OIDCOptions) *OIDCServer` (httptest wrapper). Serves below the issuer path: discovery, `/jwks` (RSA key generated per instance), `/authorize` (auto-approves the configured user: redirects to `redirect_uri` with `code` and `state`; without state, nonce or S256 challenge it answers `error=invalid_request`), `/token` (checks client secret, single-use code, redirect URI and PKCE S256, returns an RS256 ID token with the stored nonce and a JWT access token with configurable `realm_access`/`resource_access`/`groups`), `/end_session` (records `id_token_hint`, redirects to a registered `post_logout_redirect_uri`). Fault switches: omit `end_session_endpoint`, omit the ID token, opaque access token, wrong nonce, bad signature, expired ID token; `TokenAnswer` (an `http.Handler`) replaces `/token` for an IdP's error or broken answers.
- `keycloak.go` (same handler when `OIDCOptions.KeycloakRealm` is set): token endpoint for both grants and the five admin GETs with configurable roles, groups, attributes; counters for token requests and client lookups.
- `github.go`: `StartGitHub(tb testing.TB, options GitHubOptions) *GitHubServer`: `/login/oauth/authorize` (auto-approve), `/login/oauth/access_token` (client credentials, single-use code bound to its `redirect_uri`, PKCE check; a mismatch answers GitHub-style 200 `{"error":"redirect_uri_mismatch"}`), `/user`, `/user/teams` (paginated, `Link`-free: page size semantics like GitHub), `DELETE /applications/{client_id}/token` (records revoked tokens), `FailWith(endpoint, status)`, `SetTeams`, `Calls`. Plain HTTP on 127.0.0.1 (loopback exception).

---

## 4. Flows

Notation: "refuse X" = answer with `auth.WriteError` (or the ErrorURL redirect for oidc/github callbacks), report `Outcome{Result: denied, Err: X}`; "fail" = 500 `internal` and `Outcome{Result: error}`. Every handler reports exactly one outcome.

### F1 Password login (incl. TOTP)
1. `POST {prefix}/login` `{"identifier","password"}`; `httpjson.Decode`; failure: refuse ErrInvalidRequest.
2. Identifier with "@" is an email (refused path when DisableEmailLogin), else a username (refused path when DisableUsernameLogin). A refused path behaves exactly like an unknown user.
3. Lookup. `ErrUserNotFound`: run `Verify(password, dummyHash)` (same cost as a real check), refuse `{ErrUnauthenticated, Code "invalid_credentials", Reason "unknown user"}`. Other storage error: fail.
4. `Verify(password, user.PasswordHash)`. `ErrInvalidHash` with a LegacyVerifier: legacy verify. A stored hash that cannot be verified (`ErrInvalidHash` without a LegacyVerifier, or a LegacyVerifier error) costs the dummy verification like an unknown user and is refused `invalid_credentials` (Reason "stored password hash not verifiable"), not 500. On a match with a legacy hash, or with an Argon2id hash whose parameters differ from HashParameters: `Hash` the password and `UpdatePasswordHash(ctx, id, oldHash, newHash)`; a hashing or storage failure there does not deny the login, it makes the final outcome a degraded success (`Err` set); when the login is then refused or fails, `Err` carries both (the response follows the refusal or failure alone). Only login rehashes; the password checks of TOTP enable and disable do not.
5. Mismatch: refuse `invalid_credentials` (Reason "wrong password").
6. `user.TOTPEnabled` while `TOTP.Enabled` is off: fail (500, outcome error), so switching TOTP off never downgrades enrolled users to one factor (clear their TOTP in storage first). `TOTP.Enabled && user.TOTPEnabled`: `Store.Start`; put `password.pending` `{"userId","purpose":"verify","expiresAt"}` with TTL PendingTTL; 202 `{"challenge":"totp"}`; outcome challenge. The attempt counter is not reset here (D19).
7. `TOTP.Required && !user.TOTPEnabled`: same with `"purpose":"enrollment"`; 202 `{"challenge":"totp_setup"}`.
8. Identity `{Provider "password", Subject id.String(), UserID id, Username, Email, Active true}`; `OnLogin` (refusal or failure per `auth.Hook` doc). `OnLogin` must keep `UserID` (Refresh and the TOTP routes look the user up by it); a hook that replaces it fails the login (500, no session). Every path that admits a user (login, verify, enrollment) applies this.
9. `Store.Start` (rotates, revokes any previous session); `SaveIdentity`; 200 `IdentityResponse`; outcome success.

### F2 TOTP verify
1. `POST {prefix}/totp/verify`; `Store.Open`; `Get password.pending` with purpose verify and `expiresAt` in the future, else refuse `{ErrUnauthenticated, "no_pending_login"}`.
2. `GetUserByID`; not found or `!TOTPEnabled`: `Store.End`, refuse `no_pending_login`.
3. `ConsumeTOTPAttempt(id, MaximumAttempts)`; exhausted: `Store.End`, refuse `{ErrUnauthenticated, "invalid_totp_code", Reason "attempts exhausted"}`.
4. `backupCode == false`: TOTP code only: find the time step within the skew whose code matches (period, digits) and `ConsumeTOTPStep`; `false` (replayed, or not later than the last used step) counts as wrong, and so does a code of the wrong length. A stored secret that does not decode fails (500, outcome error, user ID but never the secret in the error; the attempt is spent, `SetTOTP`/`ClearTOTP` reset the counter anyway). `backupCode == true`: backup codes only (none when disabled): find the matching backup hash, `ConsumeBackupCode`; `false` (raced) counts as wrong. A stored backup code hash that `Verify` cannot read fails (500, outcome error with the user ID, never the code or hash; the attempt is spent). A wrong TOTP code never costs an Argon2id run.
5. Wrong: when `remaining == 0` `Store.End`; refuse `invalid_totp_code`.
6. `ResetTOTPAttempts`; identity as F1.8; `OnLogin`; `Store.Start` (the pending session is revoked); `SaveIdentity`; 200 `IdentityResponse`.

Wherever F2 ends the pending session (steps 2, 3, 5), a failing `Store.End` fails (500, outcome error) instead of answering the refusal; the refusal is answered only after a successful revocation.

### F3 TOTP enrollment, management, logout
- Setup: session must be full or pending enrollment (else refuse ErrUnauthenticated); user already enabled: refuse `{ErrConflict, "totp_already_enabled"}`; generate key; put `password.totp_setup` `{"secret"}` (10 min); 200 setup response.
- Enable: same session rule; user already enabled: refuse `totp_already_enabled`; `Verify` password (wrong: refuse `invalid_credentials`); `Get password.totp_setup` (missing: refuse `{ErrInvalidRequest, "totp_setup_missing"}`; undecodable or without a secret: 500; it stays for a retry after a wrong code, the session started on success drops it, in a full session it is dropped by disable or expires after its 10 min); validate code and `ConsumeTOTPStep` (wrong or replayed: refuse `invalid_totp_code`); generate backup codes unless disabled. Full session: `SetTOTP`, no session write. Enrollment session: identity, `OnLogin`, `Store.Start`, then `SetTOTP`, then `SaveIdentity`, so a refused or failed login leaves the account unchanged and no full session exists without the second factor (a `SaveIdentity` failure after `SetTOTP` is still a 500 with TOTP on; the user logs in with the scanned authenticator). `SetTOTP` false (a concurrent enrollment enabled TOTP first): refuse `totp_already_enabled`, nothing changed, no identity saved (an enrollment session is then empty). 200 `{"backupCodes"}`.
- Disable: full session; password check; not enabled: refuse `{ErrConflict, "totp_not_enabled"}`; `ClearTOTP`; pop a pending `password.totp_setup` (else enable would re-arm its old secret; a failed drop degrades the outcome, still 204); 204.
- Status: full session; 200 `{"enabled"}`.
- Logout: `Sec-Fetch-Site: cross-site`: refuse 403 `forbidden`, nothing read or ended (D14); read identity if any on `context.WithoutCancel(request.Context())`; `Store.End`; `OnLogout(identity)` with that detached context when there was one; 204; outcome success. A read failure (other than no session) ends the session all the same and degrades the outcome (success with `Err`); OnLogout does not run.
- Register: decode; at least one of username/email (refuse ErrInvalidRequest); a disabled identifier kind: refuse ErrInvalidRequest; validate (`invalid_username`, `invalid_email`, `weak_password`, all ErrInvalidRequest); `Hash`; `CreateUser` with `uuid.New()`; `ErrUserExists`: refuse `{ErrConflict, "user_exists"}`; then as F1 from step 7: with `TOTP.Required` a pending enrollment session and 202 `{"challenge":"totp_setup"}`, otherwise identity, `OnLogin`, `Store.Start`, `SaveIdentity`, 201.

### F4 OIDC login
1. `GET {prefix}/login[?return_to=...]`.
2. `oauthlogin.Begin(ctx, store, writer, request, Name+".login")`.
3. 302 to `AuthCodeURL(state, gooidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))`; outcome success (Action login).

### F5 OIDC callback
1. `oauthlogin.Complete(..., Name+".login")`; refusals as listed.
2. Exchange `code` with `oauth2.VerifierOption(verifier)` (ctx carries HTTPClient). The IdP answered with an error below 500 (`tokenendpoint.Refused`): refuse `{ErrUnauthenticated, "login_failed", Reason "token exchange"}`; a 5xx answer or an unreachable IdP: fail (500). Either error is `tokenendpoint.Error("oidc: exchange code", err)`: status and OAuth error code only, never the IdP's description or body (LOG-009).
3. `id_token` present and verified (`Verifier` with ClientID audience: signature, iss, aud, exp); `idToken.Nonce == state.Nonce` (constant time); a non-empty `sub`; failures refuse `login_failed`. A verification failure has the fixed Reason `ID token expired` or `ID token verification` (Err only a cancelled callback's `ctx.Err()`), never go-oidc's message, which quotes the token header and claims and the JWKS request's error; a JWKS outage therefore reads like an invalid token.
4. ID token claims into a map; ClaimMapper; access token claims via the audience-free verifier (opaque token: ignored, A-2.4).
5. AllowedEmailDomains set: `email_verified == true` and domain allowed (ASCII lower-cased; a non-ASCII domain never matches, since Unicode folding maps the Kelvin sign to `k`), else refuse `{ErrForbidden, Reason "email domain not allowed"}`.
6. Identity `{Provider Name, Subject sub, Username/Name/Email/Picture from Profile, Active true, OIDCRoles, OIDCClientRoles, Groups from tokens, Claims}`.
7. `OnLogin` (e.g. Keycloak `Enrich` replaces roles/groups/attributes and enforces required ones).
8. `Store.Start`; put `<Name>.id_token` (raw) with TTL MaximumAge; `SaveIdentity` (the identity last, so a failed write leaves no authenticated session behind).
9. 302 to `ExternalURL + state.ReturnPath`; outcome success.

Every failure of steps 1-8 (refusals and 500s) is answered by the ErrorURL redirect `ErrorURL?code=<code>` (`code=internal` for a 500) when ErrorURL is set, else by JSON.

### F6 OIDC logout (RP-initiated)
1. `GET {prefix}/logout`. When `iss` or `sid` is present, or `Sec-Fetch-Dest: iframe` and detection is not disabled: run F7 instead. Then `Sec-Fetch-Site: cross-site`: refuse 403 `forbidden` JSON, nothing read or ended (D14); with detection disabled a cross-site iframe load of `/logout` is therefore refused.
2. Read the session identity and, when `identity.Real().Provider == Name`, the stored ID token, both on `context.WithoutCancel(request.Context())`, so a disconnecting client skips neither the hint nor OnLogout. A read failure (other than no session) ends the session all the same and degrades the outcome (success with `Err`): OnLogout or the `id_token_hint` is lost.
3. `Store.End` (a failure: 500 JSON, its outcome also carries a step 2 read failure); `OnLogout(identity)` with that detached context.
4. With a discovered `end_session_endpoint` and an ID token: 302 to it with `client_id`, `id_token_hint`, `post_logout_redirect_uri=PostLogoutURL`. Otherwise (no endpoint, or no stored ID token, e.g. the local session already expired) 302 straight to PostLogoutURL: the IdP session stays.

### F7 OIDC front-channel logout
1. `GET {prefix}/frontchannel-logout?iss=..&sid=..`; headers `Cache-Control: no-store, must-revalidate`, `Pragma: no-cache`. Refusals answer plain text (the IdP's iframe reads no JSON). The session is read, ended and OnLogout runs on `context.WithoutCancel(request.Context())`, as in F6; a failed read degrades the outcome as in F6, and a refusal or failed `Store.End` carries it as well.
2. `iss` and `sid` both non-empty or both absent, else 400; `iss` present and not the Issuer: 400.
3. No readable session identity: `Store.End` (expire cookie only); 200 page.
4. `identity.Real().Provider != Name`: 200 page, nothing ended.
5. `sid` present and not equal to `identity.Real().Claims["sid"]`: 400.
6. `Store.End` (a failure: 500); `OnLogout(identity)`; 200 `<!doctype html><html><head><title>Logged out</title></head><body></body></html>`. The cookie reaches the iframe only with `SameSite=None` (StoreOptions).

### F8 GitHub login, callback, logout
1. Login: as F4 with key `github.login`, `AuthCodeURL(state, S256ChallengeOption(verifier))`.
2. Callback: `oauthlogin.Complete`; exchange with verifier (GitHub refusing the code: 401 `login_failed`; 5xx or unreachable: 500; an error answer is reported by status and OAuth error code only, section 3.8); fetch `/user` and all `/user/teams` pages; slugs `lower(org/slug)`; none in AllowedTeams: refuse `{ErrForbidden, Reason "not in an allowed team"}` (no session; an AdminTeams membership alone is not enough).
3. Identity `{Provider "github", Subject user.id, Username login, Name, Email (may be empty), Picture avatar_url, Active true, Teams filtered (sorted, unique), Roles [admin] when in AdminTeams}`; `OnLogin`.
4. `Store.Start`; put `github.token` (JSON `oauth2.Token`, TTL MaximumAge); `SaveIdentity` (token first, so a failed write never leaves an identity without its token); 302 `ExternalURL + returnPath`. Callback failures (steps 2-4) go to ErrorURL as in F5.
5. Logout `GET {prefix}/logout`: `Sec-Fetch-Site: cross-site`: refuse 403 `forbidden`, nothing read, ended or revoked (D14); read identity and token on `context.WithoutCancel` (a disconnecting client skips neither the revocation nor OnLogout; a read failure ends the session all the same and degrades the outcome: Result success, Err set); `Store.End` (a failure: 500, nothing revoked); `DELETE {APIURL}/applications/{ClientID}/token` (basic auth, body `{"access_token"}`, synchronous under `context.WithoutCancel` with its own 10 s timeout, failure only degrades the outcome); `OnLogout`; 302 PostLogoutURL.

### F9 GitHub refresh (route and Refresher)
1. `POST {prefix}/refresh-teams`: `Sec-Fetch-Site: cross-site`: refuse 403 `forbidden`, nothing read, called or ended (D14: a refusal could end a `SameSite=None` session); `Store.Open`; identity whose `Real().Provider` is "github" (else refuse ErrUnauthenticated, session kept); token.
2. Refetch teams for the real identity (Refresher: same from step 2 on, with the Guard's session and real identity).
3. GitHub 401 or no token: ErrUnauthenticated. No allowed team any more: ErrForbidden. On both the route ends the session and refuses; when ending it fails, the route answers 500 and reports an error instead (the session is still usable). The Refresher returns the error (the Guard ends the session).
4. Clone identity; replace `Teams`; add or remove only `auth.RoleAdmin` in `Roles`; route: write it back with `impersonation.WithReal` through `Session.SwapIdentity` against the identity read in step 1. When another request saved meanwhile (a deactivation, an impersonation, the Guard's refresh), re-read once and apply the fetched membership to that save (no second GitHub call), so neither change is lost. When that save changed the membership or the user (Provider, Subject, Teams or the admin role of the real identity differ from step 1, e.g. a newer refresh that removed the admin role), refuse `{ErrConflict, Reason "team membership changed by another request during the team refresh"}` (409 `conflict`, outcome carries the latest identity): the membership fetched here may be the older one. A second conflict refuses `{ErrConflict, Reason "session saved by other requests during the team refresh"}` (409). 200 `IdentityResponse` of the saved identity.

### F10 API key
1. `apikey.Middleware`: key from HeaderName, else from `Authorization` with the `Bearer` scheme (case-insensitive); none: next handler unchanged.
2. SHA-256 of the key, compared with every static hash (constant time, no early exit); match: static identity.
3. Else Resolver: identity: next with a clone of it (Provider defaulted); error matching ErrUnauthenticated or nil identity: refuse `{ErrUnauthenticated, "invalid_api_key"}`; any other error: fail (500, whatever its kind).
4. No Resolver and no match: refuse `invalid_api_key`. Outcome Action authenticate in every case.

### F11 Guard (session authentication, both variants)
1. Identity already in context (apikey ran): next, nothing reported.
2. `Store.Open`, `Session.Identity`; missing, expired or revoked: refuse ErrUnauthenticated (Outcome Provider "session"): RequireAPI 401 JSON; RequireUI 302 `redirect.LoginLocation(LoginURL, SafeReturnPath(ReturnPathHeader value, or RequestURI without one))`. A backend failure: 500 `internal` JSON in both variants, outcome error.
3. Real identity refreshed longer than RefreshInterval ago and a Refresher named `real.Provider` exists: claim the refresh by swapping (`Backend.CompareAndSwap`) the envelope read in step 2 for one with refreshedAt moved to now, then call the Refresher with a clone of the real identity. The claim, the Refresher and every save after them run on `context.WithTimeout(context.WithoutCancel(ctx), 30 s)`: a client aborting each due refresh would otherwise turn a refusal into a degraded result and keep the claim, so a revoked identity would live until MaximumAge. One call per interval per session: requests reading the session meanwhile find it fresh, and a request losing the claim (another one claimed or saved first) continues with the identity it read, without a call. A claim the backend fails may have committed with its reply lost (the session would then pass as fresh for RefreshInterval without a refresh, also past MaximumUnverifiedAge), so the refresh runs anyway with the claim's error on the outcome (degraded); a claim that did not commit makes the final save lose its swap. A claim that was never sent fails the request at once: a session that expired meanwhile is refused like any expired session (401, or the login redirect for RequireUI), a sealing failure is a 500.
   - ok: identity (or its Impersonator, when impersonating) replaced via `impersonation.WithReal`, saved; outcome success, Action refresh.
   - ErrUnauthenticated/ErrForbidden: `Store.End`; refuse (401 per variant, 403 JSON in both); only the refresh outcome is reported. When `Store.End` fails, the session stays usable: 500 `internal` in both variants, outcome error (the refusal kept as text only, so it cannot decide the answer), and the refresh claim is released (best effort: the claimed envelope is swapped back to the refreshedAt read in step 2), so the next request refreshes again and fails closed instead of passing for RefreshInterval.
   - other error, or a nil identity without error: keep the identity, save it unchanged (moves refreshedAt, so a GitHub outage costs one call per interval), outcome success with `Err` set (degraded) and Action refresh, continue. Once the envelope's `verifiedAt` (set at the login and on every successful refresh; an envelope without it counts from `authenticatedAt`) is older than `MaximumUnverifiedAge`, the failure is handled like a refusal instead: `*auth.Error{Kind: ErrUnauthenticated, Reason: "identity could not be verified", Err: <failure>}`, the session ends.
   - The save is a `Backend.CompareAndSwap` against the claimed envelope, keeping its expiry (so a refresh never touches the lifetime, D8). A lost swap (another save, a logout or the expiry won meanwhile) continues with what is stored now: 401 "no session identity" when nothing is. A backend failure: 500.
   - Not covered by `SaveIdentity`: a stale `SaveIdentity` from application code (impersonation, TOTP enable) racing a refresh still overwrites it. Application code that must not lose a concurrent save uses `Session.SwapIdentity` against the identity it read (as github refresh-teams does).
4. Request context gets `auth.WithIdentity`; outcome success, Action authenticate, Provider = the real identity's provider; next.

### F12 Forward-auth UI check (`GET {prefix}/ui`, called by Traefik)
1. wide event, metrics, panic recovery.
2. apikey middleware (with `API_KEYS_ENABLED`).
3. Guard RequireUI with `ReturnPathHeader = "X-Forwarded-Uri"`, `LoginURL` = provider `LoginURL()` (absolute, so Traefik passes it to the browser unchanged: a relative Location reaches the browser as `http://forwardauth:8080/...`).
4. An inactive identity: 403 `forbidden` (Reason `auth.ReasonInactive`), with or without JWT.
5. JWT enabled: `Signer.Sign(identity)` (failures: 500); response header `<JWT_HEADER>: Bearer <token>`.
6. 200 empty body with `Cache-Control: no-store`. Traefik copies `authResponseHeaders` into the upstream request; non-2xx answers (302, 401, 403, Set-Cookie) go to the client.

### F13 Forward-auth API check (`GET {prefix}/api`)
As F12 with `RequireAPI` (401 JSON instead of the redirect).

### F14 JWT signing (in F12/F13)
Claims per section 3.4, RS512, header `kid` = thumbprint, `typ` JWT. A new token per request, Lifetime default 5 min.

### F15 JWT verification (backend)
1. `jwt.NewVerifier(ctx, {JWKSURL: "https://app/auth/jwks", Issuer: <JWT_ISSUER>})` at startup.
2. Middleware: `Authorization: Bearer <token>`; missing: 401 `unauthenticated`; invalid: 401 `invalid_token` (both with `WWW-Authenticate: Bearer`); else identity into context.
3. Unknown `kid` or keys older than RefreshInterval: refetch JWKS (once per minute at most, detached from the request, 10 s) before verifying. A failed refetch for an unknown kid: 500; for a known kid: verify with the previous keys (degraded outcome, or the refusal joined with the refresh error).
4. Then `ginadapter.Require(authorization.HasOIDCRole("x"))` etc.

---

## 5. Errors, JSON shape, status mapping, wide-event recording

### 5.1 Taxonomy
Callers branch with `errors.Is(err, auth.ErrUnauthenticated | ErrForbidden | ErrInvalidRequest | ErrConflict)` [ERR-005]. Providers return or answer `*auth.Error`. Storage contracts use the `password` sentinels. `session.ErrRevoked` is internal to backends and the store (it surfaces as ErrUnauthenticated).

### 5.2 Status mapping (`auth.ResponseFor`)

| Kind (errors.Is) | Status | Default code | Message (fixed) |
|---|---|---|---|
| ErrUnauthenticated | 401 | `unauthenticated` | `authentication required` |
| ErrForbidden | 403 | `forbidden` | `access denied` |
| ErrInvalidRequest | 400 | `invalid_request` | `invalid request` |
| ErrConflict | 409 | `conflict` | `conflict` |
| anything else | 500 | `internal` | `internal error` |

`Code` of an `*auth.Error` replaces the default code; status and message always follow the Kind. `Reason` and `Err` never reach the client, so required role names, team names and allowed domains never leak (decision 10).

### 5.3 Client codes (binding, stable API for frontends)

| Code | Kind | Raised by |
|---|---|---|
| `invalid_credentials` | Unauthenticated | password login, enable, disable |
| `no_pending_login` | Unauthenticated | password totp/verify |
| `invalid_totp_code` | Unauthenticated | password totp/verify, enable |
| `totp_setup_missing` | InvalidRequest | password totp/enable |
| `totp_already_enabled`, `totp_not_enabled` | Conflict | password totp/setup, enable, disable |
| `user_exists` | Conflict | password register |
| `weak_password`, `invalid_username`, `invalid_email` | InvalidRequest | password register |
| `login_expired`, `state_mismatch` | InvalidRequest | oidc/github callback |
| `login_denied`, `login_failed` | Unauthenticated | oidc/github callback |
| `invalid_api_key` | Unauthenticated | apikey |
| `invalid_token` | Unauthenticated | jwt verifier |
| `internal` | (500) | every unhandled failure; also the `code` of an ErrorURL redirect for a 500 |
| `not_found`, `unavailable` | (404, 503) | forward-auth binary only: unknown route, readiness while shutting down or Redis down |
| (defaults) | all | everything else |

### 5.4 Wide-event recording (`ginadapter.Observe`)

| Key | Value | When |
|---|---|---|
| `auth.provider` | Outcome.Provider | always |
| `auth.action` | Outcome.Action | always |
| `auth.result` | Outcome.Result | always |
| `auth.code` | response code of Err | Err != nil |
| `auth.reason` | `*auth.Error` Reason | Reason set |
| `auth.error` | Err.Error() | Result error, or success with Err (degraded) |
| `degraded` | true | Result success/challenge with Err != nil [LOG-002, LOG-010] |
| `auth.subject` | Identity.Real().Subject | Identity != nil |
| `auth.impersonating` | true | Identity.Impersonator != nil |
| `user.id` (`we.UserID`) | Identity.UserID | Identity != nil and UserID != uuid.Nil |
| outcome | `we.Failure(Err)` | Result denied or error |
| outcome | `we.Success()` | Result success/challenge and Action not authenticate/refresh (the library answered the request itself) |
| `auth.refresh.provider`, `.action`, `.result`, `.code`, `.reason`, `.error`, `.subject`, `.impersonating` | as the `auth.*` keys above | Action refresh: the Guard reports the refresh on the same event before the authenticate outcome, so its fields get their own prefix; it never sets `user.id`. `degraded` and the request outcome stay top-level |

`ginadapter.Require` records `authorization.denied=true`, `authorization.reason` (Reason, or Err.Error() for non-`*auth.Error`), `authorization.error` (internal errors only) and `we.Failure(err)`. Never usernames, emails, names, tokens, codes, keys [LOG-009]. One `Set` per key per event [LOG-006].

---

## 6. Forward-auth binary

### 6.1 Layout
- `cmd/forwardauth/main.go` only [LAY-001]: `var version = "dev"` (ldflags), `main` calls `run() error`; `run` = `signal.NotifyContext(SIGINT, SIGTERM)` -> `loadConfiguration` -> `validateConfiguration` -> `config.Print()` -> `gin.SetMode` (release, debug with DEV_MODE; process-wide, so main sets it) -> metrics registry (Go, process, build-info collectors) + dependency recorder (`forwardauth.NewDependencies`) -> session backend + store (with SESSION_REDIS_ENABLED: Redis client, `PING` with 5 s, the boot fails with `SESSION_REDIS_ADDRESS: ping Redis at <address>: <error>` when Redis does not answer [RES-007]) -> outcome counter + observer -> provider -> guard -> apikey -> signer -> `forwardauth.NewServer` -> `Run(ctx)` [LAY-002]; the Redis client is closed after the drain. The Redis client never retries a command (`MaxRetries: -1`) and honours context deadlines (`ContextTimeoutEnabled`), so the 2 s readiness check and a request's own deadline bound every command. Startup and shutdown lines through `log/slog` JSON on stdout (stdlib instead of zerolog: one dependency less; LOG-012 only governs where such lines may appear).
- `internal/forwardauth`: the server (gin engine, routes, forward handler, wide-event middleware setup, HTTP metrics middleware, readiness, graceful run).
- Provider: one per instance, `PROVIDER=oidc` or `PROVIDER=github`. Password is not offered (it needs a user store and a login UI; Traefik's basicAuth covers static users). Several OIDC IdPs behind one binary (old GOOGLE_ENABLED multi mode) are dropped: Google is `PROVIDER=oidc` with Google's issuer and `OIDC_CLAIM_MAPPER=google`.

### 6.2 Configuration (config v2, `.Into` one struct in main [CFG-001, CFG-003, CFG-006])

```go
// Configuration holds every value forwardauth reads, filled once at startup.
type Configuration struct { /* one field per row below, named after the variable in CamelCase, e.g. SessionMaximumAgeSeconds int */ }
```
Values without a default are required: `LoadConfig` fails and the process exits non-zero before anything starts (MaPa's prime directive). "not empty" marks values with a default that refuse an explicitly empty value (`NotEmpty`). Lists (`string array`) are comma-separated, items trimmed, empty items dropped. Provider- and feature-dependent values have empty defaults and are checked by `validateConfiguration`, which returns every problem joined (`errors.Join`) and also fails the boot [CFG-004]. `config.LoadConfig` reads `.env` in the working directory if present (dev only; the image has none) [DEP-007]. Sensitive values are masked by `config.Print`.

| Variable | Type | Default | Required | Sensitive | Notes / maps to |
|---|---|---|---|---|---|
| `PROVIDER` | string | - | yes | | `oidc` or `github` |
| `EXTERNAL_URL` | string | - | yes | | public origin of the protected app (scheme and host, no path; one trailing "/" is trimmed), e.g. `https://app.example.com`; providers' ExternalURL |
| `PATH_PREFIX` | string | `/auth` | not empty | | all routes below; passes `forwardauth.ValidatePathPrefix` (`redirect.IsPathPrefix`: segments of `A-Z a-z 0-9 . _ ~ -`, no trailing "/", no "." or ".." segment) |
| `PORT` | int | `8080` | | | public listener, 1..65535 |
| `METRICS_PORT` | int | `9090` | | | `/metrics` listener [MET-001], 1..65535, not PORT |
| `DEV_MODE` | bool | `false` | | | dev wide-event emitter, gin debug mode [LOG-013] |
| `WIDE_EVENT_SAMPLE_RATE` | int | `10` | | | >= 1; keep every Nth successful event; failures, 401/403, degraded always kept [LOG-010] |
| `SHUTDOWN_DELAY_SECONDS` | int | `5` | | | 0..10; readiness 503 before draining [LAY-003], so delay plus the 20 s drain stay within the 30 s default termination grace period (`forwardauth.MaximumShutdownDelay`); e2e sets 0 |
| `IDENTITY_ENDPOINT_ENABLED` | bool | `false` | | | mounts `{prefix}/me` |
| `API_KEYS_ENABLED` | bool | `false` | | | mounts the apikey middleware on both checks; while false, `API_KEYS` and `API_KEY_PERMISSIONS` are ignored |
| `API_KEYS` | string array | `[]` | when API keys (>= 1) | yes | entries `name:secret` (split at the first ":", name not empty; a malformed entry is reported by position, never echoed); secrets per `apikey.Key` (>= 16 bytes, unique, judged by `apikey.New` during validation), so no "," in a secret |
| `API_KEY_PERMISSIONS` | string array | `[]` | | | entries `<name>=<permission>[+<permission>...]`, e.g. `ci=builds:write+deployments:read,reader=*:read`; split at the first "=", then on "+", each part `auth.ParsePermission`; becomes `apikey.Key.Permissions`. A key without an entry has no permissions |
| `SESSION_ENCRYPTION_KEY` | string | - | yes | yes | base64 of 32 bytes (`session.ParseKey`) |
| `SESSION_COOKIE_NAME` | string | `forwardauth_session` | not empty | | sent as `__Host-forwardauth_session` unless a domain or an insecure cookie is configured |
| `SESSION_COOKIE_DOMAIN` | string | `""` | | | host-only by default |
| `SESSION_INSECURE_COOKIE` | bool | `false` | | | required for a plain `http` EXTERNAL_URL off loopback, refused with an `https` one |
| `SESSION_SAME_SITE` | string | `lax` | not empty | | `lax` or `none` (none for front-channel logout; not with an insecure cookie). `strict` is refused: every login returns from the provider's site, and the browser withholds a strict cookie, the login state with it, on that redirect |
| `SESSION_MAXIMUM_AGE_SECONDS` | int | `86400` | | | >= 1 |
| `SESSION_REFRESH_INTERVAL_SECONDS` | int | `60` | | | >= 1; Guard RefreshInterval (GitHub teams) |
| `SESSION_MAXIMUM_UNVERIFIED_AGE_SECONDS` | int | `3600` | | | >= SESSION_REFRESH_INTERVAL_SECONDS; Guard MaximumUnverifiedAge |
| `SESSION_REDIS_ENABLED` | bool | `false` | | | otherwise in-memory: exactly one replica |
| `SESSION_REDIS_ADDRESS` | string | `""` | when Redis | | `host:port` (`redis.NewClient`); pinged at boot (5 s), no answer fails the boot |
| `SESSION_REDIS_PASSWORD` | string | `""` | | yes | |
| `SESSION_REDIS_DATABASE` | int | `0` | | | >= 0 |
| `SESSION_REDIS_KEY_PREFIX` | string | `forwardauth` | not empty | | |
| `OIDC_NAME` | string | `oidc` | not empty | | provider Name, routes `{prefix}/oidc/<name>/*` |
| `OIDC_ISSUER` | string | `""` | when oidc | | |
| `OIDC_CLIENT_ID` | string | `""` | when oidc | | |
| `OIDC_CLIENT_SECRET` | string | `""` | when oidc | yes | |
| `OIDC_SCOPES` | string array | `openid,profile,email` | not empty | | |
| `OIDC_CLAIM_MAPPER` | string | `default` | not empty | | `default` or `google` |
| `OIDC_ALLOWED_EMAIL_DOMAINS` | string array | `[]` | | | strongly recommended with Google |
| `OIDC_POST_LOGOUT_URL` | string | `""` | | | default EXTERNAL_URL + "/"; path or absolute http(s) URL |
| `OIDC_DISABLE_IFRAME_LOGOUT_DETECTION` | bool | `false` | | | |
| `KEYCLOAK_ENABLED` | bool | `false` | | | OnLogin = `keycloak.Client.Enrich`; requires PROVIDER=oidc |
| `KEYCLOAK_URL`, `KEYCLOAK_REALM` | string | `""` | when Keycloak | | |
| `KEYCLOAK_AUTHENTICATION_REALM` | string | `""` | | | default KEYCLOAK_REALM |
| `KEYCLOAK_GRANT_TYPE` | string | `client_credentials` | not empty | | or `password` |
| `KEYCLOAK_CLIENT_ID` / `KEYCLOAK_CLIENT_SECRET` | string | `""` | client credentials | secret | |
| `KEYCLOAK_USERNAME` / `KEYCLOAK_PASSWORD` | string | `""` | password grant | password | |
| `KEYCLOAK_CLIENT_ROLES_CLIENT_ID` | string | `""` | | | |
| `KEYCLOAK_REQUIRED_REALM_ROLES`, `KEYCLOAK_REQUIRED_CLIENT_ROLES`, `KEYCLOAK_REQUIRED_GROUPS` | string array | `[]` | | | required client roles need KEYCLOAK_CLIENT_ROLES_CLIENT_ID; refused without KEYCLOAK_ENABLED=true |
| `GITHUB_CLIENT_ID` | string | `""` | when github | | |
| `GITHUB_CLIENT_SECRET` | string | `""` | when github | yes | |
| `GITHUB_SCOPES` | string array | `read:org` | not empty | | must include `read:org`, `write:org`, `admin:org`, `user` or `repo` (a scope that lists teams; `github.New` refuses otherwise) |
| `GITHUB_AUTHORIZE_URL`, `GITHUB_TOKEN_URL`, `GITHUB_API_URL` | string | github.com defaults | not empty | | GHE |
| `GITHUB_ALLOWED_TEAMS` | string array | `[]` | when github (>= 1) | | |
| `GITHUB_ADMIN_TEAMS`, `GITHUB_RELEVANT_TEAMS` | string array | `[]` | | | |
| `JWT_ENABLED` | bool | `false` | | | |
| `JWT_PRIVATE_KEY` | string | `""` | when JWT | yes | PEM; no generated fallback (it broke multi-replica and restarts) |
| `JWT_ISSUER` | string | `""` | | | default EXTERNAL_URL (without a trailing "/") |
| `JWT_AUDIENCE` | string array | `[]` | | | |
| `JWT_LIFETIME_SECONDS` | int | `300` | | | 1..86400 |
| `JWT_HEADER` | string | `Authorization` | not empty | | value `Bearer <jwt>`; an HTTP header name (RFC 9110 token), not `Cache-Control`, `Set-Cookie`, `Connection`, `Content-Length`, `Transfer-Encoding`, `Cookie` or `Host` (`forwardauth.ValidateJWTHeader`) |

`validateConfiguration` checks: EXTERNAL_URL via `redirect.ExternalURL` and that it is an origin without a path (the routes live at PATH_PREFIX from the root); PATH_PREFIX via `forwardauth.ValidatePathPrefix`; SESSION_ENCRYPTION_KEY parses (`session.ParseKey`); SESSION_SAME_SITE value (`strict` refused with its reason) and `none` with an insecure cookie; a plain http EXTERNAL_URL whose host is not loopback (`redirect.IsSecureURL`; `app.localhost` is not loopback) requires SESSION_INSECURE_COOKIE=true, since browsers drop the Secure cookie there and every login would loop, and an https EXTERNAL_URL refuses it (Secure cookies work there); the ranges and minimums in the table (ports 1..`forwardauth.MaximumPort`, SHUTDOWN_DELAY_SECONDS 0..10); PORT != METRICS_PORT; PROVIDER value and the values it requires; OIDC_CLAIM_MAPPER value; at least one GITHUB_ALLOWED_TEAMS entry; KEYCLOAK_ENABLED requires PROVIDER=oidc, KEYCLOAK_URL, KEYCLOAK_REALM, a valid grant type and its credentials, and a KEYCLOAK_REQUIRED_* list without it is refused (nothing would enforce it); JWT_LIFETIME_SECONDS 1..86400; JWT_PRIVATE_KEY when JWT is enabled; JWT_HEADER via `forwardauth.ValidateJWTHeader`; with API_KEYS_ENABLED at least one API_KEYS entry, every entry has ":" and a name, and the parsed keys pass `apikey.New` (secret length, duplicate names or secrets; no message contains a secret); every API_KEY_PERMISSIONS entry names a key from API_KEYS, appears once, has at least one permission and every permission parses. What only the components can judge (team format, GITHUB_SCOPES, URLs, the PEM key, the Redis ping, the issuer's discovery) fails their constructors right after, still before anything is served.

### 6.3 Routes (`{prefix}` = PATH_PREFIX)

| Route | Chain |
|---|---|
| `GET {prefix}/ui` | apikey (when API_KEYS_ENABLED) -> Guard.RequireUI -> forward handler (F12) |
| `GET {prefix}/api` | apikey (when API_KEYS_ENABLED) -> Guard.RequireAPI -> forward handler (F13) |
| (both checks) | forwardauth does not enforce permissions; the injected JWT carries the identity's `permissions` claim and backends enforce them (`jwt.Verifier` + `ginadapter.RequireMethodPermission` / `authorization.HasPermission`). With JWT enabled an inactive identity is answered 403 (`Sign` refuses it). With API_KEYS_ENABLED, an `Authorization: Bearer` value that is no configured key is 401 `invalid_api_key` on both checks, even with a valid session cookie |
| `GET {prefix}/jwks` | `Signer.JWKSHandler()` (JWT enabled) |
| `GET {prefix}/me` | Guard.RequireAPI -> `auth.IdentityHandler()` (IDENTITY_ENDPOINT_ENABLED; sessions only, no API keys) |
| `GET {prefix}/health` | 200 `{"status":"ok"}` (liveness) [LAY-004] |
| `GET {prefix}/ready` | 200 `{"status":"ok"}`, or 503 `{"code":"unavailable","message":"not ready"}` while shutting down or when the Redis `PING` (2 s) fails; a failed check is recorded on the wide event (`readiness check: <cause>`), a 503 during shutdown is no failure (`we.Success()` with `ready.shutting_down=true`) |
| provider routes | `{prefix}/oidc/<OIDC_NAME>/{login,callback,logout,frontchannel-logout}` or `{prefix}/github/{login,callback,logout,refresh-teams}` via `ginadapter.RegisterRoutes` |
| any other route | 404 `{"code":"not_found","message":"not found"}`, recorded as the failure `no route` (always kept by the sampler); a known route with a trailing "/" is one of them (gin's `RedirectTrailingSlash` is off, so no 301 bypasses event, metric and absolute redirects) |
| `GET /metrics` on METRICS_PORT | `promhttp.HandlerFor(registry, ...)` [MET-001]; the only route of that listener (`/` is 404, `POST /metrics` 405) |

Traefik wiring (README and the compose test use this; the auth router must not carry the forwardAuth middleware, and its longer rule wins by Traefik's default priority):
```yaml
- traefik.http.routers.app.rule=Host(`app.example.com`)
- traefik.http.routers.app.middlewares=forwardauth-ui
- traefik.http.middlewares.forwardauth-ui.forwardauth.address=http://forwardauth:8080/auth/ui
- traefik.http.middlewares.forwardauth-ui.forwardauth.authResponseHeaders=Authorization,X-API-Key
- traefik.http.middlewares.forwardauth-ui.forwardauth.trustForwardHeader=false
- traefik.http.middlewares.forwardauth-ui.forwardauth.maxResponseBodySize=65536
- traefik.http.routers.app-auth.rule=Host(`app.example.com`) && PathPrefix(`/auth`) && !Path(`/auth/ui`) && !Path(`/auth/api`) && !Path(`/auth/health`) && !Path(`/auth/ready`)
- traefik.http.routers.app-auth.service=forwardauth
```
Plus `aliasHeadersStrategy: delete` on the entrypoints. The checks and the probes are never routed publicly: a same-origin script could read the bearer JWT from a check answer, and every anonymous `/ready` costs a Redis `PING`. Traefik calls the checks on the internal address; Kubernetes probes reach the pod directly. Traefik v3 matchers take one value each, hence one `!Path` per route. Why (verified on Traefik v3.7.16, `docs/infrastructure-notes.md` 5.6): `trustForwardHeader: false` keeps client-sent `X-Forwarded-*` from steering the return path; `authResponseHeaders: [Authorization, X-API-Key]` deletes the client's `Authorization` and `X-API-Key` before the upstream sees them, also when forwardauth sends none (JWT disabled, never a key), so a raw API key stops at forwardauth; `aliasHeadersStrategy: delete` stops `X_Auth_User`-style aliases of a header forwardAuth sets. Redirects of the binary are always absolute (a relative `Location` would reach the browser as `http://forwardauth:8080/...`). One forward-auth instance serves one external origin (return paths are relative, decision 8).

### 6.4 Server details (`internal/forwardauth`)

```go
type ServerOptions struct {
	Version           string
	Port, MetricsPort int                             // 0 picks a free port (tests)
	PathPrefix        string                          // required; see ValidatePathPrefix
	Routes            []auth.Route                    // provider routes, absolute paths
	Guard             *session.Guard                  // required
	APIKeys           *apikey.Authenticator           // optional; runs before the Guard on the checks
	Signer            *jwt.Signer                     // optional; enables the JWT header and {prefix}/jwks
	JWTHeader         string                          // default "Authorization"; value "Bearer <jwt>"; see ValidateJWTHeader
	IdentityEndpoint  bool                            // mounts {prefix}/me
	Emitter           wideevent.Emitter               // required
	Logger            *slog.Logger                    // required: net/http's own error lines of both listeners, as JSON (ErrorLog) [LOG-013]
	SampleRate        int                             // required, >= 1
	MetricsRegistry   *prometheus.Registry            // required; runtime collectors registered by main [MET-002]
	ReadinessCheck    func(ctx context.Context) error // optional (Redis ping)
	ShutdownDelay     time.Duration                   // 0..MaximumShutdownDelay (10 s)
}
func NewServer(options *ServerOptions) (*Server, error)
// Run serves until ctx ends, then: readiness 503, wait ShutdownDelay, Shutdown with 20 s, metrics server too [LAY-003].
// A listener that fails to start stops the other one and its error is returned.
func (s *Server) Run(ctx context.Context) error
type ObserverOptions struct {
	OutcomeCounter *prometheusadapter.OutcomeCounter // required
}
// NewObserver returns the auth.Observer main passes to provider, Guard and apikey: ginadapter.Observe plus the counter.
func NewObserver(options *ObserverOptions) (auth.Observer, error)
// ValidatePathPrefix reports why prefix cannot hold the routes: it must pass redirect.IsPathPrefix, so it has no
// gin parameter, wildcard or "." segment. NewServer and main's validateConfiguration both use it.
func ValidatePathPrefix(prefix string) error
// ValidateJWTHeader reports why name cannot carry the check answer's JWT: not an RFC 9110 header name, or one the
// answer or net/http sets itself (Cache-Control, Set-Cookie, Connection, Content-Length, Transfer-Encoding).
// NewServer and main's validateConfiguration both use it.
func ValidateJWTHeader(name string) error
// MaximumShutdownDelay keeps ShutdownDelay plus the 20 s drain within the 30 s default termination grace period.
const MaximumShutdownDelay = 10 * time.Second
// MaximumPort is the highest TCP port (Port, MetricsPort, main's PORT and METRICS_PORT checks).
const MaximumPort = 65535

// Dependencies records the binary's outbound calls in forwardauth_dependency_request_duration_seconds
// {dependency,operation,outcome} and, during a request, summed per dependency on its wide event [LOG-004, LOG-006, MET-006].
type Dependencies struct{ /* unexported */ }
type DependenciesOptions struct {
	Registerer prometheus.Registerer // required
}
func NewDependencies(options *DependenciesOptions) (*Dependencies, error)
// HTTPClient returns a client with the 10 s default timeout recording its calls as dependency name (operation: the
// method; a transport error or a 5xx is a failure). main passes it to oidc ("oidc"), keycloak ("keycloak") and github ("github").
func (d *Dependencies) HTTPClient(name string) *http.Client
// Backend wraps the Redis backend; its operations are recorded as dependency "redis" (operation: put, get, pop,
// compare_and_swap, revoke; a lost swap is a success). ErrRevoked is an answer,
// not a failure.
func (d *Dependencies) Backend(backend session.Backend) session.Backend
// RedisPing wraps the readiness check's Redis PING; each call is recorded as dependency "redis" (operation: ping).
func (d *Dependencies) RedisPing(ping func(ctx context.Context) error) func(ctx context.Context) error
```
- There is no `DevMode` option: gin's mode is process-wide, so main calls `gin.SetMode` (D29).
- Both listeners (public and metrics) are `http.Server`s with ReadHeaderTimeout 10 s, ReadTimeout 30 s, WriteTimeout 60 s, IdleTimeout 120 s [LAY-006], MaxHeaderBytes 64 KiB (431 above; Traefik forwards the client's headers, large cookies fit) and write their error lines through `Logger` (`slog.NewLogLogger`, level error).
- Engine order (gin's `RedirectTrailingSlash` off, see 6.3): `wideevent.Middleware` (outermost, records the final status), HTTP metrics, `recordDependencies` (collects the request's outbound calls and writes per dependency namespace `<namespace>.calls`, `.failures`, `.duration_ms` and, when set, `.backend`, `.status`, `.error`: `cache.*` for Redis, `http.<name>.*` for the HTTP clients, so the GitHub team page loop adds no field per call), panic recovery (500 JSON `internal`, `we.Failure` plus `panic.stack` on the wide event), routes; `NoRoute` answers 404 JSON `not_found` and records the failure `no route`. Calls outside a request (discovery at boot) reach only the histogram; the recorded error is the transport's reduced by `dependency.TransportFailure` (shared with `dependency.Error`) to cancellation, a dial error, "timeout" or the type of the innermost error (e.g. `transport failure (textproto.ProtocolError)`), so it names neither the URL nor anything the server sent; the caller gets the original error.
- `wideevent.Middleware` with: emitter (JSON stdout, or dev emitter when DEV_MODE; either receives a copy of the event with only the latest value of each field, so the dev emitter cannot print the raw query the pre-enricher replaced), `WithSkipPaths(health)` (`/ready` records events: a failed check is kept by `AlwaysOnError`, successful probes are sampled like any request), sampler `CompositeSampler(AlwaysOnError(), AlwaysOnStatus(401, 403), keepDegraded, Rate(SampleRate))`, pre-enricher that calls `ginadapter.RedactQuery` (overwrites `request.query` with the parameter names and every value replaced by `redacted`, cut to 512 bytes; callbacks carry `code` and `state`) [LOG-009], records `service.version`, `forward.method`, `forward.host`, `forward.path` (X-Forwarded-Method/Host and the path part of X-Forwarded-Uri, never its query). Every client-controlled field (those, `request.query`, and the middleware's `request.method`, `request.path`, `request.host`, `request.user_agent`, `request.id`, overwritten) is cut to 512 bytes at a character boundary: 401s and unmatched paths are always kept.
- The JWT step records `forward.jwt_issued=true`; the forward handler sets `Cache-Control: no-store`, calls `we.Success()` and answers 200. `{prefix}/jwks` and `{prefix}/me` also record `we.Success()`.
- HTTP metrics middleware (MET-003, namespace `forwardauth`, subsystem `http`): `forwardauth_http_requests_total{route,method,status}`, `forwardauth_http_request_duration_seconds{route,method}`, `forwardauth_http_requests_in_flight`; route = `ginContext.FullPath()` or `unmatched`; method bounded to the standard set or `other`; health/ready excluded. Plus `forwardauth_auth_outcomes_total{provider,action,result}`, `forwardauth_dependency_request_duration_seconds{dependency,operation,outcome}` (`Dependencies`) and Go, process and build-info collectors. No Redis pool collector (one small pool; add `redis.PoolStats` if it ever matters).
- No tracing in v1: a check is one hop from Traefik with at most a Redis and a provider call, which the wide event sums per dependency, and there is no trace backend or context to join; add otelhttp/redisotel in `Dependencies` when a deployment traces.

### 6.5 Docker and release (contract only; specifics in `docs/infrastructure-notes.md`)
- `docker/forwardauth.Dockerfile`: multi-stage, builder `golang:1.26` on `$BUILDPLATFORM` cross-compiling (no QEMU), `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" ./cmd/forwardauth`, runtime `gcr.io/distroless/static-debian13:nonroot` (about 22 MB), `USER nonroot:nonroot`, ports 8080 and 9090, entrypoint the binary [DEP-002, DEP-003, DEP-004, DEP-005, DEP-006].
- Image `ghcr.io/govengers/forwardauth` (the binary's name; "auth" alone says nothing, and the old images were per provider), `linux/amd64` and `linux/arm64`, published by `.github/workflows/release.yml`: `:main` on every push to `main`, `:<major>.<minor>.<patch>`, `:<major>.<minor>`, `:<major>` and `:latest` on a `v*` tag, plus `:sha-<commit>`. The GHCR package must be made public once by hand after the first push (no API for it). DEP-008 (`GOMEMLIMIT`) belongs to the deployment manifests, documented in README.

---

## 7. Decision log

### 7.1 Open questions of A-6

| # | Decision | Reason |
|---|---|---|
| 1 | Handled in config v2: package at repo root, `github.com/govengers/config/v2`, imported as `config`. | CFG-001 examples; no stutter. |
| 2 | Handled in config v2 (process-wide registry, declared DES-003 exception there). auth's binary binds everything with `.Into` and never calls `config.Get()`. | CFG-001, CFG-006. |
| 3 | Handled in config v2. | LIB-003 is config's concern. |
| 4 | Handled in config v2 (no default = required, `NotEmpty` validates defaults). Conditional requirements in forwardauth are validated in main after loading. | CFG-003, CFG-004. |
| 5 | Handled in config v2 (no duration/base64 types): forwardauth uses `*_SECONDS` ints and `session.ParseKey`; string arrays use `StringArray`. | TCH-007, no new dependency. |
| 6 | One module, one package per provider plus `session/redisbackend`, `oidc/keycloak`, `ginadapter`, `prometheusadapter`; gocloak replaced, not isolated (D6). | LIB-007; Go only compiles imported packages. |
| 7 | `auth.Identity` in the root package, `auth.WithIdentity`/`auth.IdentityFrom`; `basicauth.User` becomes `password.User` (storage record only); `UserTransformer` becomes an application middleware after the Guard (D5). | AUTH-004, AUTH-006; one identity type. |
| 8 | Server-side sessions for every provider (`session.Store` + `Backend`), cookie holds a random ID only; cookie-only mode dropped. | Revocation, multi-replica PKCE/state (A-5.3.8, A-5.3.10). |
| 9 | No global middleware; `Guard.RequireAPI`/`RequireUI` mounted per route group; `PathRules` dropped (route groups are the rules). | LIB-004, AUTH-002, FUN-001 (two middlewares, no mode flag). |
| 10 | Hooks: `auth.Hook` (OnLogin), `auth.LogoutHook` (OnLogout), `apikey.Resolver` returns `*auth.Identity`; `ClaimMapper` stays a pure function returning `oidc.Profile`. | FUN-005; decision 15. |
| 11 | `apikey` package, usable with any provider and in front of the Guard. | Decision 14. |
| 12 | PKCE S256 + nonce for OIDC, PKCE for GitHub, state bound to the server-side session; `return_to` for both redirect providers; password is a JSON API and needs none. | OAuth 2.0 Security BCP; decision 8. |
| 13 | jwx v3 only, one `jwt` package; the binary is `cmd/forwardauth` in this module (D2). | TCH-007, LIB-007. |
| 14 | Four sentinels + `*auth.Error{Kind, Code, Reason, Err}` + one `{code, message}` shape. | ERR-005, API-001, API-002. |
| 15 | No logger option: `auth.Observer` callback; `ginadapter.Observe` records on the existing wide event. | LIB-003, LOG-002, decision 3. |
| 16 | No shims; README migration sections per old library and the tables in section 10. v1.0.0 release notes list every break. | LIB-009, decision 1. |
| 17 | `go 1.26.0`. | TCH-001 (1.26 and 1.27 supported); DES-007 `new(expr)`; config v2 is on 1.26. |

### 7.2 Design decisions (refinements and deviations, numbered for reference)

| ID | Decision | Reason |
|---|---|---|
| D1 | Every provider stores the same identity in the same session, so one Guard authenticates all providers. No per-provider middleware. | Kills the double-chain bug (A-5.3.1) and the intranet's OIDC-to-basicauth session bridge. |
| D2 | `cmd/forwardauth` lives in the root module. Binary-only requirement: config v2 (+ go-pretty, godotenv, pflag); gin, wideevent, client_golang, go-redis are needed by adapter subpackages anyway. Consumers compile none of it (graph pruning); go.sum carries go.mod hashes and MVS may raise their config/v2 version. | A nested module needs a `replace` or lockstep tags [TCH-007] and the reusable CI only tests the root module. |
| D3 | One `ginadapter` package (authentication and authorization), not `authorization/ginadapter` + a second `ginadapter`. **Deviation from decision 4's path.** | Two packages named `ginadapter` imported by the same app force an alias on every import; the merged one adds no dependency (authorization is stdlib + uuid). |
| D4 | Cookie value is 32 random bytes; backend key = SHA-256 of it; no signing key. One `EncryptionKey` (AES-256-GCM, AAD = sessionID + key). gorilla/sessions and securecookie dropped. | A Redis dump no longer reveals live cookies; signing a 256-bit random ID adds nothing. |
| D5 | **Deviation from decision 15:** no per-request hook. `UserTransformer`'s job (load the app user, refuse inactive users, put the app's own user into the context) is an app middleware after the Guard; README shows the pattern. | A hook returning `*Identity` cannot add the app's user object to the context, so apps would load users twice. |
| D6 | gocloak replaced by `oidc/keycloak` (net/http + oauth2, ~200 lines) whose `Enrich` is an `auth.Hook`; default grant flips to client credentials; `AuthenticationRealm` added. | Drops gocloak, resty, golang-jwt; the password grant broke the FSUS intranet on 09.10.2026 (DeepThought). |
| D7 | Freshness via `session.Refresher` (password: user still exists; GitHub: teams), every RefreshInterval (1 min, the old GitHub cache TTL). OIDC has none (as before). | Keeps "removed from team / deleted user loses access within a minute" without per-request upstream calls. |
| D8 | Absolute session expiry (authenticatedAt + MaximumAge), never extended by refreshes. | A stolen cookie cannot be kept alive. |
| D9 | `TOTP.Required` enrolls during login (pending enrollment session) instead of a 403 `tfa_setup_required` on every route; no MFA flag on Identity. | No full session before MFA exists; no app route configuration needed. |
| D10 | Password `Messages` (i18n strings) dropped; clients map stable codes. Default MinimumLength 12, composition rules opt-in, max 128 bytes. | API-002 fixed messages; NIST SP 800-63B prefers length over composition. |
| D11 | `Storage.UpdateUser` and `DeleteUser` replaced by `UpdatePasswordHash` (compare-and-swap); storage owns uniqueness (`ErrUserExists`). | DES-004 (only what the library calls); closes the re-read window and the registration pre-check race (A-5.3.10). |
| D12 | GitHub `Identity.Teams` filtered to allowed ∪ admin ∪ relevant; JWT `sub` = numeric GitHub ID, login in `preferred_username`. | Bounded headers (Traefik/Nginx limits), data minimisation, stable subject. |
| D13 | JWT: RS512 only (`Algorithm` option dropped), kid = RFC 7638 thumbprint, private key required (no generated key), default lifetime 5 min, no `jku` header, no verifier cache, no goroutine. | A-5.3.3..5; LIB-004. |
| D14 | Logout of redirect providers is `GET` (a link); password logout stays `POST`. A request the browser marks `Sec-Fetch-Site: cross-site` is refused with 403 `forbidden` (no session read or change, outcome denied, no Identity) on password, oidc RP-initiated and github logout and on github `refresh-teams` (`internal/fetchmetadata`); requests without the header (older browsers, non-browser clients) still work. OIDC front-channel logout stays open: the IdP calls it cross-site from an iframe. github's Origin check (F-06) is replaced by the Fetch Metadata check. Login routes (`GET {prefix}/login` of oidc and github) are not refused cross-site; `oauthlogin.Begin` keeps a session holding a live identity and stores the login state in it, so a cross-site link to a login route ends no session; the callback rotates it (`Store.Start`) only when the IdP completes the login. | One navigation-friendly logout, without logout CSRF in current browsers; a logout link from another site (a portal on another registrable domain) gets 403 and must move onto the app's host. A login start that revoked the current session would turn any cross-site login link into a logout; refusing it instead would dead-end an email link whose session expired. |
| D15 | Redirect URIs are derived (`ExternalURL + PathPrefix + "/callback"`), end-session URL discovered, Google allowed via `AllowedEmailDomains` (email_verified + domain). | Fewer knobs that can disagree; old Google mode admitted any Google account. |
| D16 | GitHub/OIDC URLs: https required except loopback hosts. | Keeps the SSRF/credential hardening (F-03) while e2e runs plain HTTP on 127.0.0.1. |
| D17 | Forward-auth checks require explicit Traefik routing of `{prefix}` to the service (no github-style X-Forwarded-Uri dispatch inside the check endpoint). | Traefik forwards the original request on any 2xx, so JSON auth endpoints never worked through the check endpoint. |
| D18 | Optional `ErrorURL` on redirect providers: callback failures (refusals and `code=internal`) redirect with `?code=`; default JSON. | Real consumer pattern (bathroom-planner `/login?oidc=<reason>`). |
| D19 | No retries, no rate limiting (documented, as basicauth; an edge rate limit on `{prefix}/login` and `{prefix}/totp/verify` is recommended). TOTP codes are single use: `Storage.ConsumeTOTPStep` keeps the last used time step per user (review round 1 reversed the original "replay accepted"). `MaximumAttempts` is a lockout of consecutive wrong codes across logins, reset only by a verified second factor, `SetTOTP`, `ClearTOTP` or the application calling `ResetTOTPAttempts`; a password login no longer resets it. | RES-002; scope. A replayed code and a per-login attempt budget let anyone holding the password brute-force the second factor; the trade-off is that the password holder can now lock it (default 5; NIST 800-63B allows up to 100; raising the default is open). |
| D20 | Not built (YAGNI): session key rotation list, JWT signing key rotation list, idle timeout, multi-host return URLs, OIDC refresh tokens, `auth.Chain` for hooks (an app closure), net/http `authorization` middleware (gin `Require` only), standalone `IsMultiFactor`. | No consumer needs them today. |
| D21 | Generic permissions (MaPa, 29.10.2026): `auth.Permission{Resource, Access}` with Access `read`/`write` (write includes read) and resource `*` for all; one text form `<resource>:<access>` for Go, JSON, JWT claim and config. Identities carry them (`Identity.Permissions`); API keys get them from `Key.Permissions` or the Resolver; checks via `authorization.HasPermission` and `ginadapter.RequireMethodPermission`. No permission means no access. Forward auth only transports them (JWT); API keys of the binary carry permissions but no roles. | build-api's read_only/read_write keys generalised; strict lower-case grammar so a typo fails at boot, not at request time. Not built: prefix wildcards (`builds/*`), actions beyond read/write, a deny form, roles for the binary's API keys. |

Decisions taken during implementation (29.10.2026, settled by the lead):

| ID | Decision | Reason |
|---|---|---|
| D22 | Sessions: values sealed with a per-session key (HKDF-SHA256 from `EncryptionKey`); `SaveIdentity` starts a lifetime only on a `Store.Start` handle, at the time Start issued it; `Session.Put` refuses ttl <= 0; `ReturnPathHeader`, when set, is the only return path source; `LoginURL` paths must pass `SafeReturnPath` and refuse a fragment. Guard: a Refresher's temporary failure (or nil identity) keeps the identity and is a degraded success (`Result success`, `Err` set), a backend failure is 500; the refresh is saved by `Backend.CompareAndSwap`, so it loses to a save or logout made while it ran. The Guard claims a due refresh by that swap (moved refreshedAt) before it calls the Refresher: one call per interval per session, a request losing the claim continues with the identity it read. Revocation markers exist only for sessions that held values and never outlive them; a full memory backend evicts them like sessions (expired entries first, then the entry expiring soonest), an evicted marker no longer refuses a Put, but nothing regains an identity: a later `SaveIdentity` swaps against the envelope it read (last writer wins, at most 3 tries, then an error), and the one unconditional write is the first save of a Start handle (once per Start, copies included). Residual: a Start handle that never saved and is kept past its response could still make that save after End plus eviction; every provider saves in the request that started the session. `Store.End` revokes with its own 10 s timeout. | The 2^32 random-nonce limit of GCM applies per key; a refresh racing the expiry, a retained Start handle or a planted cookie must not get a fresh lifetime (D8); a temporary GitHub outage must not log users out or turn requests into errors; a refresh must not write an old identity over a change; markers for unknown IDs would let a flood of made-up cookies evict real sessions (memory) or grow Redis without bound; concurrent requests must not each call GitHub; with markers that are never evicted anyone could block every new session for 10 min with chained login starts (the memory backend is for one replica at non-production scale, Redis evicts by its own policy). |
| D23 | LIB-010 through one helper `internal/dependency.Error` (message only, chain dropped, `context.Canceled`/`DeadlineExceeded` kept detectable), also for `apikey` Resolver errors and every outbound HTTP call, whose `*url.Error` it reduces to method, origin and a classified cause (`TransportFailure`); other standard library errors wrap with `%w`. A token endpoint's error answer goes through one helper too, `internal/tokenendpoint.Error` (status and a well-formed OAuth error code, never its text), kept apart from `internal/dependency` so packages without OAuth do not link oauth2 (LIB-007). Providers answer and report through one `failure.Reporter`. | One audited place instead of several copies; callers must still see a cancelled request; `error_description`, `error_uri` and bodies are free text that may carry personal data, and so are a URL's path and query and a malformed answer's bytes in a transport error or a JWKS parse error (LOG-009). |
| D24 | Redirect targets: `ErrorURL` and `PostLogoutURL` of oidc and github accept a safe path or an absolute http(s) URL without fragment, a path becomes absolute with `ExternalURL`; `ErrorURL` also receives 500s (`code=internal`). `PathPrefix` of password, oidc and github: segments of `A-Z a-z 0-9 . _ ~ -`, no trailing "/", no "." or ".." segment. URL checks require a host name. | A forward-auth redirect must be absolute to reach the browser; a fragment would swallow the appended `?code=`; prefixes must be neither mux wildcards nor removed by path cleaning. |
| D25 | Code exchange (oidc and github alike, `tokenendpoint.Refused`): an error answer below 500 is 401 `login_failed`; a 5xx answer or an unreachable token endpoint is 500. Keycloak's admin token request classifies nothing: every failure is 500. The oidc auth style is fixed from discovery; discovered endpoints must be https or loopback http like the issuer (D16); an ID token without `sub` is refused; `"jwt"` is a reserved provider name. GitHub `Scopes` must include one that lists teams. | A user cannot fix an outage, monitoring must see it; oauth2's auto-detected style resends failed exchanges (RES-002); go-oidc checks only the issuer, so an http token endpoint would receive the client secret in clear; `jwt` is the verifier's Outcome.Provider; a scope that cannot list teams fails every login. |
| D26 | GitHub: the token goes only to `APIURL`'s scheme and host (own RoundTripper); AdminTeams members still need an allowed team; `Identity.Teams` sorted and unique; the token is stored before the identity. | oauth2's Transport sends the token on cross-host redirects (archives, `uploads.github.com`); the old library's admin rule kept; stable JWTs. |
| D27 | Password: TOTP routes exist only with `TOTP.Enabled`, and an enrolled user's login fails (500) while it is off; registration with `TOTP.Required` answers 202 `totp_setup`; a stored hash that cannot be verified is 401 `invalid_credentials` and costs the dummy verification; only login rehashes, legacy hashes and Argon2id hashes whose parameters differ from `HashParameters`; `MinimumLength` counts runes; `Digits` 6 or 8; `MaximumAttempts` has no "unlimited"; backup codes only with `"backupCode": true`; `Period` <= 3600, `Skew` <= 10, `BackupCodeCount` <= 20, backup codes <= 128 bytes and >= 1,000,000 distinct codes; Storage matches identifiers ignoring case. | No dead routes and no silent downgrade to one factor; enrollment before any full session; a broken stored hash answers like a wrong password, in status and time; outdated cost parameters must not stay forever; a wrong TOTP code must not cost an Argon2id run; bounded step arithmetic and Argon2id work per attempt; `Alice` and `alice` are one account. |
| D28 | JWT: claim names owned by identity fields are never copied from `Identity.Claims`; `exp` required; `iat` checked with the skew; `RefreshInterval` >= 1 min; a failed periodic refresh keeps the keys (degraded); `Sign` refuses an inactive identity; the verifier uses only RSA keys with an RSA signature `alg` (RS*, PS*), a kid and use `sig` (or none) from the JWKS, ignores entries it cannot parse, reads at most 1 MiB, refetches outside its mutex and detached from the request (10 s; known kids keep verifying meanwhile, an unknown kid waits for it at most until its own request ends), keeps token material out of Reasons, credentials of the JWKS URL and the JWKS answer's bytes out of errors (a parse failure is fixed text, a read failure its classified transport cause), and challenges 401s with `WWW-Authenticate: Bearer`. | An IdP `roles` claim must not become application roles; a token without expiry must not verify forever; a Sign/Verify round trip must not turn an inactive identity active; a published `oct` key would let anyone mint HS256 tokens, an RSA key with another alg verifies nothing; one exotic key type must not fail the whole key set; a key without kid can verify no token, so a set of them must fail at boot, not on every request; a cancelled request must not use up the refetch, a slow JWKS must not stall every verification. |
| D29 | Forward-auth binary: `DevMode` removed from `ServerOptions` (main sets gin's mode); one JSON shape also for 404 (`not_found`), readiness 503 (`unavailable`) and panics (500); check responses `no-store`; extra boot validation (session key parsed, PORT != METRICS_PORT, KEYCLOAK_ENABLED needs PROVIDER=oidc, API_KEYS entries need ":" and are never echoed); runtime image `static-debian13`; image also tagged `:main`. | gin's mode is process-global; API-001; a misconfiguration fails the boot, not the first request; `golang:1.26` is Debian 13. |
| D30 | apikey: duplicate names or secrets and secrets with surrounding whitespace are refused; `HeaderName` must not be `Authorization`; Resolver errors are 500 unless they match `ErrUnauthenticated`; the `Bearer` scheme is matched case-insensitively, as by the jwt verifier. | Ambiguous keys and a resolver deciding the status by accident are configuration bugs; RFC 9110 makes the scheme case-insensitive, and a `bearer` key falling through to the session identity was a bypass of the key check. |
| D31 | authorization: `Not` refuses a missing (401) or inactive (403) identity before inverting and inverts only a refusal `auth.ResponseFor` answers 403 (Kind of the outermost `*auth.Error`; a forbidden cause never counts); wiring mistakes (nil check, `All()`/`Any()` without checks, invalid `HasPermission`) are plain errors (500), not refusals; `Any` returns a failure in preference to a refusal; one shared inactive Reason `"inactive"`. | `Not(HasRole(x))` must never admit anonymous or deactivated users, and `Not` must never invert a check that decided nothing, or an unauthenticated refusal wrapping a forbidden cause, into a pass. |
| D32 | Forward-auth binary after review round 1: `SESSION_SAME_SITE=strict` is refused; `SHUTDOWN_DELAY_SECONDS` <= 10; the boot pings Redis (5 s); the Redis client never retries and honours deadlines; `JWT_HEADER` must be a header name the answer does not set itself; `validateConfiguration` also runs `redirect.IsPathPrefix` and `apikey.New`; outbound calls are instrumented (`Dependencies`); net/http's error lines go through slog; the metrics listener serves only `GET /metrics`; unknown routes are recorded failures; the Traefik `/auth` router excludes the checks and probes. Not built: requiring `X-Forwarded-Method` on the checks (relies on Traefik stripping it and breaks direct calls). | Strict breaks every login (the cookie is withheld on the redirect back); delay plus drain must fit the 30 s grace period; a missing Redis must fail the boot, not the first login [RES-007]; a retried Pop lost its value [RES-004]; every problem at boot at once [CFG-003]; LOG-004, MET-006; a public check answer hands its bearer JWT to same-origin scripts. |
| D33 | After review round 2: `password.Storage.SetTOTP` returns `(bool, error)` and enables only while TOTP is off (atomic), `false` is 409 `totp_already_enabled`; TOTP enable reads the setup secret with `Get` (was `Pop`); `OnLogin` must keep the password `UserID`; every provider's logout reads the session and runs OnLogout on a detached context, a failed read degrades the outcome; the oidc callback stores the ID token before the identity; a refusal (Guard refresh or refresh-teams) whose session cannot be ended is 500, and the Guard releases its refresh claim, so the next request refreshes again; refresh-teams saves through the new `Session.SwapIdentity` (409 after a second conflict); `session.ErrSessionRevoked` renamed `ErrRevoked`; `failure.NewReporter` replaces the struct literal; `dependency.Error` reduces every HTTP call's `*url.Error`; DES-008 waived for password's identifier. Binary: `API_KEYS_ENABLED` (default false) gates API keys; `EXTERNAL_URL` must be an origin; gin's `RedirectTrailingSlash` off; both listeners get the LAY-006 timeouts; recorded transport errors are reduced to their type; `just lint` fails on a tracked executable. | Two concurrent enrollments replaced a just-enabled second factor; one typo forced a new QR code; a replaced UserID broke Refresh and the TOTP routes at the first refresh instead of the login; a disconnecting client skipped OnLogout; a failed ID token write left an authenticated session behind; a usable session must not be reported as denied; refresh-teams overwrote a deactivation saved while it called GitHub, and "the concurrent save wins" would keep a removed admin role for another interval; NAM-003, DES-001/006; a URL's query and a transport's text may carry personal data; one login field is the go-basicauth wire format. A feature switched by a non-empty list is CFG-004; a path in EXTERNAL_URL put redirect URIs and return URLs under a path the binary does not serve; gin's 301 bypassed the wide event, the metric and absolute redirects and printed callback query values in debug mode; a slow client could hold the metrics listener; a malformed answer's bytes may be personal data (LOG-009); a 31 MB binary got committed. |
| D34 | After review round 3: a later `SaveIdentity` writes by compare-and-swap against the envelope it read (at most 3 tries) and a Start handle has one first save, shared by its copies; Redis `CompareAndSwap` keeps a `#swapped:<token>` receipt for go-redis retries; a Guard refusal whose session cannot be ended releases the refresh claim; refresh-teams refuses cross-site (403) and answers 409 when another request changed the membership or the user while it called GitHub; TOTP disable drops a pending setup, an unreadable setup or backup code hash is 500; JWKS keys need a kid, JWKS parse and read errors carry fixed text or the classified cause, an unknown-kid wait ends with its request; apikey `Resolver` must set Active and keep the key out of its error text; an oidc ID token that does not verify has a fixed Reason; the go-oidc filter drops the Content-Type with the body; a failed logout's outcome keeps the session read failure. Binary: a plain http non-loopback `EXTERNAL_URL` needs `SESSION_INSECURE_COOKIE=true`; `/ready` records wide events; `X-API-Key` belongs in `authResponseHeaders`; no tracing in v1. | Eviction of a revocation marker let a retained handle or a save racing the logout resurrect a session; a retry after a lost reply answered a successful swap as lost; a refused identity passed for another interval when End failed; a delayed refresh restored a removed admin role, and a cross-site post could end a `SameSite=None` session; disable left an old setup that enable re-armed, and corruption read as "missing" or "no match"; a key set without kids booted and refused every token; response bytes, go-oidc's messages (token header, JWKS error) and a Content-Type header may carry personal data (LOG-009); a Secure cookie on plain http loops every login; a failed readiness check was recorded nowhere; the raw key reached the protected app. |
| D35 | After review round 4: no component follows a redirect on its own calls (`dependency.WithoutRedirects`: OIDC discovery, JWKS and token exchange, Keycloak token and Admin API, GitHub token exchange, revocation and its own user/team reads, jwt JWKS); a redirected call is a plain error (500), not a refusal; go-oidc's discovery and JWKS bodies are read up to 1 MiB, other answers' not at all; a successful `/ready` is recorded as success; the e2e harness holds both probe listeners before releasing them. | The startup URL checks (D16) saw only the first hop: a 307 to `http` resent the client secret, code and PKCE verifier in clear text; an unbounded read of a streamed or compressed answer could exhaust memory during an IdP outage; LOG-011; two probes could hand out the same port, which the binary refuses. |
| D36 | After the round-5 security audit: the Guard runs a due refresh (Refresher, ending the session, the save) without the request's cancellation, bounded by 30 s; a refresh failing with a non-refusal error for longer than `MaximumUnverifiedAge` (default 1 h) since the identity was last verified ends the session like a refusal (`verifiedAt` in the envelope, falling back to `authenticatedAt`). | A client aborting every due refresh, or a provider answering 403/429 for hours, kept a revoked identity, its teams and its admin role alive until MaximumAge. |
| D37 | The store names a Secure, host-only cookie on path `/` `__Host-` + `CookieName`; an own `__Host-` name needs those attributes and an own `__Secure-` name a Secure cookie, otherwise `NewStore` fails. | `request.Cookie` returns the first cookie of a name, so a sibling subdomain could toss a `Domain=` cookie that shadows the session (fixation into the attacker's session). Browsers accept a `__Host-` cookie only from the host itself over https. Existing sessions end once (the name changes). |
| D38 | `MemoryBackend` also bounds the bytes it holds (`MaximumBytes`, default 64 MiB; expired entries first, then soonest expiring); the login state is JSON without HTML escaping and `SafeReturnPath` refuses invalid UTF-8. | Every anonymous login start stores its state: `json.Marshal` wrote each `<`, `>`, `&` of a 2048-byte return path as six bytes (12 KB a start, 1.2 GB at the entry cap), each invalid UTF-8 byte as `\ufffd`; an entry cap alone does not bound memory. |
| D39 | The public listener reads at most 64 KiB of request line and headers; the wide event's client-controlled fields are cut to 512 bytes. | net/http's 1 MiB default let a client push up to 1 MiB of header bytes into every 401 or unmatched-path event, which the sampler always keeps. |
| D40 | After the agent-docs pass (30.10.2026): the binary's query redaction moved into the library as `ginadapter.RedactQuery`, which the binary's pre-enricher calls. | Library consumers on gin mounted the wide-event middleware without redaction, so callback `code` and `state` reached their logs. |
| D41 | After the agent-docs pass (30.10.2026): `session.Store.SameSite()`; `oidc.New` and `github.New` refuse a store whose cookie is SameSite Strict. Password-only stores may keep Strict. | A Strict cookie is withheld on the redirect back from the IdP or GitHub, so every callback failed with `login_expired` at runtime instead of at startup (the binary already refused `SESSION_SAME_SITE=strict`, D32). |

---

## 8. Test plan and tooling

### 8.1 Unit tests per package (each >= 80 % statements; port the old suites where named)

| Package | Must cover |
|---|---|
| `auth` | context round trip and nil cases; `Real`, `Clone` (deep, nil-safe, no aliasing); `ResponseFor` table (each kind, custom code, wrapped twice, unknown -> 500, message never contains Reason or cause); `WriteError` headers; `NewIdentityResponse` excludes Claims/Attributes/Data, omits Nil userId, nests impersonator, `roles` never null; `IdentityHandler` 200/401; `RegisterRoutes`; `Error.Error`/`Unwrap` with `errors.Is`; `ParsePermission` table (valid forms, charset, case, length 64/65, missing or second separator, unknown access) with `String` round trip; `Grants` table (read/write implication, wildcard, requiring `*`, fail closed on empty/invalid resource or access and on an invalid permission); `Permits` table (nil identity, no permissions, any-of match, invalid entries skipped, Active and Impersonator ignored); JSON text form round trip and invalid permission errors on marshal and unmarshal; `AccessForMethod` table; `Clone` and `NewIdentityResponse` copy Permissions. Examples. (Implemented, 100 %.) |
| `session` | `ParseKey` table; `NewStore`/`NewGuard`/`NewMemoryBackend` validation, defaults, caller untouched; cookie attributes; `Start` revokes the previous session; `Open` missing/malformed; Put/Get/Pop; backend sees only hashed IDs and ciphertext; AAD (value copied to another key or session is absent); tampered value absent; `SaveIdentity`/`Identity` incl. absolute expiry via clock and authenticatedAt preserved; `End` idempotent; Put after revoke -> ErrRevoked; memory backend through `backendtest.Run` incl. eviction order (revocation markers evicted too, a flood of login starts blocks no session); Guard: pass-through with identity, API 401, UI 302 with return path (request URI, header, unsafe omitted), refresh after interval (clock) with real identity, a due refresh claimed once by concurrent requests (one Refresher call), a request losing the claim skips the call, impersonator refresh, refresher 401/403 end the session, transient error keeps identity and reports a degraded success, backend failure 500, `SaveIdentity` refused on a cookie-opened session without identity, `SwapIdentity` (swaps an equal identity, loses to a save after its read, refusals), a refusal whose session cannot be ended is 500, observer outcomes. |
| `jwt` | signer validation (missing/bad PEM, < 2048 bits, PKCS#1 and PKCS#8, missing issuer); stable kid; Sign/Verify round trip of every Identity field; reserved claims not copied; `permissions` claim round trip in text form, `Sign` error on an invalid permission, `Verify` drops non-string and unparsable entries and keeps the rest; JWKS JSON (public only); identity-owned claim names in `Claims` not copied; verifier: wrong iss, wrong aud, missing and expired exp, nbf (clock), bad signature, alg mismatch, unknown kid refetch + rate limit, refresh interval, failed refresh keeps keys (degraded), wrong claim types without panic, middleware 401 (with `WWW-Authenticate: Bearer`)/500/200, observer; `NewVerifier` fails when JWKS is unreachable, larger than 1 MiB or has no RSA key with an RS*/PS* alg; `oct` keys, RSA keys with another alg and unparsable entries of the JWKS ignored; a known kid verifies while a refetch is in flight; Reasons never quote token material; errors omit the JWKS URL's credentials; a cancelled request still refetches; `Sign` refuses an inactive identity. |
| `password` | port `util_test`, `legacy_password_test`, `validation_test`, `tfa_test`, `security_state_test`, `e2e_test`: Hash/Verify (limits, version, malformed); VerifyBcrypt; policy and identifier tables; login by username/email, disabled kinds, unknown user via dummy hash, wrong password; legacy upgrade CAS incl. concurrent change and degraded failure; content type, 64 KiB, unknown fields; registration off (404 on mux) and on (201, 409, 400s); TOTP challenge, verify, attempts exhaustion ends the pending session, failed attempts outlive the login, TOTP code single use (replay, earlier step, concurrent logins, enable code), backup code only with the flag and single use under `-race`, pending expiry, pending session revoked after success; rehash of outdated Argon2id parameters; every failed check costs one verification; Required enrollment flow; concurrent enrollments enable TOTP once (409 for the loser); enable retried after a wrong code with the same setup; configured Period and Digits; undecodable stored secret (500); OnLogin replacing UserID (500); setup/enable/disable/status, impersonated session refused; logout + OnLogout (also with a disconnected client, and a failed session read degrades the outcome); OnLogin refusal (403, no session) and failure (500); Refresh (deleted user, profile change, other fields kept); MemoryStorage contracts; outcomes per action. |
| `oidc` | port `e2e_test`, `multi_handler_test`, `claim_mappers_test`, `token_claims_test`: validation (names, reserved, URLs, scopes order); discovery failure; login redirect has state, nonce, S256 challenge; return_to table incl. `//evil`, `/\evil`, `https://evil`, control chars; callback success (session rotated, id token stored, redirect to return path), state mismatch, expired, replay, IdP error, nonce mismatch, bad signature, exchange failure (fake checks PKCE); AllowedEmailDomains; OnLogin change/refusal; ErrorURL; logout with and without end_session_endpoint, foreign session gets no hint, a failed session read degrades the outcome; a failed ID token write leaves no session; discovery and JWKS errors carry no answer text; front-channel table (iss/sid pairing, wrong issuer, sid mismatch, foreign provider, no session, iframe heuristic on/off, headers); two providers on one store. |
| `oidc/keycloak` | port `gocloak_test`: validation per grant; token cached and renewed (clock), dropped after a 401; AuthenticationRealm used for the token; Enrich fills roles/client roles/groups/attributes; client UUID cached, retried after failure; each Required* missing -> ErrForbidden with Reason, generic response; API error -> plain error. |
| `github` | port `oauth_handler_test`, `session_handler_test`, `github_connector_test`, `init_test`, `coverage_gap_test`, `fuzz_test`: validation (teams format, https/loopback, defaults, caller slices untouched); login; callback incl. state/PKCE, pagination > 100 teams, filtered teams, admin role, not allowed -> 403 without session, API failure -> 500; logout revokes token, revocation failure degraded; refresh-teams and Refresh (removal ends session, admin role toggled, other roles kept, a concurrent save survives the refresh, a second conflict is 409, a session that cannot be ended is 500); HTTPClient sends the token, foreign session refused; fuzz team slug normalisation. |
| `apikey` | validation (incl. invalid permissions); X-API-Key and Bearer; invalid -> 401 without fall-through; no key -> pass-through; resolver success/unknown/nil/error; roles and permissions cloned per request and isolated from Options and from the resolver's identity; outcomes. (Implemented, 100 %.) |
| `authorization` | allowed and denied case for every primitive [TST-003]; All/Any/Not empty and nested; 401 vs 403 kinds; Real; HasUserID with Nil; inactive refused; reasons stay server-side; HasPermission: exact resource, `*`, write grants read, read refuses write, no permissions, inactive, no identity (401), empty/invalid resource and invalid access fail (500, also under `Not` and `Not(Not(...))`), Reason names the missing permission but the body does not; `Any` with a failed check before or after a refusal fails, also under `Not`; `Not` passes an unauthenticated (or other non-403) refusal with a forbidden cause through. |
| `ginadapter` | Middleware pass (identity visible to the next gin handler) and refuse (aborted), wraps once, concurrent requests kept apart, a request that lost its chain is 500; RegisterRoutes (FullPath equals route path); Observe fields per section 5.4 asserted with an `EmitterFunc` [LOG-014], Success/Failure rules, no event in ctx is a no-op; Require 401/403/500 with recorded fields and generic body; RequireMethodPermission: GET with `x:read` passes, POST with `x:read` 403, POST with `*:write` passes, no identity 401. |
| `prometheusadapter` | counter moves per labels; `testutil.CollectAndLint` clean; duplicate registration returns an error [MET-007]. |
| `session/redisbackend` | `backendtest.Run` against miniredis; key layout with hash tags; marker blocks Put; no marker for an unknown session; a Pop retried after a lost reply (fault-injecting dialer) returns the value, also when another client put a replacement meanwhile (which stays); connection failure surfaces as error without a `redis.Nil` chain. |
| `internal/redirect` | tables for every function + `FuzzSafeReturnPath` (accepted paths never parse to a host or scheme). |
| `internal/oauthlogin`, `internal/httpjson`, `internal/random` | Begin/Complete tables; Decode content types, size, unknown fields, trailing data, errors never repeat request text; Write headers; token length and uniqueness. |
| `internal/dependency`, `internal/failure`, `internal/hook`, `internal/impersonation` | chain dropped but cancellation detectable; an HTTP call's error names neither path, query nor server bytes (malformed answer, connection refused, cancelled, client timeout, also wrapped by a dependency), `TransportFailure` table; denied vs error, `NewReporter` validation, `Reporter` (JSON, ErrorURL redirect only for callbacks, Provider stamped, nil Observer); nil hook, refusal kind kept, nil identity; write-back with and without impersonation, inputs untouched. |
| `internal/tokenendpoint`, `internal/fetchmetadata` | the endpoint's description, URI and body never in the error (code kept when well-formed, dropped when malformed or overlong; no Response), context errors detectable, `Refused` below 500 only; `cross-site` refused, `same-origin`, `same-site`, `none` and no header pass. Provider tests: every logout route refuses a cross-site request without touching the session, oidc front-channel logout passes it. |
| `internal/forwardauth` | through the real gin engine with memory backend and fake issuer: ui/api checks, JWT header, jwks, me toggle, health/ready, readiness 503 during shutdown delay, metrics labels (route template, `unmatched`, method `other`), query redaction pre-enricher (dev and JSON emitter), sampler keeps 401/403 and unmatched requests, observer closure records and counts, dependency sums and histogram, JSON error lines of both listeners, metrics listener serves only `GET /metrics`, both listeners bound by the LAY-006 timeouts, a trailing "/" is an unmatched 404 (no redirect), recorded transport errors repeat nothing the server sent; `goleak.VerifyTestMain` over the package. |

Coverage is measured without `cmd/`, `internal/fakeprovider/` and `test/`; `cmd/forwardauth` is covered by the e2e suite [TST-010].

### 8.2 End-to-end suites (build tag `e2e`, every file `//go:build e2e`) [TST-011]

**(a) `test/e2e` - binary subprocess.** `TestMain` reads `E2E_BINARY` (absolute path, built with `-cover`) and passes `GOCOVERDIR` through. A helper starts the binary with an explicit environment (no inherited env, `cmd.Dir` = `t.TempDir()` so no `.env` is read [CFG-005]) on free ports (probed on 127.0.0.1; an exit with `address already in use` is retried on two new ports, at most 3 attempts), waits for `{prefix}/health`, and stops it with SIGTERM and waits (coverage is written on normal exit). JWT key generated in the test. Fakes: `fakeprovider.StartOIDC` (with Keycloak realm) and `StartGitHub` in the test process; miniredis via TCP. Scenarios:
1. Boot fails with a non-zero exit and lists the variables when `EXTERNAL_URL`, `PROVIDER` or `SESSION_ENCRYPTION_KEY` is missing, and when `PROVIDER=github` lacks `GITHUB_ALLOWED_TEAMS`.
2. OIDC UI flow: `/auth/ui` with `X-Forwarded-Uri: /dashboard?tab=2` -> 302 to `EXTERNAL_URL/auth/oidc/oidc/login?return_to=...` -> IdP -> callback -> 302 to `/dashboard?tab=2` with cookie -> `/auth/ui` 200 with `Authorization: Bearer`; the JWT verifies with `jwt.NewVerifier` against `/auth/jwks` and carries sub, provider, roles, groups.
3. OIDC API check without cookie: 401 `{"code":"unauthenticated","message":"authentication required"}`.
4. Open redirect: `return_to=//evil.example` ends at `/`.
5. RP-initiated logout sends `id_token_hint`; afterwards `/auth/ui` redirects again. Front-channel logout with matching iss/sid ends the session.
6. Keycloak enrichment: roles in the JWT; missing required realm role -> callback 403 `forbidden`, body without the role name.
7. API keys: `X-API-Key` and Bearer -> 200 + JWT `sub` = key name and `permissions` from `API_KEY_PERMISSIONS` (`ci=builds:write+*:read` -> `["builds:write","*:read"]`); key without an entry -> no `permissions` claim; wrong key -> 401; boot fails for an entry naming an unknown key or an unparsable permission.
8. GitHub flow (second binary): allowed team -> 200, JWT teams filtered; not allowed -> 403; `refresh-teams` after the fake removes the team -> 403 and the session is gone; Refresher after `SESSION_REFRESH_INTERVAL_SECONDS=1` (fake clock not available here: interval of 1 s and `require.Eventually`).
9. Multi-replica: two binaries on one miniredis; login through A, `/auth/ui` on B -> 200; logout on B, A refuses.
10. `/auth/me` toggle; `/auth/ready` 503 during the shutdown delay (`SHUTDOWN_DELAY_SECONDS=5`, polled for 3 s); metrics port serves `forwardauth_http_requests_total` and `forwardauth_auth_outcomes_total`, `/` on it is 404.
11. Also covered: boot fails when the issuer or Redis is unreachable, and lists every problem at once, also those the components judge (API key secrets, PATH_PREFIX segments); GitHub logout revokes the token; the wide events are JSON lines without secrets, with `http.github` and `cache` sums and the dependency histogram; with `DEV_MODE=true` no query value is printed.

**(b) `test/e2e/compose` - docker compose** (stack layout, ports, image pins, harness: `docs/infrastructure-notes.md`). Traefik v3.7.16 + the forwardauth image (`PROVIDER=oidc`, `JWT_ENABLED=true`) + a fake issuer container whose `main` (`//go:build e2e`) serves `fakeprovider.NewOIDCHandler` + whoami behind the `forwardauth-ui` and `forwardauth-api` middlewares, wired as section 6.3. Every URL is `http://127.0.0.1:<free port>` and forwardauth runs in the issuer container's network namespace (`network_mode: service:issuer`), so the issuer URL is identical inside and outside Docker without DNS or dialer tricks. `docker compose down --volumes` runs also on failure. Scenarios: an anonymous browser goes through the issuer with PKCE, state and nonce; login ends at whoami with `Authorization: Bearer` echoed and verifiable against `/auth/jwks`; `/api` without session 401 JSON, with a session reaches the app; logout then `/whoami` redirects to login; a client's `Authorization` header never reaches the app; client-sent `X-Forwarded-*` headers do not steer the redirect; a forged callback state is refused; the checks and probes are not routed to the browser. Runs on `ubuntu-latest`.

### 8.3 Tooling files

`justfile` (follows govengers/config's; the file in the repository is the reference, recipes summarised here):

| Recipe | What it does |
|---|---|
| `lint` | fails when git tracks an executable (Mach-O, ELF, PE by `file --mime-type`), then `go vet ./...`, `go vet -tags e2e ./test/e2e/...`, `golangci-lint run ./...` |
| `test` | gotestsum `-race -count=1` with a coverage profile; drops `/cmd/`, `/internal/fakeprovider/`, `/test/` from it (`sandbox/unit.cover`); fails below 80 % total or 80 % in any package |
| `build` | `go build -trimpath -ldflags "-s -w -X main.version=<git describe>" -o sandbox/forwardauth ./cmd/forwardauth` |
| `docker-build` | `docker build -f docker/forwardauth.Dockerfile --build-arg VERSION=<git describe> -t ghcr.io/govengers/forwardauth:<git describe> .` |
| `test-e2e` | picks two free ports (20000..32767, below the common ephemeral ranges), generates a JWT key, builds the binary with `-cover`, starts the compose stack (`up --detach --build --wait`), runs both suites in one gotestsum run (`-tags e2e ./test/e2e/...`, `sandbox/e2e.json`), prints the binary coverage; the stack is always stopped (logs printed on failure) |
| `vulncheck` | `govulncheck ./...` |
| `check` | `lint test test-e2e vulncheck` (everything CI runs) |

`sandbox/unit.cover` is the filtered profile, so the CI coverage badge matches the gate. Tools run through `go run module@version` (gotestsum v1.13.0, govulncheck v1.9.0), never `tool` directives [TCH-002].

`.govengers.yml`:
```yaml
profile: library
exceptions:
  - rule: DES-008
    reason: >-
      Only password kindOf (password/validation.go). The login request has one "identifier" field, ...
```
One rule is waived, DES-008, for one site: password's `kindOf` tells an email from a username by "@" (F1 step 2), because the login body has one `identifier` field (the go-basicauth wire format) and usernames cannot contain "@"; the reason in the file says why separate fields or looking up both kinds are worse. Any other string dispatch is outside the exception. The repo also contains a service (`cmd/forwardauth`, `internal/forwardauth`); reviewers apply the service rules CFG, LAY, LOG, MET, DEP, API-001/002 to those two directories in addition to the library profile (stated in README "Contributing").

`.golangci.yml`: copied verbatim from `govengers/standards/.golangci.yml` (already sets `run.build-tags: [e2e]`). No local relaxations.

CI caller workflow (org reusable `go-library.yml@v1`, as govengers/config), the GHCR release workflow and `.dockerignore`: see `docs/infrastructure-notes.md`. `.gitignore`: `sandbox/`, `.env`, `/forwardauth` (a root `go build ./cmd/forwardauth`).

---

## 9. Work breakdown

Historical: every work package below and a cleanup pass (shared helpers moved to `internal/{redirect, dependency, failure, hook, impersonation}`, `auth.ActionTOTPStatus`, decisions D23-D24) are merged on `feat/v1`; ownership is kept for reference. Merge order was: **WP0 first**, then WP1-WP6 and WP8 in parallel, **WP7 last**. Every WP: branch from `feat/v1` after WP0, `just check` green before merge, self-review with `standards/REVIEW.md`. `go.mod`/`go.sum` conflicts are resolved at merge with `go mod tidy`. Deviations went back to the design lead, who folded them into this document (7.2).

### WP0 Foundation (one agent)
- Owns: `go.mod` (module `github.com/govengers/auth`, `go 1.26.0`), `go.sum`, `.gitignore`, `.golangci.yml`, `.govengers.yml`, `justfile` (complete, section 8.3), `.github/workflows/ci.yml`, root package `*.go`, `session/` (without `redisbackend/`), `jwt/`, `internal/random`, `internal/redirect`, `internal/httpjson`, `internal/oauthlogin`, `internal/backendtest`, `internal/fakeprovider/doc.go` (package comment only), `LICENSE` stays.
- Consumes: nothing.
- Ships: tests of section 8.1 for `auth`, `session`, `jwt`, `internal/*`; examples for `auth`, `session`, `jwt`.
- Must not touch: any provider, adapter or binary directory; README.md.

### WP1 Password provider
- Owns: `password/`.
- Consumes: `auth.{Identity, Error, sentinels, WriteError, IdentityResponse, NewIdentityResponse, Hook, LogoutHook, Observer, Outcome, Action*, Result*, Route}`, `session.{Store, Session, Refresher contract}`, `internal/httpjson`, `internal/random`.
- Ships: password tests (8.1), `Example` for `New` + `Routes`.
- Must not touch: `session/`, root, `internal/` (request changes from WP0 owner instead).

### WP2 OIDC + Keycloak
- Owns: `oidc/`, `oidc/keycloak/`, `internal/fakeprovider/oidc.go`, `internal/fakeprovider/keycloak.go`.
- Consumes: root API, `session`, `internal/oauthlogin`, `internal/redirect`, `internal/httpjson`.
- Ships: oidc and keycloak tests (8.1), examples; the fake issuer API used by WP7 (section 3.13).
- Must not touch: `internal/oauthlogin` (WP0), `internal/fakeprovider/github.go`.

### WP3 GitHub provider
- Owns: `github/`, `internal/fakeprovider/github.go`.
- Consumes: root API, `session`, `internal/oauthlogin`, `internal/redirect`, `internal/httpjson`.
- Ships: github tests (8.1) incl. fuzz test, example.
- Must not touch: `internal/fakeprovider/oidc.go`, `keycloak.go`.

### WP4 API keys
- Owns: `apikey/`.
- Consumes: root API.
- Ships: apikey tests, example.
- Must not touch: anything else.

### WP5 Authorization + gin adapter
- Owns: `authorization/`, `ginadapter/`.
- Consumes: root API (`Identity`, `IdentityFrom`, `Error`, sentinels, `ResponseFor`, `Outcome`, `Route`); `go-wide-event-logger` v0.3.2 (`FromContext`, `Event` setters, `Middleware`, `EmitterFunc` in tests).
- Ships: authorization and ginadapter tests (8.1), examples (`All`/`Any`, `Middleware` + `Require` on a gin engine).
- Must not touch: root package.

### WP6 Redis backend
- Owns: `session/redisbackend/`.
- Consumes: `session.Backend`, `session.ErrRevoked`, `internal/backendtest`.
- Ships: conformance run on miniredis, layout test, example.
- Must not touch: `session/*.go`.

### WP7 Forward-auth binary, Docker, e2e, metrics adapter (merges last)
- Owns: `cmd/forwardauth/`, `internal/forwardauth/`, `prometheusadapter/`, `test/e2e/**`, and the infra files specified in `docs/infrastructure-notes.md` (Dockerfile, `.dockerignore`, GHCR release workflow, compose stack and fake-issuer container); may edit only the `build`, `docker-build`, `test-e2e` recipes of the justfile.
- Consumes: every public API above, `internal/fakeprovider` (WP2, WP3), `internal/redirect.ExternalURL`, `github.com/govengers/config/v2 v2.0.0` (`LoadConfig`, `String/StringArray/Bool/Int`, `.Default/.NotEmpty/.Sensitive/.Into`, `Print`), `docs/infrastructure-notes.md`.
- Ships: `internal/forwardauth` and `prometheusadapter` unit tests, both e2e suites (8.2), Dockerfile, image workflow.
- Must not touch: library packages (bugs found go to the owning WP).

### WP8 README and migration docs
- Owns: `README.md`, `docs/migration.md`.
- Consumes: this document (sections 3, 6, 10).
- Ships: README with badges (as govengers/config), install line, minimal examples (password app, OIDC app with Keycloak, GitHub forward auth, backend JWT verification, authorization), Traefik setup, the app-user middleware pattern replacing UserTransformer (D5), env var table, "Contributing" note on service rules for the binary, release-notes block for v1.0.0 [LIB-008, LIB-009]; `docs/migration.md` with section 10 expanded per old library.
- Must not touch: any `.go` file.

Follow-ups outside this repo (need MaPa's sign-off, not part of any WP): deprecation notices in the three old repos; `govengers/standards` AUTH-001/AUTH-007 and README stack table still name basicauth/oidc-auth and `UserTransformer`; move the wide-event logger's gin middleware into its own subpackage so cores could record directly later.

---

## 10. Migration notes (old -> new)

### 10.1 go-basicauth (v1.5.x) -> `password` + `session`

| Old | New |
|---|---|
| `basicauth.NewHandler(&Options{Engine, AuthenticationBaseUrl, Storage, Settings, UserKey, UserTransformer})` | `session.NewStore`, `password.New(&password.Options{Sessions, Storage, PathPrefix, ...})`, `session.NewGuard`; `PathPrefix` takes segments of `A-Z a-z 0-9 . _ ~ -` only, no trailing "/" (`AuthenticationBaseUrl` accepted more) |
| `(*Handler).RegisterRoutes()` (global `Engine.Use`) | `ginadapter.RegisterRoutes(engine, provider.Routes())` + `group.Use(ginadapter.Middleware(guard.RequireAPI()))` |
| `RequireAuth()` | `guard.RequireAPI()` |
| `PathRules`, `PublicPaths` | mount the Guard only on protected groups |
| `GetUserFromContext(c)`, gin key `"user"` | `auth.IdentityFrom(ctx)` |
| `UserKey`, `UserTransformer` | app middleware after the Guard (README pattern); provisioning in `OnLogin` |
| `BasicAuthSettings.EnableUsernameLogin` / `EnableEmailLogin` | `DisableUsernameLogin` / `DisableEmailLogin` |
| `EnableTFA`, `TFA` | `TOTP.Enabled` (the TOTP routes exist only with it; enrolled users cannot log in while it is off), `TOTP` (`MaxVerifyAttempts` -> `MaximumAttempts`, where 0 means the default 5, not unlimited, and wrong codes count across logins until a verified code or `ResetTOTPAttempts`; `SkewWindows` -> `Skew` (at most 10), `PendingSessionTTL` -> `PendingTTL`; `AccountLabel` removed; `Digits` 6 or 8; `Period` at most 3600; `BackupCodeCount` at most 20, codes at most 128 bytes and at least 1,000,000 distinct) |
| verify body `{"code","isBackupCode"}` (a wrong TOTP code fell through to the backup codes) | `{"code","backupCode"}`: `true` checks backup codes only, `false` TOTP codes only; every TOTP code is accepted once |
| `TFA.Required` (403 `tfa_setup_required`) | `TOTP.Required` (202 `{"challenge":"totp_setup"}` at login) |
| `EnableRegistration` | `EnableRegistration` |
| `SessionName`, `SessionExpiration` | `StoreOptions.CookieName`, `MaximumAge` |
| `SessionSecretKey` (64 B) | removed |
| `SessionEncryptionKey` (32 B) | `StoreOptions.EncryptionKey` |
| `CookieSecure`, `CookieHttpOnly`, `CookieSameSite`, `CookiePath`, `CookieDomain` | `InsecureCookie` (inverted), always HttpOnly, `SameSite`, `CookiePath`, `CookieDomain` |
| `PasswordRequirements` | `Policy` (`MinLength` -> `MinimumLength`, default 12, counted in characters; `RequireNumbers` -> `RequireDigit`) |
| `Messages` | removed (client codes) |
| `HashingParams`, `Params`, `DefaultPasswordHashingParams` | `HashParameters`, `Parameters`, `DefaultParameters()` |
| `LegacyPasswordVerifier`, `BcryptVerifier` | `LegacyVerifier`, `VerifyBcrypt` (only login rehashes, legacy hashes and Argon2id hashes on other parameters than `HashParameters`; a hash nothing can verify is 401 `invalid_credentials`) |
| `HashPassword`, `VerifyPassword` (returned Params) | `Hash`, `Verify` (returns `(bool, error)`) |
| `GenerateSessionSecretKey`, `GenerateSessionEncryptionKey`, `GenerateSessionKey` | `openssl rand -base64 32` + `session.ParseKey` |
| `NewMemoryStorage` | `password.NewMemoryStorage` |
| `Storage` without ctx; `UpdateUser`, `DeleteUser` | ctx on every method; `UpdatePasswordHash` (CAS); new `ConsumeTOTPStep` (a `totp_step` column, atomic "later than the last used step" UPDATE); delete removed; `CreateUser` must return `ErrUserExists`; usernames and emails unique and looked up ignoring case |
| `User.CreatedAt/UpdatedAt/IsTechnicalUser/APIKeyHash/TOTPEnrolledAt/TOTPFailedAttempts` | not part of `password.User` (keep them in your own table) |
| routes `/auth/login`, `/logout`, `/register`, `/me`, `/tfa/{setup,enable,disable,verify}` | `/auth/password/login`, `/logout`, `/register`, `auth.IdentityHandler()` at an app path, `/auth/password/totp/{setup,enable,disable,verify}` + `GET /auth/password/totp` |
| error body `{"error","message"}`, codes `tfa_*`, `unauthorized`, `invalid_request` | `{"code","message"}`, codes `totp_*`, `unauthenticated`, `invalid_request` |
| login 202 `{"data":{"tfaRequired":true}}`, success `{"message","data":UserResponse}` | 202 `{"challenge":"totp"}`, 200 `IdentityResponse`; logout 204 |
| errors `ErrInvalidCredentials`... | `auth.ErrUnauthenticated` etc. + codes (section 5.3); storage sentinels `ErrUserNotFound`, `ErrUserExists`, `ErrTOTPAttemptsExhausted` |

### 10.2 oidc-fwd-auth (v0.9.x) library -> `oidc`, `session`, `jwt`, `oidc/keycloak`

| Old | New |
|---|---|
| `oidc.NewHandler(&Options{Provider, Session, ...})` | `oidc.New(ctx, &oidc.Options{Name, Issuer, ClientID, ClientSecret, ExternalURL, Sessions, ...})` |
| `ProviderOptions.ClientId`, `RedirectUri`, `LogoutUri`, `Scopes`+`ExtraScopes`, `ClaimMapper` | `ClientID`, derived from ExternalURL, discovered `end_session_endpoint`, `Scopes`, `ClaimMapper` (returns `oidc.Profile`) |
| `PostLogoutRedirectUri`, `AuthBaseUrl`, `AuthBaseContextPath` | `PostLogoutURL` (path or absolute URL, no fragment), `ExternalURL`, `PathPrefix` (default `/auth/oidc/<name>`; same segment rule as password); `Name` must not be `password`, `github`, `apikey`, `session` or `jwt` |
| `EnableUserInfoEndpoint`, `/userinfo` | `auth.IdentityHandler()` (no raw claims) |
| `SessionOptions{SecretSigningKey, SecretEncryptionKey, Name, Domain, MaxAge, Secure, SameSite, Backend, CacheSize, CacheTTL, Redis}` | `session.StoreOptions{-, EncryptionKey []byte, CookieName, CookieDomain, MaximumAge time.Duration, InsecureCookie, SameSite, Backend, -, -, redisbackend.New}`; `CacheSize` -> `MemoryBackendOptions.MaximumSessions` |
| `ExternalSessionStore`, `MultiHandler`, `AddProvider`, `GetHandler`, `GetDefaultHandler`, `LoginURL`, `ProviderNames` | one `oidc.New` per IdP sharing one Store; `Provider.LoginURL()` |
| `GetUiAuthMiddleware`, `GetApiAuthMiddleware` | `guard.RequireUI()`, `guard.RequireAPI()` |
| gin keys `sessionData`, `realmRoles`, `clientRoles`, `groups`, `attributes`, `provider` | `auth.IdentityFrom(ctx)`: `OIDCRoles`, `OIDCClientRoles`, `Groups`, `Attributes`, `Provider` |
| `SessionData{Sub, Name, Username, Email, IDToken, Claims, AccessTokenClaims, RealmRoles, ClientRoles, Groups, Attributes}` | `auth.Identity{Subject, Name, Username, Email, -, Claims, -, OIDCRoles, OIDCClientRoles, Groups, Attributes}` |
| `SessionStore.GetSessionData(r)`, `Set/Get/PopStringValue`, flash | `store.Open(r)` + `Session.Identity/Put/Get/Pop` |
| `PostLoginHook(c, *SessionData) error` | `OnLogin auth.Hook` (return `&auth.Error{Kind: auth.ErrForbidden}` to refuse) |
| `PostLogoutHook(c)` | `OnLogout auth.LogoutHook` |
| `GocloakOptions{ServerURL, AuthMethod, ...}`, `FetchUserAuthorization`, `GocloakEnabled` | `keycloak.New(&keycloak.Options{URL, GrantType (default client_credentials), AuthenticationRealm, ...})`, `OnLogin: client.Enrich` |
| `AuthorizationDeniedError` (403 with detail) | `*auth.Error{Kind: ErrForbidden, Reason}` (403 without detail) |
| `ErrSessionRevoked` | `session.ErrRevoked` |
| `jwt.NewSigner(&SignerOptions{Algorithm, JwtIssuer, JwtPrivateKey})`, `NewToken`, `SignToken`, `Token`, `Jwks` | `jwt.NewSigner(&jwt.SignerOptions{PrivateKey, Issuer, Audience, Lifetime})`, `Sign(identity)`, `JWKSHandler()` |
| `jwt.NewHandler(&HandlerOptions{JwksUrl, JwksRefreshInterval, LocalJwks, Cached, CacheSize, TTL, HeaderKey})`, `GetUserFromRequest`, `jwt.User` | `jwt.NewVerifier(ctx, &jwt.VerifierOptions{JWKSURL, Issuer, Audience, RefreshInterval, HeaderName})`, `Middleware()` / `Verify`, `auth.Identity` |
| routes `/auth/oidc/{login,callback,logout,frontchannel-logout}` | `/auth/oidc/<name>/...` (register the new callback at the IdP) |

### 10.3 github-fwd-auth (v1.4.x) library -> `github`, `apikey`, `session`

| Old | New |
|---|---|
| `githuboauth.Init(engine, &Config)` / `New(&Config)` + `GetMiddleware()` | `github.New(&github.Options{...})`, `ginadapter.RegisterRoutes`, `ginadapter.Middleware(guard.RequireUI())` |
| `Config.RedirectURI`, `AuthURL`, `TokenURL`, `DeviceAuthURL`, `GitHubAPIBaseURL`, `BaseURL` | derived, `AuthorizeURL`, `TokenURL`, removed, `APIURL`, `ExternalURL` |
| `LoginPath`, `CallbackPath`, `UserInfoPath`, `LogoutPath`, `RefreshTeamsPath` | `PathPrefix` (`/auth/github`); userinfo -> `auth.IdentityHandler()`; logout is `GET`; `ErrorURL`/`PostLogoutURL` as in oidc (a relative one becomes absolute, a hash route like `/#/error` is refused) |
| `AllowedTeams`, `AdminTeams`, `RelevantTeams` | same (never mutated; Teams filtered to these, sorted); `AllowedTeams` needs at least one team (empty used to admit everyone); AdminTeams members still need an allowed team |
| `AllowedAPIKeys`, `APIKeyResolver`, `ResolvedAPIKey{Login, Teams, Data}` | `apikey.Options{Keys: []apikey.Key{Name, Secret, Roles, Permissions}, Resolver}` returning `*auth.Identity{Subject/Username, Teams, Permissions, Data}` |
| access level in `ResolvedAPIKey.Data` (build-api `read_only` / `read_write`) + an app middleware refusing non-GET for read_only | `Identity.Permissions`: `read_only` -> `[*:read]`, `read_write` -> `[*:write]`; gate with `ginadapter.RequireMethodPermission(resource)` or `Require(authorization.HasPermission(...))`. Browser sessions have no permissions: grant them in `OnLogin` (e.g. `*:write` for allowed-team members) or compose `Any(HasRole(...), HasPermission(...))` |
| `GetApiKeyAuthMiddleware(keys)` | `keys, err := apikey.New(...)`, then `keys.Middleware()` |
| `SessionSecretKey`, `SessionEncryptionKey`, `CookieName`, `CookieDomain` (default localhost), `SessionMaxAge *int`, `CookieInsecure` | removed, `StoreOptions.EncryptionKey`, `CookieName`, `CookieDomain` (default host-only), `MaximumAge`, `InsecureCookie` |
| `Handle.IsAuthenticated(c)`, `IsAdmin(c)`, `GetRelevantTeams(c)` | `authorization.IsAuthenticated()`, `authorization.IsAdmin()`, `auth.IdentityFrom(ctx).Teams` |
| `GetAdminMiddleware()` | `ginadapter.Require(authorization.IsAdmin())` |
| `GetSessionStore().GetSession(c)`, `Session.GetHttpClient(ctx)`, `GetToken` | `store.Open(request)`, `provider.HTTPClient(ctx, current)` |
| `GetGitHubConnector`, `UserProfile`, `Team`, `Organization`, `Plan`, `GetTeamSlugs` | removed; `Identity.Teams`, `HTTPClient` for anything else |
| `GenerateSession*Key`, `EncodeKeyToBase64`, `DecodeKeyFromBase64` | `session.ParseKey` |
| `ErrSessionNotFound`, `ErrInvalidSession`, `ErrUserInfoNotCached` | `auth.ErrUnauthenticated` |
| github `pkg/jwt` (jwx v2) | `jwt` (jwx v3); JWT `sub` = numeric ID, `preferred_username` = login, `uid` removed |

### 10.4 Forward-auth environment variables -> `forwardauth`

| oidc-fwd-auth | github-fwd-auth | forwardauth |
|---|---|---|
| - | - | `PROVIDER` (new, required) |
| `DEPLOYMENT_IMAGE_TAG` | - | removed (version via ldflags) |
| `LOG_LEVEL` | `LOG_LEVEL` | removed (wide events; `WIDE_EVENT_SAMPLE_RATE`) |
| `DEV` | `DEV` | `DEV_MODE` |
| `PORT` | `PORT` | `PORT` (+ `METRICS_PORT`) |
| `HEALTH_ENDPOINT`, `FWD_AUTH_API_ENDPOINT`, `FWD_AUTH_UI_ENDPOINT`, `JWKS_ENDPOINT`, `OIDC_ENDPOINTS_BASE_CONTEXT_PATH` | `/health`, `/api-auth`, `/ui-auth`, `/JWKS` (fixed) | `PATH_PREFIX` + `/health`, `/api`, `/ui`, `/jwks`, `/oidc/<OIDC_NAME>` |
| `ENABLE_USERINFO_ENDPOINT` | - | `IDENTITY_ENDPOINT_ENABLED` |
| `OIDC_ENDPOINTS_BASE_URL` | `BASE_URL` | `EXTERNAL_URL` (required; an origin, no path) |
| `SESSION_SIGNING_KEY` | `SESSION_SECRET_KEY` | removed |
| `SESSION_ENCRYPTION_KEY` (32 chars) | `SESSION_ENCRYPTION_KEY` (base64) | `SESSION_ENCRYPTION_KEY` (base64 of 32 bytes; `printf %s "$OLD" \| base64` keeps an old 32-char key) |
| `SESSION_NAME` | `SESSION_COOKIE_NAME` | `SESSION_COOKIE_NAME` |
| `SESSION_DOMAIN` (default localhost) | `COOKIE_DOMAIN` (default localhost) | `SESSION_COOKIE_DOMAIN` (default host-only) |
| `SESSION_MAX_AGE` | `SESSION_MAX_AGE` | `SESSION_MAXIMUM_AGE_SECONDS` |
| `SESSION_SECURE` | `COOKIE_INSECURE` | `SESSION_INSECURE_COOKIE` |
| `SESSION_CACHE_SIZE` | - | removed |
| `SESSION_REDIS_ENABLED`, `_HOST` + `_PORT`, `_PASSWORD`, `_DB`, `_KEY_PREFIX` | - | `SESSION_REDIS_ENABLED`, `_ADDRESS`, `_PASSWORD`, `_DATABASE`, `_KEY_PREFIX` |
| `OIDC_WELL_KNOWN_URL` | - | `OIDC_ISSUER` |
| `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_SCOPES` | `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`, `OAUTH_SCOPES` | `OIDC_*` / `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_SCOPES` |
| `OIDC_REDIRECT_URI`, `GOOGLE_REDIRECT_URI` | `OAUTH_REDIRECT_URI` | removed (derived; register `EXTERNAL_URL/auth/oidc/<name>/callback` or `/auth/github/callback`) |
| `OIDC_LOGOUT_URL` | - | removed (discovered); `OIDC_POST_LOGOUT_URL` |
| `KEYCLOAK_SERVER_URL`, `KEYCLOAK_AUTH_METHOD` (default password) | - | `KEYCLOAK_URL`, `KEYCLOAK_GRANT_TYPE` (default client_credentials) |
| other `KEYCLOAK_*` | - | unchanged names (+ `KEYCLOAK_AUTHENTICATION_REALM`) |
| `GOOGLE_ENABLED`, `GOOGLE_CLIENT_ID/SECRET/SCOPES`, `AUTH_DEFAULT_PROVIDER`, `AUTH_LOGIN_SELECTOR_URL` | - | removed: one provider per instance; Google via `OIDC_ISSUER=https://accounts.google.com`, `OIDC_CLAIM_MAPPER=google`, `OIDC_ALLOWED_EMAIL_DOMAINS` |
| - | `OAUTH_PROVIDER_AUTH_URL`, `OAUTH_PROVIDER_TOKEN_URL`, `GITHUB_API_BASE_URL` | `GITHUB_AUTHORIZE_URL`, `GITHUB_TOKEN_URL`, `GITHUB_API_URL` (defaults github.com) |
| - | `OAUTH_PROVIDER_DEVICE_AUTH_URL` | removed |
| - | `ALLOWED_GITHUB_TEAMS`, `ADMIN_GITHUB_TEAMS` | `GITHUB_ALLOWED_TEAMS` (required), `GITHUB_ADMIN_TEAMS`, `GITHUB_RELEVANT_TEAMS` |
| (always signed) | `CREATE_JWT` | `JWT_ENABLED` (default false; oidc users set true) |
| - | `JWT_ALGORITHM` | removed (RS512) |
| `JWT_PRIVATE_KEY` (empty = generated) | `JWT_PRIVATE_KEY` | `JWT_PRIVATE_KEY` (required when enabled) |
| `JWT_ISSUER` (default oidc-fwd-auth) | `JWT_ISSUER` | `JWT_ISSUER` (default EXTERNAL_URL) + `JWT_AUDIENCE`, `JWT_LIFETIME_SECONDS`, `JWT_HEADER` |
| - | `API_KEYS` (secrets) | `API_KEYS_ENABLED=true` + `API_KEYS` (`name:secret` entries; carry no roles; ignored without the flag) |
| - | (static keys had unrestricted access) | `API_KEY_PERMISSIONS` (`name=perm+perm`); `name=*:write` reproduces the old unrestricted key for backends that check permissions |
| `github-fwd-auth.env` dotenv | - | `.env` in the working directory (dev only) |

Deployment changes: add the Traefik router for `PATH_PREFIX` on the app host, excluding the checks and probes (section 6.3); point forwardAuth at `/auth/ui` or `/auth/api` with `trustForwardHeader: false`, `maxResponseBodySize` and `authResponseHeaders: [Authorization, X-API-Key]` (the raw API key stops at forwardauth), and `aliasHeadersStrategy: delete` on the entrypoints; backends verify JWTs at `/auth/jwks` (was `/auth/JWKS` or `/JWKS`) with the issuer from `JWT_ISSUER`; static API keys need `API_KEYS_ENABLED=true`, and those that had unrestricted access need `API_KEY_PERMISSIONS` (`<name>=*:write`) wherever backends check permissions; every user logs in once after the upgrade (new session format).
