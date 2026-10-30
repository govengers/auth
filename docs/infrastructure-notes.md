# govengers/auth - infrastructure notes (CI, Docker, release, e2e)

Status: 29.10.2026. Groundwork for the implementation agents; `docs/design.md` fixes the code contracts, this file wins on infra details (design.md says so). Everything below marked "verified" was built and run in a scratch tree outside this repo (Go 1.26.3, Docker Desktop on arm64, a stand-in `cmd/forwardauth` with the routes and variables of design section 6, the real Traefik v3.7.16 image). The real binary is not involved, so adapt the marked spots.

## 0. Decisions and deviations from design.md (read this first)

1. **Hostname strategy for the compose suite changed.** Design D16 only accepts `http` for loopback hosts, so `http://issuer.e2e.test:8080` would be refused by `oidc`/`github` validation. Verified alternative: every URL is `http://127.0.0.1:<port>`, forwardauth runs in the **network namespace of the fake-issuer container** (`network_mode: service:issuer`), so `127.0.0.1:<issuer port>` is the same issuer inside and outside Docker. Ports are picked free by the justfile. No DNS, no `/etc/hosts`, no `DialContext` mapping in the test client (design 8.2(b) mentions one; it is no longer needed). Section 5.2.
2. **Fake issuer: our own Go fake, not `navikt/mock-oauth2-server`.** Section 5.1. A verified stdlib-only reference implementation is in appendix A; if WP2's `internal/fakeprovider` meets the contract in 5.1 use that instead (only `newIssuer` in the container `main` changes).
3. **Runtime image `gcr.io/distroless/static-debian13:nonroot`** (design 6.5 and DEP-002 say debian12). Both exist; `golang:1.26` is Debian 13 based, 13 was verified here. One-word change if you prefer 12.
4. **Image also published on `main` as `:main`** (lead's request; design 6.5 says tags only). To follow the design drop `branches:` and `type=ref,event=branch` from the release workflow (section 4.3).
5. **GitHub provider e2e stays in suite (a)** (binary subprocess, in-process `StartGitHub`), as in design 8.2(a) scenario 8. The compose stack is OIDC only. If a GitHub compose run is wanted later, the same network-namespace trick works (section 5.7).
6. **Traefik hardening that the stack and the docs ([Forward-Auth-Configuration](wiki/Forward-Auth-Configuration.md#traefik-settings)) should both state** (verified, section 5.6): `forwardAuth.trustForwardHeader: false`, `maxResponseBodySize`, `authResponseHeaders: [Authorization]` (Traefik deletes the client's `Authorization` before copying the auth response, also when the auth response has none), entrypoint `aliasHeadersStrategy: delete`. forwardauth must answer redirects with an **absolute** `Location` (confirmed: a relative one reaches the browser as `http://forwardauth:8080/...`).
7. **`just test-e2e` merges suite (a) and (b)** into one `gotestsum` run so `sandbox/e2e.json` counts both (section 5.5). `sandbox/unit.cover` must be the filtered profile because the org workflow computes the coverage badge from it (section 1).
8. Local Go 1.26.3 is stale: `govulncheck` reports stdlib GO-2026-6809/6617/6613/6612/6611 (fixed in 1.26.9/1.26.10). CI uses `setup-go` `1.26.x`, so it is fine there; locally `just vulncheck` fails until Go is upgraded.

## 1. Org CI: `govengers/.github` `go-library.yml@v1`

Source: `/Users/mapa/github.com/govengers/.github/.github/workflows/go-library.yml` (repo `govengers/.github`, tag `v1` = `9a44392`, which is also `main`). Starter template: `workflow-templates/go-library.yml` + `.properties.json` (filePattern `go.mod$`). The template and the caller file in govengers/config are byte-identical to what is below (`$default-branch` replaced by `main`).

**Contract (what the repo must provide)**

| Recipe | What the workflow needs from it |
|---|---|
| `just lint` | `golangci-lint` (installed by `golangci/golangci-lint-action@v9`, `install-only`, version input default `v2.15.0`) is on PATH; the recipe runs `go vet` and `golangci-lint run` with the repo's `.golangci.yml` |
| `just test` | unit tests with `-race`; **writes `sandbox/unit.json`** (`go test -json`, counted as `Action=="pass" and .Test != null`) **and `sandbox/unit.cover`**; fails below the threshold. The recipe owns the threshold (config: `coverage_threshold := "80"` + awk); the workflow itself never fails on coverage, it only colours the badge (>= 80 brightgreen, >= 60 yellow, else red) |
| `just test-e2e` | runs when input `e2e` is true (default); **writes `sandbox/e2e.json`** (same counting). Docker is available on `ubuntu-latest` (= ubuntu-24.04 image: Docker 28.0.4, Compose 2.38.2, Buildx preinstalled, per actions/runner-images) |
| `just vulncheck` | `govulncheck` text mode |

Order in the single job `check` (name shown to branch protection: `go-library / lint, test, e2e, vulncheck`): checkout@v7, Go version from the first `go` line of `go.mod` as `<major>.<minor>.x` (newest patch, TCH-001), setup-go@v7, setup-just@v4 (just 1.59.0), golangci-lint-action@v9, `just lint`, `just test`, `just test-e2e` (if `e2e`), `just vulncheck`, then "Build badges" and an artifact upload. No job `timeout-minutes` is set.

**Gotchas**

- The badge step runs `go tool cover -func=sandbox/unit.cover`. If `just test` filters generated code, `cmd/` or fakes (it should, design 8.3 `excluded`), the **filtered profile must be the file named `sandbox/unit.cover`**, otherwise the badge shows a different number than the gate. Write the raw profile to `sandbox/unit.raw.cover`.
- `go.mod` needs a `go 1.26.0` style line at the start of a line; `jq` and `awk` are used on the runner (present).
- Badges: job `badges` runs only on pushes to the default branch (`needs: check`, `contents: write`), force-pushes an orphan branch `badges` with `unit-tests.json`, `coverage.json`, `e2e-tests.json` (shields endpoint format, one commit "badges for <sha7>"), serialised by a concurrency group. A branch ruleset that forbids creating or force-pushing a branch named `badges` breaks it. `sandbox/e2e.json` missing means no e2e badge, and the table in the step summary shows `-`.
- Permissions: the caller needs `contents: write` on the calling job (a called workflow cannot exceed the caller), `contents: read` on top level. Nothing else; the image release is a separate workflow (section 4).
- Inputs: `golangci-lint-version` (default v2.15.0), `e2e` (true), `badges` (true).
- Actions are pinned by major tag (`@v7`, `@v9`, ...), not by SHA. The release workflow below follows that.


`.github/workflows/ci.yml (exact caller file for auth; same as govengers/config)`

```yaml
name: CI

on:
  push:
    branches: [main]
    tags: ["v*"]
  pull_request:

permissions:
  contents: read

jobs:
  go-library:
    uses: govengers/.github/.github/workflows/go-library.yml@v1
    permissions:
      contents: write # the badges job pushes test and coverage badges to the badges branch
```

After the first push to `main` set the badges in the README (section 2.7) and, if the repo uses branch protection, require the check `go-library / lint, test, e2e, vulncheck`.

## 2. How govengers/config v2 implements the contract (what to copy into auth)

State: the worktree `config-v2-fixes` (branch `fix/v2-review`) no longer exists, it was merged. Current source of truth: `/Users/mapa/github.com/govengers/config` on `main` = `cb3019e` (merge of PR #2), tag `v2.0.0` pushed. `justfile`, `.golangci.yml` and the e2e harness are unchanged from `fd60aff`. Its CI on main and on the tag is green (e2e badge "10 passed", coverage 96.8%).

| File | In auth |
|---|---|
| `.github/workflows/ci.yml` | copy as is (section 1) |
| `.golangci.yml` | copy verbatim from `/Users/mapa/github.com/govengers/standards/.golangci.yml` (identical to config's, `diff` clean); no local relaxations (design 8.3). It sets `run.build-tags: [e2e]` |
| `.govengers.yml` | `profile: library`, `exceptions: []` (design 8.3). Without the file the profile is inferred as `service` because `cmd/forwardauth` serves traffic (REVIEW.md step 2) |
| `.gitignore` | copy `/Users/mapa/github.com/govengers/config/.gitignore` (toptal go + JetBrains + VS Code); the project part is the tail below |
| `justfile` | pattern below; the auth version is design 8.3 plus the recipes of section 5.5 |
| `LICENSE` | already in the repo (Apache 2.0) |

### 2.1 config's justfile (pattern)


`govengers/config justfile`

```just
set shell := ["bash", "-euo", "pipefail", "-c"]

gotestsum := "go run gotest.tools/gotestsum@v1.13.0"
govulncheck := "go run golang.org/x/vuln/cmd/govulncheck@v1.9.0"
coverage_threshold := "80"

default:
    @just --list

# Vet and lint with the govengers baseline (.golangci.yml, copied from govengers/standards)
lint:
    go vet ./...
    go vet -tags e2e ./test/e2e/...
    golangci-lint run ./...

# Unit tests with the race detector; fails below the coverage threshold
test:
    mkdir -p sandbox
    {{gotestsum}} --format testname --jsonfile sandbox/unit.json -- -race -count=1 -coverprofile=sandbox/unit.cover ./...
    go tool cover -func=sandbox/unit.cover > sandbox/unit.func
    awk -v threshold={{coverage_threshold}} '/^total:/ { found = 1; sub("%", "", $3); print "coverage " $3 "%"; if ($3 + 0 < threshold) { print "coverage is below " threshold "%"; exit 1 } } END { if (!found) { print "no coverage total"; exit 1 } }' sandbox/unit.func

# End-to-end tests: build the example program in test/e2e/testdata/app and run it as a process
test-e2e:
    mkdir -p sandbox
    {{gotestsum}} --format testname --jsonfile sandbox/e2e.json -- -tags e2e -count=1 ./test/e2e/...

# Scan for known vulnerabilities in reachable code
vulncheck:
    {{govulncheck}} ./...

# Everything CI runs
check: lint test test-e2e vulncheck
```

For auth: add `build`, `docker-build`, a filtered coverage profile (`excluded := "/cmd/|/internal/fakeprovider/|/test/"`), the per-package gate (all in design 8.3), and the merged `test-e2e` of section 5.5. Keep `gotestsum` and `govulncheck` pinned by `go run module@version` (TCH-002; the pins are the ones in config).

### 2.2 `.gitignore` project tail

```gitignore
# just recipes write test reports here
sandbox/

# local configuration and keys
.env
*.env
*.pem
*.key
```

Note `*.pem`/`*.key`: a committed test key under those names needs `git add -f`. The compose suite avoids this by generating the JWT key per run (section 5.5).

### 2.3 `.govengers.yml`

```yaml
profile: library
exceptions: []
```

(config's own file waives DES-003 with a reason; auth has no such exception.)

### 2.4 `.golangci.yml`

Copy the file, do not retype it. Things the baseline forced on the verified code (so the implementation agents do not rediscover them):

- `varnamelen`: handler parameters are `writer http.ResponseWriter, request *http.Request`, never `w`/`r`; receivers may be short.
- `gosec` G120: `request.Body = http.MaxBytesReader(writer, request.Body, limit)` before `ParseForm`.
- `gosec` G704 (SSRF taint) fires on `client.Do(request)` in test helpers and in a health probe; where the URL is the test server's own, use `//nolint:gosec // G704: <reason>` at the call (nolintlint demands linter name + reason, and complains when the directive is unused).
- `bodyclose` cannot see a `t.Cleanup` close: read and close the body inside the helper and return a small struct (see `page` in section 5.4).
- `errorlint`: `fmt.Errorf("... %w", err)` only when `err` is non-nil.
- `funlen` (60 lines / 40 statements) applies to non-test files in `test/e2e/`, so keep fake handlers small.
- gofumpt/goimports: run `golangci-lint run --fix`-style formatting before committing.

### 2.5 How config's e2e harness builds and runs its binary (pattern for suite (a))

`test/e2e/config_test.go` (tag `e2e`): `TestMain` builds `./testdata/app` into `os.MkdirTemp` with `go build -o`, runs the suite, removes the directory; `runApp` starts the binary with `exec.CommandContext(t.Context(), ...)`, `cmd.Dir = t.TempDir()` and `cmd.Env = []string{"PATH=" + os.Getenv("PATH")}` plus the case's variables, so nothing leaks in from the developer's shell and no `.env` is found; it captures stdout/stderr in buffers and maps `*exec.ExitError` to an exit code. The app prints its bound configuration as JSON to stdout and the config table to stderr. Auth's variant differs as design 8.2(a) says: `E2E_BINARY` is a prebuilt `-cover` binary, `GOCOVERDIR` is passed through, the harness waits for `/auth/health` and stops the process with SIGTERM so coverage data is written.

### 2.6 `justfile` details worth keeping

`set shell := ["bash", "-euo", "pipefail", "-c"]` (every recipe line fails on its own), `go vet -tags e2e ./test/e2e/...` separate from `go vet ./...` (explicit path with the tag; `./...` silently skips packages whose files are all excluded by the tag).

### 2.7 README badges block (config's, adapted)

```markdown
[![CI](https://github.com/govengers/auth/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/govengers/auth/actions/workflows/ci.yml)
[![unit tests](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/govengers/auth/badges/unit-tests.json)](https://github.com/govengers/auth/actions/workflows/ci.yml)
[![e2e tests](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/govengers/auth/badges/e2e-tests.json)](test/e2e)
[![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/govengers/auth/badges/coverage.json)](https://github.com/govengers/auth/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/govengers/auth.svg)](https://pkg.go.dev/github.com/govengers/auth)
[![License](https://img.shields.io/github/license/govengers/auth)](LICENSE)
```

config's README "Tests" section for reference: unit tests `just test` (race, 80% gate), e2e `just test-e2e`, everything CI runs `just check`, "CI uses the shared govengers Go library workflow".

## 3. config v2 in a main package

**Pushed state (checked 29.10.2026):** `github.com/govengers/config` `main` = `cb3019e`, annotated tag `v2.0.0` (`5f997ab` -> `cb3019e`), branches `feat/v2` (`fd60aff`), `v1` (`112d5f6`), `badges`. `proxy.golang.org` resolves `github.com/govengers/config/v2@v2.0.0` and `@latest` to `v2.0.0` (2026-10-29T01:53:05Z), and a pseudo-version for any sha (`@fd60aff` -> `v2.0.0-20261029014714-fd60affc2cd2`). A branch name does not resolve through the proxy (`@feat/v2`: "disallowed version string"); use the tag. So: `go get github.com/govengers/config/v2@v2.0.0` works now.

API (from `config.go`, `values.go`, `registry.go`, `print.go`, `flag.go`):

- `config.LoadConfig([]config.Value) error` (reads `.env` in the working directory if present) and `config.LoadConfigWithOptions(values, &config.LoadConfigOptions{DotEnvFile, DotEnvFiles, DisableDotEnv})`. All problems are reported in one error; on failure nothing is changed (registry, targets, process environment).
- Builders `config.String`, `config.StringArray`, `config.Bool`, `config.Int`; methods `.Default(v)`, `.NotEmpty()` (String, StringArray), `.Sensitive()`, `.Into(*T)`. No default means required. `Bool` has no `NotEmpty`.
- `config.Get().String/StringArray/Bool/Int(key)` panic on an undeclared key or a type mismatch; `config.Set()` is for tests; `config.BindPFlag(key, flag)`.
- `config.Print()` writes the table to stdout, `config.Fprint(io.Writer) error` anywhere else. The table uses ANSI colours even when the writer is not a terminal, and masks `Sensitive` values as `****`.
- Dotenv: design 6.2 uses plain `LoadConfig` (reads `.env` from the working directory if there is one; the image has none). The snippet below uses `DisableDotEnv: true` for comparison; config's README recommends it in production because a `.env` in the working directory can set any variable of the process. The choice is the design lead's (section 7.3).

Compiling and running snippet (verified; shape of design 6.2):


`cmd/forwardauth/config.go (shape only)`

```go
// Command cfgsnippet compiles the config snippet of the infrastructure notes.
package main

import (
	"fmt"
	"os"

	"github.com/govengers/config/v2"
)

// Configuration holds every value the service reads; main copies fields into component options.
type Configuration struct {
	ListenAddress  string
	MetricsAddress string
	DevMode        bool
	SessionTTL     int
	IssuerURL      string
	ClientSecret   string
	AllowedHosts   []string
}

func loadConfiguration() (*Configuration, error) {
	configuration := &Configuration{}
	err := config.LoadConfigWithOptions([]config.Value{
		config.String("LISTEN_ADDRESS").NotEmpty().Default(":8080").Into(&configuration.ListenAddress),
		config.String("METRICS_ADDRESS").NotEmpty().Default(":9090").Into(&configuration.MetricsAddress),
		config.Bool("DEV_MODE").Default(false).Into(&configuration.DevMode),
		config.Int("SESSION_TTL_SECONDS").Default(86400).Into(&configuration.SessionTTL),
		config.String("OIDC_ISSUER_URL").NotEmpty().Into(&configuration.IssuerURL),
		config.String("OIDC_CLIENT_SECRET").NotEmpty().Sensitive().Into(&configuration.ClientSecret),
		config.StringArray("ALLOWED_HOSTS").NotEmpty().Into(&configuration.AllowedHosts),
	}, &config.LoadConfigOptions{DisableDotEnv: true}) // production: environment only (a .env must not set process variables)
	if err != nil {
		return nil, err // every missing or invalid value, in one error
	}
	return configuration, nil
}

func main() {
	configuration, err := loadConfiguration()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := config.Fprint(os.Stderr); err != nil { // the table, secrets masked as ****
		fmt.Fprintln(os.Stderr, err)
	}
	fmt.Println("listening on", configuration.ListenAddress)
}
```

Observed: with `OIDC_ISSUER_URL`, `OIDC_CLIENT_SECRET` and `ALLOWED_HOSTS` unset, the process prints `OIDC_ISSUER_URL is not set and has no default: missing` (one line per variable) and exits 1, which is what e2e scenario 1 of design 8.2(a) asserts.

## 4. Docker and release

### 4.1 Dockerfile

Path `docker/forwardauth.Dockerfile` (DEP-006). Verified: builds for `linux/arm64` (native) and `linux/amd64` (cross-compiled on an arm64 host, **no QEMU needed** because the builder runs on `$BUILDPLATFORM` and the runtime stage only copies a file); runs as uid 65532; `-X main.version` is injected; Go 1.26.10 toolchain comes from `golang:1.26` (same minor as `go.mod`, DEP-004); image about 4 MB for the stand-in, the real binary adds its size. `COPY . .` after `go mod download` keeps the dependency layer cached and is robust against the package layout; the `.dockerignore` keeps the context small and secrets out.


`docker/forwardauth.Dockerfile`

```dockerfile
# Build context is the repository root: docker build -f docker/forwardauth.Dockerfile .
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/forwardauth ./cmd/forwardauth

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/forwardauth /forwardauth
USER nonroot:nonroot
EXPOSE 8080 9090
ENTRYPOINT ["/forwardauth"]
```

Notes: `golang:1.26` floats on the patch version on purpose (newest security patch, TCH-001); pin by digest in Dependabot/Renovate if the org wants it. A distroless image has no shell or curl, so there is **no `HEALTHCHECK`**: Kubernetes uses `httpGet` on `/auth/health` (liveness) and `/auth/ready` (readiness) and the metrics port 9090; compose uses a `healthcheck` subcommand where it needs one (see the fake issuer) or the test polls. `GOMEMLIMIT`/`GOMAXPROCS` (DEP-008) belong to the deployment manifests, not the image.

### 4.2 `.dockerignore`


`.dockerignore`

```gitignore
.git
.github
docs
sandbox
**/*.md
**/*_test.go
.env
**/*.env
**/*.pem
**/*.key
```

(Patterns without `**/` only match the context root, hence `**/*.md`. Do not ignore `test/`: the fake-issuer image builds from the same context. Remove `**/*.md` if anything is `go:embed`ded from Markdown.)

### 4.3 Release workflow `.github/workflows/release.yml`

Builds `ghcr.io/govengers/forwardauth` for `linux/amd64,linux/arm64` on pushes to `main` (`:main`, `:sha-<7>`) and on `v*` tags (`:1.2.3`, `:1.2`, `:1`, `:latest` for non-prerelease tags, `:sha-<7>`). Action versions are the current releases (checked 29.10.2026: checkout v7.0.1, setup-buildx v4.4.1, login v4.7.0, metadata v6.2.0, build-push v7.4.0), pinned by major tag like the org workflow.


`.github/workflows/release.yml`

```yaml
name: Release image

# Publishes ghcr.io/govengers/forwardauth: :main on every push to main, :1.2.3, :1.2, :1 and :latest on a v1.2.3 tag.
on:
  push:
    branches: [main]
    tags: ["v*"]

permissions:
  contents: read

jobs:
  image:
    name: build and push ghcr.io/govengers/forwardauth
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write # push to ghcr.io with the workflow token
    steps:
      - uses: actions/checkout@v7

      # The builder stage cross-compiles (--platform=$BUILDPLATFORM) and the runtime stage only copies a file,
      # so the arm64 image needs no QEMU.
      - uses: docker/setup-buildx-action@v4

      - uses: docker/login-action@v4
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - id: meta
        uses: docker/metadata-action@v6
        with:
          images: ghcr.io/govengers/forwardauth
          tags: |
            type=ref,event=branch
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
            type=semver,pattern={{major}}
            type=sha

      - uses: docker/build-push-action@v7
        with:
          context: .
          file: docker/forwardauth.Dockerfile
          platforms: linux/amd64,linux/arm64
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          build-args: VERSION=${{ github.ref_type == 'tag' && github.ref_name || github.sha }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

Gating: this workflow does not wait for CI. On `main` the PR checks already ran; a tag is cut from a green `main`, and the e2e job builds the same image anyway. If a hard gate is wanted: add a job `ci: uses: govengers/.github/.github/workflows/go-library.yml@v1` (with `badges: false`, `permissions: contents: read`), `needs: ci` on `image`, and let `ci.yml` run on pull requests only (otherwise the suite runs twice on a tag).

**GHCR facts (checked with `gh`, 29.10.2026)**

- `gh api 'orgs/govengers/packages?package_type=container'` returns `[]`: no container package exists yet, so the first release creates `ghcr.io/govengers/forwardauth`.
- Org `govengers`: plan `free`, repo `govengers/auth` is public, default branch `main`. GHCR is available to free orgs and public images are free. The org-level Actions policies (allowed actions, default workflow permissions) are not readable without `admin:org` (403), so not verified; the release workflow sets `permissions` explicitly and uses only GitHub-owned and verified-creator actions (`actions/*`, `docker/*`).
- Expected one-time manual step (no REST API for it): after the first push, open the package settings and make the package **public**, and check it is linked to the repo (the `org.opencontainers.image.source` label that metadata-action sets does the linking) so `GITHUB_TOKEN` of later runs may push.

## 5. End-to-end with docker compose

Two suites (design 8.2): (a) `test/e2e` binary subprocess, no Docker; (b) `test/e2e/compose` Traefik + image + fake issuer + whoami. This section is (b), plus what suite (a) needs from the fakes.

### 5.1 Fake issuer: recommendation

**Use our own Go fake**, built from the same handler the unit tests use (`internal/fakeprovider` in the design), wrapped in a 80-line container `main`.

| | own Go fake | `ghcr.io/navikt/mock-oauth2-server` 6.1.4 |
|---|---|---|
| image | about 9 MB distroless static, built from this repo | 142 MiB compressed (linux/amd64, measured from the GHCR manifest), JVM |
| start | milliseconds | JVM start (not measured here) |
| network at CI time | none beyond what the build already pulls | one more pull from ghcr.io |
| PKCE | verifies S256, and can **reject** an authorize request without S256, state or nonce | supports `plain` and `S256` (source: `verifyPkce`), cannot refuse a client that sends none |
| nonce, end_session | yes | nonce echoed (source: `AuthorizationCodeHandler`), `/endsession` redirects to `post_logout_redirect_uri` |
| negative security tests | faults: wrong nonce, expired, wrong audience/issuer, broken signature | token claims configurable via `JSON_CONFIG`, signatures always valid |
| login without a human | one configured user (or a cookie picks the user) | `interactiveLogin: false` or a login form to POST; claims per request mapping |
| reuse | same code serves `httptest` unit tests and the container | container only |

Deciding reasons: determinism (no JVM, no third-party image drift, no network), strictness (the e2e suite can prove the library never skips PKCE/state/nonce, which a lenient mock cannot), and zero extra code because the handler exists anyway.

**Contract the container fake must meet** (the reference in appendix A does; check `fakeprovider.NewOIDCHandler` against it):

1. `ISSUER_URL`-configured issuer string equals the `iss` claim and the discovery `issuer` byte for byte.
2. Discovery with `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `end_session_endpoint`, `code_challenge_methods_supported: [S256]`; JWKS with the current key.
3. `/authorize`: unknown `client_id` or unregistered `redirect_uri` is a 400 page (never a redirect to it); missing `state`, `nonce` or S256 challenge redirects back with `error=invalid_request`; success redirects with `code` and `state`.
4. `/token`: client secret by Basic and by form; code single use; `redirect_uri` must match; `code_verifier` checked against the S256 challenge; returns `id_token` (nonce echoed) and a JWT `access_token`.
5. `/end_session`: redirects to a registered `post_logout_redirect_uri` (with `state`), otherwise a plain page.
6. The container `main` handles SIGTERM (a PID 1 Go process ignores it otherwise, and `compose down` waits 10 s; measured `down` with the handler: 0.7 s), listens on all interfaces, and has a `healthcheck` subcommand because distroless has no shell.
7. Optional, cheap: `POST/DELETE /_control/faults` (reference implementation) for suite-level negative tests; unit tests of `oidc` cover these without Docker.

### 5.2 Hostname strategy

Requirement: the issuer URL is one string that (1) the browser (test client on the host) follows, (2) appears as `iss`/`issuer`, (3) forwardauth (in a container) fetches discovery, JWKS and the token from, and (4) passes `oidc` validation, which allows `http` only for loopback (D16).

| Option | Verdict |
|---|---|
| `http://issuer.e2e.test:8080`, names resolved by a custom `DialContext` on the host and by network aliases in Docker | Works (verified), but the library refuses non-loopback `http` URLs. Only usable if D16 gets a test escape hatch. |
| `network_mode: host` for everything | Linux only; the macOS Docker Desktop VM has no host network. |
| forwardauth and fake issuer as host processes, only Traefik in Docker (`host.docker.internal`) | Does not test the image. |
| TLS with a generated test CA (`SSL_CERT_FILE` in forwardauth, `RootCAs` in the client) | Most realistic (Secure cookies on), but certificate plumbing in recipe, Traefik and three trust stores. Candidate for later. |
| **`http://127.0.0.1:<port>` everywhere, forwardauth joins the issuer container's network namespace** | **Chosen, verified.** Loopback satisfies D16; `127.0.0.1:<issuer port>` is the issuer in both views (published port on the host, shared loopback in the pod-like pair); Traefik reaches forwardauth as `http://issuer:8080` (the namespace owner's service name). |

Consequences: the issuer port must be the same number inside and outside, so the justfile picks two free ports (`E2E_APP_PORT` for Traefik's published port, `E2E_ISSUER_PORT` for the issuer) before `compose up`; fixed ports collide (on the author's machine 18080 was already taken). forwardauth must start after the issuer is listening (it discovers at startup): `depends_on: issuer: condition: service_healthy`, plus `restart: on-failure:5`. Cookies are keyed by host, not port, so the app and the issuer share a jar namespace on `127.0.0.1`; names do not collide (`forwardauth_session`, the login state cookie; the fake sets none). The Go cookie jar ignores `SameSite`, so this suite does not prove Lax/None behaviour; it needs a real browser (out of scope for forwardauth).

### 5.3 Stack files (verified)

Layout: `test/e2e/compose/{compose.yml,traefik/traefik.yml,traefik/dynamic.yml,docker/fakeissuer.Dockerfile,fakeissuer/main.go,browser_test.go,flows_test.go}`. Variables of forwardauth are those of design 6.2; the paths are those of design 6.3.


`test/e2e/compose/compose.yml`

```yaml
# End-to-end stack: Traefik (forwardAuth) -> the forwardauth image, with a fake OIDC issuer and whoami.
#
# Hostname strategy: every URL is http://127.0.0.1:<port>, with a port the justfile picks (E2E_APP_PORT for
# Traefik, E2E_ISSUER_PORT for the issuer). The library accepts http only for loopback hosts (design D16),
# and the issuer URL must be the same string in the browser's redirects, in the discovery document and in
# forwardauth's configuration. So forwardauth runs in the network namespace of the issuer container:
# there, 127.0.0.1:<issuer port> is the issuer, exactly as it is on the host through the published port.
# No DNS, no /etc/hosts, no dialer tricks in the test client.
name: auth-e2e
services:
  traefik:
    image: traefik:v3.7.16
    ports: ["127.0.0.1:${E2E_APP_PORT:?run just test-e2e}:8080"]
    volumes:
      - ./traefik/traefik.yml:/etc/traefik/traefik.yml:ro
      - ./traefik/dynamic.yml:/etc/traefik/dynamic.yml:ro
    healthcheck:
      test: ["CMD", "traefik", "healthcheck"]
      interval: 1s
      timeout: 2s
      retries: 30

  whoami:
    image: traefik/whoami:v1.12.0

  # Owns the network namespace that forwardauth joins; Traefik reaches forwardauth through this service name.
  issuer:
    build: {context: ../../.., dockerfile: test/e2e/compose/docker/fakeissuer.Dockerfile}
    ports: ["127.0.0.1:${E2E_ISSUER_PORT:?run just test-e2e}:${E2E_ISSUER_PORT}"]
    environment:
      LISTEN_ADDRESS: ":${E2E_ISSUER_PORT}"
      ISSUER_URL: http://127.0.0.1:${E2E_ISSUER_PORT}
      CLIENT_ID: forwardauth
      CLIENT_SECRET: e2e-oidc-secret
      REDIRECT_URIS: http://127.0.0.1:${E2E_APP_PORT}/auth/oidc/oidc/callback
      POST_LOGOUT_REDIRECT_URIS: http://127.0.0.1:${E2E_APP_PORT}/
    healthcheck: # distroless has no shell: the binary probes itself
      test: ["CMD", "/fakeissuer", "healthcheck"]
      interval: 1s
      timeout: 2s
      retries: 30

  forwardauth:
    build: {context: ../../.., dockerfile: docker/forwardauth.Dockerfile}
    network_mode: service:issuer
    environment: # design 6.2; the fixed values are test fixtures, not secrets
      PROVIDER: oidc
      EXTERNAL_URL: http://127.0.0.1:${E2E_APP_PORT}
      OIDC_ISSUER: http://127.0.0.1:${E2E_ISSUER_PORT}
      OIDC_CLIENT_ID: forwardauth
      OIDC_CLIENT_SECRET: e2e-oidc-secret
      SESSION_ENCRYPTION_KEY: MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY= # base64 of 32 bytes
      SESSION_INSECURE_COOKIE: "true" # the stack is plain HTTP
      SHUTDOWN_DELAY_SECONDS: "0"
      JWT_ENABLED: "true"
      JWT_PRIVATE_KEY: ${JWT_PRIVATE_KEY:?export a PEM key, or run just test-e2e}
    depends_on:
      issuer: {condition: service_healthy} # forwardauth discovers the issuer at startup
    restart: on-failure:5
```

`test/e2e/compose/traefik/traefik.yml`

```yaml
entryPoints:
  web:
    address: ":8080" # the port in every e2e URL: the network aliases of this service target it
    http:
      aliasHeadersStrategy: delete # X_Auth_User and X.Auth.User must not alias a header forwardAuth sets
  traefik:
    address: ":8082" # ping only; its default :8080 would collide with web
    http:
      aliasHeadersStrategy: delete
ping:
  entryPoint: traefik
providers:
  file:
    filename: /etc/traefik/dynamic.yml
log:
  level: INFO
```

`test/e2e/compose/traefik/dynamic.yml`

```yaml
# forwardauth shares the network namespace of the issuer service, so it is reached as http://issuer:8080.
http:
  routers:
    # a protected page: the browser is sent to the login when there is no session
    whoami-ui:
      rule: PathPrefix(`/whoami`)
      entryPoints: [web]
      service: whoami
      middlewares: [forwardauth-ui]
    # a protected API: 401 JSON when there is no session
    whoami-api:
      rule: PathPrefix(`/api`)
      entryPoints: [web]
      service: whoami
      middlewares: [forwardauth-api]
    # login, callback, logout, jwks, health of forwardauth itself: no middleware
    forwardauth:
      rule: PathPrefix(`/auth`)
      entryPoints: [web]
      service: forwardauth

  middlewares:
    forwardauth-ui:
      forwardAuth:
        address: http://issuer:8080/auth/ui
        authResponseHeaders: [Authorization]
        trustForwardHeader: false # forwardauth builds return paths from X-Forwarded-*: only Traefik may set them
        maxResponseBodySize: 65536
    forwardauth-api:
      forwardAuth:
        address: http://issuer:8080/auth/api
        authResponseHeaders: [Authorization]
        trustForwardHeader: false
        maxResponseBodySize: 65536

  services:
    whoami:
      loadBalancer:
        servers: [{url: "http://whoami:80"}]
    forwardauth: # runs in the network namespace of the issuer service (see compose.yml)
      loadBalancer:
        servers: [{url: "http://issuer:8080"}]
```

`test/e2e/compose/docker/fakeissuer.Dockerfile`

```dockerfile
# The fake OpenID Connect provider of the compose end-to-end stack. Build context: the repository root.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -tags e2e -trimpath -ldflags="-s -w" -o /out/fakeissuer ./test/e2e/compose/fakeissuer

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/fakeissuer /fakeissuer
USER nonroot:nonroot
ENTRYPOINT ["/fakeissuer"]
```

`test/e2e/compose/fakeissuer/main.go`

```go
//go:build e2e

// Command fakeissuer runs the fake OpenID Connect provider of the compose end-to-end stack.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/govengers/config/v2"

	"github.com/govengers/auth/internal/fakeissuer"
)

const shutdownTimeout = 5 * time.Second

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		return healthcheck()
	}
	options := &fakeissuer.Options{Users: fakeissuer.DefaultUsers(), DefaultUser: "alice"}
	var listenAddress string
	err := config.LoadConfigWithOptions([]config.Value{
		config.String("LISTEN_ADDRESS").NotEmpty().Into(&listenAddress), // all interfaces: Docker forwards to the container address
		config.String("ISSUER_URL").NotEmpty().Into(&options.Issuer),
		config.String("CLIENT_ID").NotEmpty().Into(&options.ClientID),
		config.String("CLIENT_SECRET").NotEmpty().Sensitive().Into(&options.ClientSecret),
		config.StringArray("REDIRECT_URIS").NotEmpty().Into(&options.RedirectURIs),
		config.StringArray("POST_LOGOUT_REDIRECT_URIS").Default(nil).Into(&options.PostLogoutRedirectURIs),
	}, &config.LoadConfigOptions{DisableDotEnv: true})
	if err != nil {
		return err
	}
	issuer, err := fakeissuer.New(options)
	if err != nil {
		return err
	}

	// docker compose stop sends SIGTERM; a process running as PID 1 ignores it unless it handles it
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server := &http.Server{Addr: listenAddress, Handler: issuer.Handler(), ReadHeaderTimeout: 5 * time.Second}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.ListenAndServe() }()

	select {
	case err := <-serveErrors:
		return err
	case <-ctx.Done():
	}
	shutdownContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	return server.Shutdown(shutdownContext)
}

// healthcheck is the container health probe: distroless has no shell or curl to run instead.
func healthcheck() error {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1"+os.Getenv("LISTEN_ADDRESS")+"/jwks", nil) //nolint:gosec // G704: the URL is this container's own listen address
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(request) //nolint:gosec // G704: same URL
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: %s", response.Status)
	}
	return nil
}
```

Notes on the files: Traefik's own entrypoint `traefik` defaults to `:8080` and collides with `web:8080`, hence `:8082` and `ping.entryPoint: traefik` (`traefik healthcheck` reads `/etc/traefik/traefik.yml`). The password-like values are test fixtures (`gitleaks`-style scanners may need an allowlist for `test/e2e/compose/compose.yml`). To swap in WP2's handler replace the body of `run` between the config load and the `http.Server` with `fakeprovider.NewOIDCHandler(&fakeprovider.OIDCOptions{...})` (field names per WP2) and keep the signal handling and `healthcheck`. The fake must be registered with the redirect URI `http://127.0.0.1:${E2E_APP_PORT}/auth/oidc/oidc/callback` (`{prefix}/oidc/<OIDC_NAME>/callback`, both defaults) and the post-logout URI `EXTERNAL_URL/`.

### 5.4 Go harness (verified against the stand-in)

The client behaves like a browser (cookie jar) but returns every redirect to the test (`http.ErrUseLastResponse`), so each hop is asserted. The tests hit real `http://127.0.0.1:<port>` URLs, so there is no dialer mapping and no cross-host redirect to worry about; "does not auto-follow" is what makes the hops visible.


`test/e2e/compose/browser_test.go`

```go
//go:build e2e

package compose

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	maxBodyBytes = 1 << 20
	readyTimeout = 60 * time.Second
)

// The stack listens on loopback ports that `just test-e2e` picks and exports; see compose.yml.
var (
	appURL    = "http://127.0.0.1:" + os.Getenv("E2E_APP_PORT")
	issuerURL = "http://127.0.0.1:" + os.Getenv("E2E_ISSUER_PORT")
)

func TestMain(m *testing.M) {
	if os.Getenv("E2E_APP_PORT") == "" || os.Getenv("E2E_ISSUER_PORT") == "" {
		fmt.Fprintln(os.Stderr, "E2E_APP_PORT and E2E_ISSUER_PORT are not set: run `just test-e2e`")
		os.Exit(1)
	}
	// `docker compose up --wait` returns when the containers run; poll until the routes answer.
	for _, target := range []string{issuerURL + "/.well-known/openid-configuration", appURL + "/auth/health"} {
		if err := waitFor(target); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

func waitFor(target string) error {
	deadline := time.Now().Add(readyTimeout)
	client := &http.Client{Timeout: 2 * time.Second}
	lastProblem := "no answer"
	for time.Now().Before(deadline) {
		request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
			lastProblem = response.Status
		} else {
			lastProblem = err.Error()
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("stack not ready: %s did not answer 200 within %s (last: %s)", target, readyTimeout, lastProblem)
}

// browser is an HTTP client with a cookie jar that behaves like a browser, except that it never follows
// a redirect by itself: the test sees every hop and asserts on it.
type browser struct {
	t      *testing.T
	client *http.Client
}

// page is one response, fully read.
type page struct {
	status   int
	location string
	header   http.Header
	body     string
}

func newBrowser(t *testing.T) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &browser{t: t, client: &http.Client{
		Jar:           jar,
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (b *browser) get(target string, header http.Header) page {
	b.t.Helper()
	request, err := http.NewRequestWithContext(b.t.Context(), http.MethodGet, target, nil)
	require.NoError(b.t, err)
	for name, values := range header {
		request.Header[name] = values // keep non-canonical names such as X_Forwarded_Host as sent
	}
	response, err := b.client.Do(request)
	require.NoError(b.t, err)
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes))
	require.NoError(b.t, err)
	return page{status: response.StatusCode, location: response.Header.Get("Location"), header: response.Header, body: string(body)}
}

// signIn walks the whole login for target and returns the browser holding the session. The four hops
// are redirects: target to the login, the login to the issuer, the issuer to the callback and the
// callback back to target.
func signIn(t *testing.T, target string) *browser {
	t.Helper()
	person := newBrowser(t)
	location := appURL + target
	for range 4 {
		hop := person.get(location, nil)
		require.Equal(t, http.StatusFound, hop.status, hop.body)
		location = hop.location
	}
	require.Equal(t, appURL+target, location)
	return person
}

func queryOf(t *testing.T, location string) url.Values {
	t.Helper()
	parsed, err := url.Parse(location)
	require.NoError(t, err)
	return parsed.Query()
}
```

`test/e2e/compose/flows_test.go`

```go
//go:build e2e

package compose

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnonymousBrowserIsSentThroughTheIssuerWithPKCEStateAndNonce(t *testing.T) {
	person := newBrowser(t)

	toLogin := person.get(appURL+"/whoami?x=1", nil)
	require.Equal(t, http.StatusFound, toLogin.status)
	// absolute: Traefik resolves a relative Location against the internal forwardauth address
	require.Equal(t, appURL+"/auth/oidc/oidc/login?return_to=%2Fwhoami%3Fx%3D1", toLogin.location)

	toIssuer := person.get(toLogin.location, nil)
	require.Equal(t, http.StatusFound, toIssuer.status)
	require.True(t, strings.HasPrefix(toIssuer.location, issuerURL+"/authorize?"), toIssuer.location)
	query := queryOf(t, toIssuer.location)
	require.Equal(t, "S256", query.Get("code_challenge_method"))
	require.NotEmpty(t, query.Get("code_challenge"))
	require.NotEmpty(t, query.Get("state"))
	require.NotEmpty(t, query.Get("nonce"))
	require.Equal(t, appURL+"/auth/oidc/oidc/callback", query.Get("redirect_uri"))
}

func TestLoginEndsAtTheAppWhichSeesTheIdentityAsABearerToken(t *testing.T) {
	person := signIn(t, "/whoami?x=1")

	hop := person.get(appURL+"/whoami?x=1", nil)

	require.Equal(t, http.StatusOK, hop.status)
	require.Contains(t, hop.body, "Authorization: Bearer ")
	// verify the token with jwt.NewVerifier(ctx, &jwt.VerifierOptions{JWKSURL: appURL + "/auth/jwks", ...})
}

func TestAnAPICallWithoutSessionIs401JSON(t *testing.T) {
	hop := newBrowser(t).get(appURL+"/api/things", nil)

	require.Equal(t, http.StatusUnauthorized, hop.status)
	require.Contains(t, hop.header.Get("Content-Type"), "application/json")
	require.Contains(t, hop.body, `"code":"unauthenticated"`)
}

func TestAfterLogoutTheAppRedirectsToTheLoginAgain(t *testing.T) {
	person := signIn(t, "/whoami")

	toIssuer := person.get(appURL+"/auth/oidc/oidc/logout", nil)
	require.Equal(t, http.StatusFound, toIssuer.status)
	require.True(t, strings.HasPrefix(toIssuer.location, issuerURL+"/end_session?"), toIssuer.location)
	backToApp := person.get(toIssuer.location, nil)
	require.Equal(t, http.StatusFound, backToApp.status)
	require.True(t, strings.HasPrefix(backToApp.location, appURL+"/"), backToApp.location)

	require.Equal(t, http.StatusFound, person.get(appURL+"/whoami", nil).status)
}

func TestAuthorizationHeaderFromTheClientNeverReachesTheApp(t *testing.T) {
	forged := http.Header{"Authorization": {"Bearer forged-by-the-client"}}

	anonymous := newBrowser(t).get(appURL+"/whoami", forged)
	require.Equal(t, http.StatusFound, anonymous.status, "a forged header is not a login")

	hop := signIn(t, "/whoami").get(appURL+"/whoami", forged)
	require.Equal(t, http.StatusOK, hop.status)
	require.Contains(t, hop.body, "Authorization: Bearer stub.")
	require.NotContains(t, hop.body, "forged-by-the-client")
}

func TestForwardedHeadersFromTheClientDoNotSteerTheRedirect(t *testing.T) {
	hop := newBrowser(t).get(appURL+"/whoami", http.Header{"X-Forwarded-Host": {"evil.example"}, "X-Forwarded-Proto": {"https"}, "X-Forwarded-Uri": {"/admin"}})

	require.Equal(t, http.StatusFound, hop.status)
	require.Equal(t, appURL+"/auth/oidc/oidc/login?return_to=%2Fwhoami", hop.location)
}

func TestACallbackWithAForgedStateIsRefused(t *testing.T) {
	person := newBrowser(t)
	toLogin := person.get(appURL+"/whoami", nil)
	toIssuer := person.get(toLogin.location, nil)
	toCallback := person.get(toIssuer.location, nil)

	forged := person.get(strings.Replace(toCallback.location, "state=", "state=forged", 1), nil)

	require.Equal(t, http.StatusBadRequest, forged.status)
	require.Equal(t, http.StatusFound, person.get(appURL+"/whoami", nil).status, "still not logged in")
}
```

Adapt when the real binary exists: the bearer assertion in `TestLoginEndsAtTheAppWhichSeesTheIdentityAsABearerToken` should read the `Authorization: Bearer <jwt>` line from the whoami body and verify it with `jwt.NewVerifier(ctx, &jwt.VerifierOptions{JWKSURL: appURL + "/auth/jwks", Issuer: <JWT_ISSUER>})` (design 8.2(b)); `TestAuthorizationHeaderFromTheClientNeverReachesTheApp` should assert the same instead of the `stub.` prefix. The assertions on `Location` (absolute login URL with `return_to`) are design F12 and caught the relative-redirect trap in verification. The stand-in used `forwardauth_session` as cookie name (design 6.2 default).

### 5.5 `just` recipes

The `test-e2e` below is the verified compose part. To merge with suite (a) of design 8.3 add the lines marked `# suite (a)`; both suites then land in one `sandbox/e2e.json`. Compose is brought down also when the tests fail (`trap`), after printing the last 100 log lines of the stack on failure. Measured: warm run about 7 s, first run with image builds about 25 s, `compose down` 0.7 s (it is 10 s if a container ignores SIGTERM). On the GitHub runner expect pulls of `golang:1.26`, `traefik`, `whoami` plus two image builds (about 1 to 3 min cold); Docker Hub anonymous pull limits are the one external risk, `mirror.gcr.io/library/<image>` is a drop-in for `golang` and `traefik` if it ever bites.

```just
compose := "docker compose -f test/e2e/compose/compose.yml"

# End-to-end tests: binary subprocess suite and the compose suite; the stack is always stopped
test-e2e:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p sandbox/coverage
    trap 'status=$?; [ "$status" -eq 0 ] || {{compose}} logs --no-color --tail=100; {{compose}} down --volumes --remove-orphans' EXIT
    go build -cover -o sandbox/forwardauth-e2e ./cmd/forwardauth   # suite (a)
    free_port() { local port; while port=$((20000 + RANDOM % 20000)); (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; do :; done; echo "$port"; }
    export E2E_APP_PORT="$(free_port)" E2E_ISSUER_PORT="$(free_port)"
    export JWT_PRIVATE_KEY="$(openssl genrsa 2048 2>/dev/null)"
    {{compose}} up --detach --build --wait
    export E2E_BINARY={{justfile_directory()}}/sandbox/forwardauth-e2e GOCOVERDIR={{justfile_directory()}}/sandbox/coverage   # suite (a)
    {{gotestsum}} --format testname --jsonfile sandbox/e2e.json -- -tags e2e -count=1 ./test/e2e/...
    go tool covdata percent -i=sandbox/coverage   # suite (a)
```

Facts: `openssl genrsa 2048` yields a PEM key (PKCS#8 on OpenSSL 3, PKCS#1 on LibreSSL; the signer accepts both); the multi-line value passes through compose interpolation intact (`JWT_PRIVATE_KEY: ${JWT_PRIVATE_KEY:?...}`). `gotestsum` prints `EMPTY test/e2e/compose/fakeissuer` for the package without tests; harmless. Each `compose.yml` variable uses `:?` so running compose by hand without the variables fails loudly. To rerun tests against a stack you started by hand: `export E2E_APP_PORT=... E2E_ISSUER_PORT=... ; go test -tags e2e ./test/e2e/compose/`. Without the variables the package exits 1 with a message instead of skipping (TST-011: no silent skips).

### 5.6 Traefik behaviour (verified on v3.7.16, file provider)

- Traefik **warns at startup** about three unset options on this setup: `aliasHeadersStrategy` (entrypoint; `X_Auth_User` style headers alias real ones for CGI-like backends), `forwardAuth.maxResponseBodySize` and `forwardAuth.trustForwardHeader`. All three are set in the files above. One warning remains ("can reject some encoded characters in the request path", `encodedCharacters` options); it concerns RFC 3986 strictness of backends, harmless here.
- `trustForwardHeader: false`: a client-sent `X-Forwarded-Host: evil.example` / `X-Forwarded-Proto: https` / `X-Forwarded-Uri` does not reach forwardauth, the redirect is built from Traefik's own values (test `TestForwardedHeadersFromTheClientDoNotSteerTheRedirect`). Set it `true` only when another trusted proxy sits in front, and document that in [docs/wiki/Forward-Auth-Configuration.md](wiki/Forward-Auth-Configuration.md#traefik-settings).
- `authResponseHeaders: [Authorization]`: the client's `Authorization` is deleted first and replaced by the auth response's value; when the auth response has none (JWT disabled) it is simply gone. A forged header never reaches the upstream, with or without a session (tests `TestAuthorizationHeaderFromTheClientNeverReachesTheApp`; the JWT-disabled case was checked by hand). Note: the client's `Authorization` **does** reach forwardauth (it is the API-key credential, F10).
- A non-2xx answer of forwardauth (302 with `Location`, `Set-Cookie`, 401 JSON body) goes to the client. A **relative** `Location` is resolved against the auth address and reaches the browser as `http://forwardauth:8080/...`: the login URL must be absolute (design F12 step 3 is right).
- The longer `/auth` router needs no middleware and no explicit priority here because the protected routers are `/whoami` and `/api`. If the protected app owns `/`, the auth router must outrank it (design 6.3: longer rule wins, or set `priority`).
- Compose `up --wait` plus `service_healthy` worked on local Compose 2.10.2 (Docker 20.10.17) and needs nothing newer than the runner's 2.38.2.

### 5.7 Fake GitHub

Suite (a) uses `fakeprovider.StartGitHub` in the test process (design 8.2(a) scenario 8): no container, plain HTTP on 127.0.0.1 is already allowed. The reference fake of appendix B covers `/login/oauth/authorize` (state and S256 required), `POST /login/oauth/access_token` (verifier checked, GitHub-style 200 with an error body on failure), `/api/v3/user`, `/api/v3/user/teams`, `/api/v3/user/orgs`, one host for OAuth and API like GitHub Enterprise Server (`GITHUB_AUTHORIZE_URL`, `GITHUB_TOKEN_URL`, `GITHUB_API_URL=.../api/v3`). For a compose GitHub run later: second forwardauth service with `PROVIDER=github`, `network_mode: service:github` on a fake-GitHub container that owns another free port, `EXTERNAL_URL` on a second Traefik entrypoint or a path-separated router; the GitHub URLs must be `http://127.0.0.1:<port>` for the same D16 reason.

## 6. Tool versions on this machine

| Tool | Local | CI (org workflow / runner) | Note |
|---|---|---|---|
| go | 1.26.3 darwin/arm64 | `setup-go` `1.26.x` (newest patch) | local is behind 1.26.10; `govulncheck` flags stdlib vulns locally (section 0.8) |
| golangci-lint | 2.11.4 (built with go1.26.1) | v2.15.0 (input default) | local is older, CI may report more; upgrade locally |
| just | 1.45.0 | 1.59.0 | recipes verified on 1.45.0, shebang recipes included |
| docker | client/server 20.10.17 (Docker Desktop, aarch64) | Docker 28.0.4 | old but sufficient for everything above |
| docker compose | v2.10.2 | 2.38.2 | `up --wait`, `network_mode: service:`, `${VAR:?msg}` verified on 2.10.2 |
| docker buildx | v0.9.1 | 0.38.1 | `--platform` cross build verified |
| govulncheck | v1.8.0 installed | `go run ...@v1.9.0` in the recipe | the recipe pin wins |
| gotestsum | not installed | `go run gotest.tools/gotestsum@v1.13.0` | fine, recipes use `go run` |
| jq, gh, openssl, python3 | present (OpenSSL 3.6.5) | present on runners | |

## 7. Open points for the design lead

1. D16 vs hostnames: decided above (loopback + shared namespace). If a test-only escape hatch for non-loopback `http` is added to `oidc`, the hostname variant (names like `app.e2e.test`, `DialContext` mapping, network aliases on Traefik) is a drop-in and was verified as well; say so and the stack files change in three places.
2. `debian13` vs `debian12` runtime image, and `:main` tag (section 0.3, 0.4).
3. `DisableDotEnv` for the image: design 6.2 keeps `.env` loading ("dev only, the image has none"); config's README recommends `DisableDotEnv: true` in production. An empty working directory in the image makes it harmless; the choice is the lead's.
4. Org-level Actions policy and package visibility could not be read (needs `admin:org`); first release needs the manual "make public" step (section 4.3).
5. Suite (a) needs `fakeprovider` handlers with the same strictness as the contract in 5.1; otherwise it cannot prove PKCE/state/nonce are always sent.

## Appendix A: reference fake OIDC issuer (stdlib only, verified)

Where it lives in the verified tree: `internal/fakeissuer/` (tagless, usable from `httptest` unit tests and from the container `main`). Design puts the equivalent into `internal/fakeprovider/oidc.go` (WP2); this one signs RS256 with the standard library, so it has no jwx dependency. Lint-clean with the baseline (`golangci-lint` 2.11.4), `go test -race` green, 71.6% statement coverage (it is test support, excluded from the gate by the `/internal/fake` filter).


`internal/fakeissuer/fakeissuer.go`

```go
// Package fakeissuer is an OpenID Connect provider for tests. It speaks just enough of the protocol
// for an authorization code client with PKCE: discovery, JWKS, authorize, token, userinfo and end
// session. It is strict on purpose: authorize rejects a request without state, nonce and an S256 code
// challenge, and the token endpoint verifies the code verifier, so a client that skips one fails.
//
// Nobody types a password: authorize logs in the user named by the UserCookie cookie, or DefaultUser.
// Tokens are signed with RS256 by a key generated in New. Faults make the tokens invalid in one chosen
// way, so tests can check that the client rejects them.
package fakeissuer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"
)

// UserCookie names the cookie that selects the user to log in. A test sets it on the issuer's host.
const UserCookie = "e2e_user"

const (
	tokenLifetime = 5 * time.Minute
	maxFormBytes  = 1 << 16
)

// User is an identity the issuer can log in.
type User struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
}

// DefaultUsers returns the users the end-to-end stack and its tests share, by login name.
func DefaultUsers() map[string]User {
	return map[string]User{
		"alice": {Subject: "sub-alice", Email: "alice@example.test", Name: "Alice Admin", Groups: []string{"admins", "staff"}},
		"bob":   {Subject: "sub-bob", Email: "bob@example.test", Name: "Bob Builder", Groups: []string{"staff"}},
	}
}

// Faults make the issuer's tokens invalid in one specific way. Set them with Issuer.SetFaults or
// POST /_control/faults and clear them with DELETE /_control/faults.
type Faults struct {
	WrongNonce    bool `json:"wrong_nonce"`
	Expired       bool `json:"expired"`
	WrongAudience bool `json:"wrong_audience"`
	WrongIssuer   bool `json:"wrong_issuer"`
	BadSignature  bool `json:"bad_signature"`
}

// Options configures New.
type Options struct {
	// Issuer is the URL clients and browsers use to reach the provider, without a trailing slash. It is
	// also the "iss" claim, so it must be identical wherever it is read.
	Issuer                 string
	ClientID               string
	ClientSecret           string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	// Users by login name. DefaultUser must be one of them.
	Users       map[string]User
	DefaultUser string
}

// Issuer is the provider. It is safe for concurrent use.
type Issuer struct {
	options *Options
	key     *rsa.PrivateKey
	keyID   string

	mutex  sync.Mutex
	codes  map[string]authorization
	tokens map[string]User
	faults Faults
}

type authorization struct {
	user        User
	nonce       string
	challenge   string
	redirectURI string
}

// New returns an issuer with a fresh signing key.
func New(options *Options) (*Issuer, error) {
	if options.Issuer == "" || options.ClientID == "" {
		return nil, errors.New("fakeissuer: Issuer and ClientID are required")
	}
	if _, found := options.Users[options.DefaultUser]; !found {
		return nil, fmt.Errorf("fakeissuer: default user %q is not in Users", options.DefaultUser)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("fakeissuer: generate key: %writer", err)
	}
	return &Issuer{
		options: options,
		key:     key,
		keyID:   randomToken(8),
		codes:   map[string]authorization{},
		tokens:  map[string]User{},
	}, nil
}

// SetFaults replaces the active faults.
func (i *Issuer) SetFaults(faults Faults) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.faults = faults
}

// Handler serves every endpoint.
func (i *Issuer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", i.discovery)
	mux.HandleFunc("GET /jwks", i.jwks)
	mux.HandleFunc("GET /authorize", i.authorize)
	mux.HandleFunc("POST /token", i.token)
	mux.HandleFunc("GET /userinfo", i.userinfo)
	mux.HandleFunc("GET /end_session", i.endSession)
	mux.HandleFunc("POST /_control/faults", i.setFaults)
	mux.HandleFunc("DELETE /_control/faults", func(writer http.ResponseWriter, _ *http.Request) {
		i.SetFaults(Faults{})
		writer.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func (i *Issuer) discovery(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{
		"issuer":                                i.options.Issuer,
		"authorization_endpoint":                i.options.Issuer + "/authorize",
		"token_endpoint":                        i.options.Issuer + "/token",
		"jwks_uri":                              i.options.Issuer + "/jwks",
		"userinfo_endpoint":                     i.options.Issuer + "/userinfo",
		"end_session_endpoint":                  i.options.Issuer + "/end_session",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
	})
}

func (i *Issuer) jwks(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": i.keyID,
		"n": base64.RawURLEncoding.EncodeToString(i.key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(i.key.E)).Bytes()),
	}}})
}

func (i *Issuer) authorize(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	redirectURI := query.Get("redirect_uri")
	if query.Get("client_id") != i.options.ClientID || !slices.Contains(i.options.RedirectURIs, redirectURI) {
		http.Error(writer, "unknown client_id or unregistered redirect_uri", http.StatusBadRequest) // never redirect to it
		return
	}
	if problem := authorizeProblem(query); problem != "" {
		redirectWith(writer, request, redirectURI, url.Values{"error": {"invalid_request"}, "error_description": {problem}, "state": {query.Get("state")}})
		return
	}
	user, found := i.loginUser(request)
	if !found {
		http.Error(writer, "unknown "+UserCookie+" cookie", http.StatusBadRequest)
		return
	}
	code := randomToken(16)
	i.mutex.Lock()
	i.codes[code] = authorization{user: user, nonce: query.Get("nonce"), challenge: query.Get("code_challenge"), redirectURI: redirectURI}
	i.mutex.Unlock()
	redirectWith(writer, request, redirectURI, url.Values{"code": {code}, "state": {query.Get("state")}})
}

// authorizeProblem names what a strict client must not omit, or returns "".
func authorizeProblem(query url.Values) string {
	switch {
	case query.Get("response_type") != "code":
		return "response_type must be code"
	case query.Get("code_challenge") == "" || query.Get("code_challenge_method") != "S256":
		return "PKCE with S256 is required"
	case query.Get("state") == "":
		return "state is required"
	case query.Get("nonce") == "":
		return "nonce is required"
	default:
		return ""
	}
}

func (i *Issuer) loginUser(request *http.Request) (User, bool) {
	name := i.options.DefaultUser
	if cookie, err := request.Cookie(UserCookie); err == nil {
		name = cookie.Value
	}
	user, found := i.options.Users[name]
	return user, found
}

func (i *Issuer) token(writer http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(writer, request.Body, maxFormBytes)
	if err := request.ParseForm(); err != nil {
		oauthError(writer, "invalid_request", "unreadable form")
		return
	}
	clientID, clientSecret, basic := request.BasicAuth()
	if !basic {
		clientID, clientSecret = request.PostForm.Get("client_id"), request.PostForm.Get("client_secret")
	}
	if clientID != i.options.ClientID || clientSecret != i.options.ClientSecret {
		writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if request.PostForm.Get("grant_type") != "authorization_code" {
		oauthError(writer, "unsupported_grant_type", "only authorization_code is implemented")
		return
	}
	grant, found := i.takeCode(request.PostForm.Get("code")) // a code works once
	switch {
	case !found:
		oauthError(writer, "invalid_grant", "unknown or reused code")
	case grant.redirectURI != request.PostForm.Get("redirect_uri"):
		oauthError(writer, "invalid_grant", "redirect_uri differs from the authorize request")
	case challengeOf(request.PostForm.Get("code_verifier")) != grant.challenge:
		oauthError(writer, "invalid_grant", "PKCE verification failed")
	default:
		i.issueTokens(writer, grant)
	}
}

func (i *Issuer) takeCode(code string) (authorization, bool) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	grant, found := i.codes[code]
	delete(i.codes, code)
	return grant, found
}

func (i *Issuer) issueTokens(writer http.ResponseWriter, grant authorization) {
	i.mutex.Lock()
	faults := i.faults
	i.mutex.Unlock()

	now := time.Now()
	idToken, err := i.sign(idClaims(i.options, grant, now, faults), faults.BadSignature)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	accessClaims := idClaims(i.options, grant, now, faults)
	delete(accessClaims, "nonce")
	accessClaims["scope"] = "openid profile email groups"
	accessClaims["jti"] = randomToken(8)
	accessToken, err := i.sign(accessClaims, faults.BadSignature)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	i.mutex.Lock()
	i.tokens[accessToken] = grant.user
	i.mutex.Unlock()
	writeJSON(writer, http.StatusOK, map[string]any{
		"access_token": accessToken, "id_token": idToken, "token_type": "Bearer",
		"expires_in": int(tokenLifetime.Seconds()), "scope": "openid profile email groups",
	})
}

func idClaims(options *Options, grant authorization, now time.Time, faults Faults) map[string]any {
	claims := map[string]any{
		"iss": options.Issuer, "sub": grant.user.Subject, "aud": options.ClientID,
		"iat": now.Unix(), "auth_time": now.Unix(), "exp": now.Add(tokenLifetime).Unix(),
		"nonce": grant.nonce, "email": grant.user.Email, "email_verified": true,
		"name": grant.user.Name, "preferred_username": grant.user.Name, "groups": grant.user.Groups,
	}
	if faults.WrongNonce {
		claims["nonce"] = "not-the-nonce-you-sent"
	}
	if faults.Expired {
		claims["iat"], claims["exp"] = now.Add(-2*tokenLifetime).Unix(), now.Add(-tokenLifetime).Unix()
	}
	if faults.WrongAudience {
		claims["aud"] = "another-client"
	}
	if faults.WrongIssuer {
		claims["iss"] = options.Issuer + "/other"
	}
	return claims
}

func (i *Issuer) userinfo(writer http.ResponseWriter, request *http.Request) {
	bearer := request.Header.Get("Authorization")
	i.mutex.Lock()
	user, found := i.tokens[bearer[min(len("Bearer "), len(bearer)):]]
	i.mutex.Unlock()
	if !found {
		writer.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"sub": user.Subject, "email": user.Email, "name": user.Name, "groups": user.Groups})
}

func (i *Issuer) endSession(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	target := query.Get("post_logout_redirect_uri")
	if !slices.Contains(i.options.PostLogoutRedirectURIs, target) {
		_, _ = fmt.Fprintln(writer, "logged out")
		return
	}
	redirectWith(writer, request, target, url.Values{"state": {query.Get("state")}})
}

func (i *Issuer) setFaults(writer http.ResponseWriter, request *http.Request) {
	var faults Faults
	if err := json.NewDecoder(request.Body).Decode(&faults); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	i.SetFaults(faults)
	writer.WriteHeader(http.StatusNoContent)
}

// sign returns a compact RS256 JWT. badSignature flips the last bit, so verification must fail.
func (i *Issuer) sign(claims map[string]any, badSignature bool) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": i.keyID})
	if err != nil {
		return "", fmt.Errorf("fakeissuer: encode header: %writer", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("fakeissuer: encode claims: %writer", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("fakeissuer: sign: %writer", err)
	}
	if badSignature {
		signature[len(signature)-1] ^= 1
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func challengeOf(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func redirectWith(writer http.ResponseWriter, request *http.Request, target string, values url.Values) {
	parsed, err := url.Parse(target)
	if err != nil {
		http.Error(writer, "bad redirect uri", http.StatusBadRequest)
		return
	}
	query := parsed.Query()
	for key, list := range values {
		query[key] = list
	}
	parsed.RawQuery = query.Encode()
	http.Redirect(writer, request, parsed.String(), http.StatusFound)
}

func oauthError(writer http.ResponseWriter, code, description string) {
	writeJSON(writer, http.StatusBadRequest, map[string]string{"error": code, "error_description": description})
}

func writeJSON(writer http.ResponseWriter, status int, body any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(body) // the client hung up: nothing left to do
}

func randomToken(size int) string {
	buffer := make([]byte, size)
	_, _ = rand.Read(buffer) // never fails since Go 1.24
	return base64.RawURLEncoding.EncodeToString(buffer)
}
```

`internal/fakeissuer/fakeissuer_test.go`

```go
package fakeissuer_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth/internal/fakeissuer"
)

const (
	redirectURI = "http://app.test/callback"
	verifier    = "a-long-random-code-verifier-for-the-test-0123456789"
)

func newIssuer(t *testing.T) (*fakeissuer.Issuer, *httptest.Server) {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	issuer, err := fakeissuer.New(&fakeissuer.Options{
		Issuer: "http://" + server.Listener.Addr().String(), ClientID: "client", ClientSecret: "secret",
		RedirectURIs: []string{redirectURI}, PostLogoutRedirectURIs: []string{"http://app.test/bye"},
		Users: fakeissuer.DefaultUsers(), DefaultUser: "alice",
	})
	require.NoError(t, err)
	server.Config.Handler = issuer.Handler()
	server.Start()
	t.Cleanup(server.Close)
	return issuer, server
}

func noRedirects() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// redirect is what a browser would see after one request, without following it.
type redirect struct {
	status   int
	location string
}

func authorize(t *testing.T, server *httptest.Server, params url.Values, user string) redirect {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/authorize?"+params.Encode(), nil)
	require.NoError(t, err)
	if user != "" {
		request.AddCookie(&http.Cookie{Name: fakeissuer.UserCookie, Value: user})
	}
	response, err := noRedirects().Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	return redirect{status: response.StatusCode, location: response.Header.Get("Location")}
}

func validParams() url.Values {
	digest := sha256.Sum256([]byte(verifier))
	return url.Values{
		"client_id": {"client"}, "redirect_uri": {redirectURI}, "response_type": {"code"}, "scope": {"openid"},
		"state": {"s1"}, "nonce": {"n1"}, "code_challenge_method": {"S256"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])},
	}
}

func exchange(t *testing.T, server *httptest.Server, code, codeVerifier string) (int, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {codeVerifier}}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("client", "secret")
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	var body map[string]any
	require.NoError(t, json.NewDecoder(response.Body).Decode(&body))
	return response.StatusCode, body
}

func codeFrom(t *testing.T, outcome redirect) string {
	t.Helper()
	require.Equal(t, http.StatusFound, outcome.status)
	location, err := url.Parse(outcome.location)
	require.NoError(t, err)
	require.Equal(t, "s1", location.Query().Get("state"))
	return location.Query().Get("code")
}

// verifyAndDecode checks the RS256 signature against the published JWKS and returns the claims.
func verifyAndDecode(t *testing.T, server *httptest.Server, token string) (map[string]any, bool) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/jwks", nil)
	require.NoError(t, err)
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	var jwks struct{ Keys []struct{ N, E string } }
	require.NoError(t, json.NewDecoder(response.Body).Decode(&jwks))
	modulus, err := base64.RawURLEncoding.DecodeString(jwks.Keys[0].N)
	require.NoError(t, err)
	exponent, err := base64.RawURLEncoding.DecodeString(jwks.Keys[0].E)
	require.NoError(t, err)
	key := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(new(big.Int).SetBytes(exponent).Int64())}

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	valid := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) == nil
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims, valid
}

func TestAuthorizationCodeFlowWithPKCE(t *testing.T) {
	_, server := newIssuer(t)

	code := codeFrom(t, authorize(t, server, validParams(), "bob"))
	status, body := exchange(t, server, code, verifier)

	require.Equal(t, http.StatusOK, status)
	claims, valid := verifyAndDecode(t, server, body["id_token"].(string))
	require.True(t, valid)
	require.Equal(t, "n1", claims["nonce"])
	require.Equal(t, "sub-bob", claims["sub"])
	require.Equal(t, "client", claims["aud"])
	require.Equal(t, server.URL, claims["iss"])
}

func TestTheTokenEndpointRejectsAWrongVerifierAndAReusedCode(t *testing.T) {
	_, server := newIssuer(t)

	status, _ := exchange(t, server, codeFrom(t, authorize(t, server, validParams(), "")), "not-the-verifier")
	require.Equal(t, http.StatusBadRequest, status)

	code := codeFrom(t, authorize(t, server, validParams(), ""))
	status, _ = exchange(t, server, code, verifier)
	require.Equal(t, http.StatusOK, status)
	status, _ = exchange(t, server, code, verifier)
	require.Equal(t, http.StatusBadRequest, status, "a code works once")
}

func TestAuthorizeRejectsAClientThatSkipsPKCEStateOrNonce(t *testing.T) {
	_, server := newIssuer(t)
	for _, omitted := range []string{"code_challenge", "state", "nonce"} {
		params := validParams()
		params.Del(omitted)
		outcome := authorize(t, server, params, "")
		require.Equal(t, http.StatusFound, outcome.status, omitted)
		require.Contains(t, outcome.location, "error=invalid_request", omitted)
	}
}

func TestAuthorizeNeverRedirectsToAnUnregisteredURI(t *testing.T) {
	_, server := newIssuer(t)
	params := validParams()
	params.Set("redirect_uri", "http://evil.test/callback")

	require.Equal(t, http.StatusBadRequest, authorize(t, server, params, "").status)
}

func TestFaultsBreakTheIDToken(t *testing.T) {
	issuer, server := newIssuer(t)
	issuer.SetFaults(fakeissuer.Faults{WrongNonce: true, BadSignature: true})

	_, body := exchange(t, server, codeFrom(t, authorize(t, server, validParams(), "")), verifier)

	claims, valid := verifyAndDecode(t, server, body["id_token"].(string))
	require.False(t, valid)
	require.NotEqual(t, "n1", claims["nonce"])
}

func TestEndSessionRedirectsOnlyToARegisteredURI(t *testing.T) {
	_, server := newIssuer(t)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/end_session?post_logout_redirect_uri=http://app.test/bye&state=x", nil)
	require.NoError(t, err)
	response, err := noRedirects().Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()

	require.Equal(t, http.StatusFound, response.StatusCode)
	require.Equal(t, "http://app.test/bye?state=x", response.Header.Get("Location"))
}
```

## Appendix B: reference fake GitHub (stdlib only, verified)

`internal/fakegithub/`, same conventions as appendix A; 84.4% coverage, lint-clean (one `//nolint:gosec // G704` in the test helper).


`internal/fakegithub/fakegithub.go`

```go
// Package fakegithub is a GitHub for tests: the OAuth web flow (authorize with PKCE, access token) and
// the REST calls a login needs (/user, /user/teams, /user/orgs). One host serves both, the way GitHub
// Enterprise Server does: OAuth under /login/oauth, the API under /api/v3.
//
// Like fakeissuer it is strict (state and an S256 code challenge are required, the verifier is checked)
// and nobody types a password: authorize logs in the user named by the UserCookie cookie, or DefaultUser.
package fakegithub

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
)

// UserCookie names the cookie that selects the user to log in. A test sets it on the fake's host.
const UserCookie = "e2e_user"

const maxFormBytes = 1 << 16

// Team is a membership in a GitHub team.
type Team struct {
	Organization string
	Slug         string
}

// User is an account the fake can log in.
type User struct {
	Login string
	ID    int64
	Name  string
	Email string
	Teams []Team
}

// DefaultUsers returns the users the end-to-end stack and its tests share, by login name.
func DefaultUsers() map[string]User {
	return map[string]User{
		"alice": {Login: "alice", ID: 1001, Name: "Alice Admin", Email: "alice@example.test", Teams: []Team{{"acme", "platform"}, {"acme", "everyone"}}},
		"bob":   {Login: "bob", ID: 1002, Name: "Bob Builder", Email: "bob@example.test", Teams: []Team{{"acme", "everyone"}}},
	}
}

// Options configures New.
type Options struct {
	ClientID     string
	ClientSecret string
	RedirectURIs []string
	// Users by login name. DefaultUser must be one of them.
	Users       map[string]User
	DefaultUser string
}

// GitHub is the fake. It is safe for concurrent use.
type GitHub struct {
	options *Options

	mutex  sync.Mutex
	codes  map[string]authorization
	tokens map[string]User
}

type authorization struct {
	user        User
	challenge   string
	redirectURI string
}

// New returns a fake GitHub.
func New(options *Options) (*GitHub, error) {
	if _, found := options.Users[options.DefaultUser]; !found {
		return nil, fmt.Errorf("fakegithub: default user %q is not in Users", options.DefaultUser)
	}
	if options.ClientID == "" {
		return nil, errors.New("fakegithub: ClientID is required")
	}
	return &GitHub{options: options, codes: map[string]authorization{}, tokens: map[string]User{}}, nil
}

// Handler serves the OAuth and API endpoints.
func (github *GitHub) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login/oauth/authorize", github.authorize)
	mux.HandleFunc("POST /login/oauth/access_token", github.accessToken)
	mux.HandleFunc("GET /api/v3/user", github.withUser(func(writer http.ResponseWriter, user User) {
		writeJSON(writer, map[string]any{"login": user.Login, "id": user.ID, "name": user.Name, "email": user.Email})
	}))
	mux.HandleFunc("GET /api/v3/user/teams", github.withUser(func(writer http.ResponseWriter, user User) {
		teams := make([]map[string]any, 0, len(user.Teams))
		for _, team := range user.Teams {
			teams = append(teams, map[string]any{"slug": team.Slug, "name": team.Slug, "organization": map[string]string{"login": team.Organization}})
		}
		writeJSON(writer, teams)
	}))
	mux.HandleFunc("GET /api/v3/user/orgs", github.withUser(func(writer http.ResponseWriter, user User) {
		var organizations []map[string]string
		seen := map[string]bool{}
		for _, team := range user.Teams {
			if !seen[team.Organization] {
				seen[team.Organization] = true
				organizations = append(organizations, map[string]string{"login": team.Organization})
			}
		}
		writeJSON(writer, organizations)
	}))
	return mux
}

func (github *GitHub) authorize(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	redirectURI := query.Get("redirect_uri")
	if query.Get("client_id") != github.options.ClientID || !slices.Contains(github.options.RedirectURIs, redirectURI) {
		http.Error(writer, "unknown client_id or unregistered redirect_uri", http.StatusBadRequest)
		return
	}
	if query.Get("state") == "" || query.Get("code_challenge") == "" || query.Get("code_challenge_method") != "S256" {
		http.Error(writer, "state and a PKCE S256 code challenge are required", http.StatusBadRequest)
		return
	}
	name := github.options.DefaultUser
	if cookie, err := request.Cookie(UserCookie); err == nil {
		name = cookie.Value
	}
	user, found := github.options.Users[name]
	if !found {
		http.Error(writer, "unknown "+UserCookie+" cookie", http.StatusBadRequest)
		return
	}
	code := randomToken(16)
	github.mutex.Lock()
	github.codes[code] = authorization{user: user, challenge: query.Get("code_challenge"), redirectURI: redirectURI}
	github.mutex.Unlock()

	target, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(writer, "bad redirect uri", http.StatusBadRequest)
		return
	}
	values := target.Query()
	values.Set("code", code)
	values.Set("state", query.Get("state"))
	target.RawQuery = values.Encode()
	http.Redirect(writer, request, target.String(), http.StatusFound)
}

func (github *GitHub) accessToken(writer http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(writer, request.Body, maxFormBytes)
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "unreadable form", http.StatusBadRequest)
		return
	}
	form := request.PostForm
	if form.Get("client_id") != github.options.ClientID || form.Get("client_secret") != github.options.ClientSecret {
		writeJSON(writer, map[string]string{"error": "incorrect_client_credentials"}) // GitHub answers 200 with an error body
		return
	}
	github.mutex.Lock()
	grant, found := github.codes[form.Get("code")]
	delete(github.codes, form.Get("code")) // a code works once
	github.mutex.Unlock()

	digest := sha256.Sum256([]byte(form.Get("code_verifier")))
	if !found || grant.redirectURI != form.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(digest[:]) != grant.challenge {
		writeJSON(writer, map[string]string{"error": "bad_verification_code"})
		return
	}
	token := "gho_" + randomToken(20)
	github.mutex.Lock()
	github.tokens[token] = grant.user
	github.mutex.Unlock()
	writeJSON(writer, map[string]string{"access_token": token, "token_type": "bearer", "scope": "read:user,read:org"})
}

// withUser serves an API call for the user behind the bearer token, or 401.
func (github *GitHub) withUser(serve func(http.ResponseWriter, User)) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		_, token, _ := strings.Cut(request.Header.Get("Authorization"), " ") // "Bearer x" and "token x"
		github.mutex.Lock()
		user, found := github.tokens[token]
		github.mutex.Unlock()
		if !found {
			writeJSON(writer, map[string]string{"message": "Bad credentials"}, http.StatusUnauthorized)
			return
		}
		serve(writer, user)
	}
}

func writeJSON(writer http.ResponseWriter, body any, status ...int) {
	writer.Header().Set("Content-Type", "application/json")
	for _, code := range status {
		writer.WriteHeader(code)
	}
	_ = json.NewEncoder(writer).Encode(body) // the client hung up: nothing left to do
}

func randomToken(size int) string {
	buffer := make([]byte, size)
	_, _ = rand.Read(buffer) // never fails since Go 1.24
	return base64.RawURLEncoding.EncodeToString(buffer)
}
```

`internal/fakegithub/fakegithub_test.go`

```go
package fakegithub_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth/internal/fakegithub"
)

const (
	redirectURI = "http://app.test/callback"
	verifier    = "a-long-random-code-verifier-for-the-test-0123456789"
)

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	github, err := fakegithub.New(&fakegithub.Options{
		ClientID: "client", ClientSecret: "secret", RedirectURIs: []string{redirectURI},
		Users: fakegithub.DefaultUsers(), DefaultUser: "alice",
	})
	require.NoError(t, err)
	server := httptest.NewServer(github.Handler())
	t.Cleanup(server.Close)
	return server
}

func do(t *testing.T, request *http.Request) (int, string) {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request) //nolint:gosec // G704: every URL points at the httptest server
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	var body strings.Builder
	buffer := make([]byte, 4096)
	count, _ := response.Body.Read(buffer)
	body.Write(buffer[:count])
	if response.StatusCode == http.StatusFound {
		return response.StatusCode, response.Header.Get("Location")
	}
	return response.StatusCode, body.String()
}

func TestLoginAndReadTheUserAndTeams(t *testing.T) {
	server := newServer(t)
	digest := sha256.Sum256([]byte(verifier))
	params := url.Values{
		"client_id": {"client"}, "redirect_uri": {redirectURI}, "state": {"s1"},
		"code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])},
	}
	authorize, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/login/oauth/authorize?"+params.Encode(), nil)
	require.NoError(t, err)
	authorize.AddCookie(&http.Cookie{Name: fakegithub.UserCookie, Value: "bob"})
	status, location := do(t, authorize)
	require.Equal(t, http.StatusFound, status)
	redirect, err := url.Parse(location)
	require.NoError(t, err)
	require.Equal(t, "s1", redirect.Query().Get("state"))

	form := url.Values{"client_id": {"client"}, "client_secret": {"secret"}, "code": {redirect.Query().Get("code")}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}
	exchange, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	exchange.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	status, body := do(t, exchange)
	require.Equal(t, http.StatusOK, status)
	var token struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &token))

	for path, want := range map[string]string{"/api/v3/user": `"login":"bob"`, "/api/v3/user/teams": `"slug":"everyone"`, "/api/v3/user/orgs": `"login":"acme"`} {
		call, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+path, nil)
		require.NoError(t, err)
		call.Header.Set("Authorization", "Bearer "+token.AccessToken)
		status, body = do(t, call)
		require.Equal(t, http.StatusOK, status, path)
		require.Contains(t, body, want, path)
	}
}

func TestAPIRejectsAnUnknownToken(t *testing.T) {
	server := newServer(t)
	call, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/api/v3/user", nil)
	require.NoError(t, err)
	call.Header.Set("Authorization", "token nope")

	status, _ := do(t, call)

	require.Equal(t, http.StatusUnauthorized, status)
}

func TestAuthorizeRequiresPKCEAndState(t *testing.T) {
	server := newServer(t)
	call, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/login/oauth/authorize?client_id=client&redirect_uri="+url.QueryEscape(redirectURI), nil)
	require.NoError(t, err)

	status, _ := do(t, call)

	require.Equal(t, http.StatusBadRequest, status)
}
```
