set shell := ["bash", "-euo", "pipefail", "-c"]

gotestsum := "go run gotest.tools/gotestsum@v1.13.0"
govulncheck := "go run golang.org/x/vuln/cmd/govulncheck@v1.9.0"
coverage_threshold := "80"
image := "ghcr.io/govengers/forwardauth"
version := `git describe --tags --always --dirty 2>/dev/null || echo dev`
excluded := "/cmd/|/examples/|/internal/fakeprovider/|/test/"

default:
    @just --list

# Vet and lint with the govengers baseline; no executable may be tracked (it would ship in every module download)
lint:
    ! git ls-files -z | xargs -0 file --mime-type | grep -E ':[[:space:]]+application/(x-mach-binary|x-executable|x-pie-executable|x-sharedlib|x-dosexec|vnd.microsoft.portable-executable)$'
    go vet ./...
    if [ -d test/e2e ]; then go vet -tags e2e ./test/e2e/...; fi
    golangci-lint run ./...

# Unit tests with -race; gates total and per-package coverage (excluding cmd, examples, fakes, tests)
test:
    mkdir -p sandbox
    {{gotestsum}} --format testname --jsonfile sandbox/unit.json -- -race -count=1 -coverprofile=sandbox/unit.raw.cover ./...
    grep -v -E '{{excluded}}' sandbox/unit.raw.cover > sandbox/unit.cover
    go tool cover -func=sandbox/unit.cover > sandbox/unit.func
    awk -v threshold={{coverage_threshold}} '/^total:/ { found = 1; sub("%", "", $3); print "coverage " $3 "%"; if ($3 + 0 < threshold) { print "coverage is below " threshold "%"; exit 1 } } END { if (!found) { print "no coverage total"; exit 1 } }' sandbox/unit.func
    awk -v threshold={{coverage_threshold}} 'NR > 1 { file = $1; sub(/:.*/, "", file); package = file; sub(/\/[^\/]*$/, "", package); statements[package] += $2; if ($3 > 0) covered[package] += $2 } END { failed = 0; for (package in statements) { percent = 100 * covered[package] / statements[package]; if (percent < threshold) { printf "%s: coverage %.1f%% is below %s%%\n", package, percent, threshold; failed = 1 } } exit failed }' sandbox/unit.cover

# Build the forward-auth binary
build:
    go build -trimpath -ldflags "-s -w -X main.version={{version}}" -o sandbox/forwardauth ./cmd/forwardauth

# Build the forward-auth image
docker-build:
    docker build -f docker/forwardauth.Dockerfile --build-arg VERSION={{version}} -t {{image}}:{{version}} .

# End-to-end: binary subprocess suite (with binary coverage) and the docker compose suite; the stack is always stopped
test-e2e:
    #!/usr/bin/env bash
    set -euo pipefail
    compose="docker compose -f test/e2e/compose/compose.yml"
    # below 32768, the start of every common ephemeral range, so no client socket of the run holds the port
    free_port() { local port; while port=$((20000 + RANDOM % 12768)); (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; do :; done; echo "$port"; }
    export E2E_APP_PORT="$(free_port)" E2E_ISSUER_PORT="$(free_port)"
    while [ "$E2E_ISSUER_PORT" = "$E2E_APP_PORT" ]; do E2E_ISSUER_PORT="$(free_port)"; done
    export JWT_PRIVATE_KEY="$(openssl genrsa 2048 2>/dev/null)"
    trap 'status=$?; [ "$status" -eq 0 ] || $compose logs --no-color --tail=100; $compose down --volumes --remove-orphans' EXIT
    rm -rf sandbox/coverage && mkdir -p sandbox/coverage
    go build -cover -o sandbox/forwardauth-e2e ./cmd/forwardauth
    $compose up --detach --build --wait
    export E2E_BINARY={{justfile_directory()}}/sandbox/forwardauth-e2e GOCOVERDIR={{justfile_directory()}}/sandbox/coverage
    {{gotestsum}} --format testname --jsonfile sandbox/e2e.json -- -tags e2e -count=1 ./test/e2e/...
    go tool covdata percent -i=sandbox/coverage

# Scan for known vulnerabilities in reachable code
vulncheck:
    {{govulncheck}} ./...

# Mirror docs/wiki to the GitHub wiki (the repository stays the source; links become GitHub URLs)
wiki:
    #!/usr/bin/env bash
    set -euo pipefail
    target="$(mktemp -d)"
    trap 'rm -rf "$target"' EXIT
    git clone --quiet https://github.com/govengers/auth.wiki.git "$target"
    find "$target" -maxdepth 1 -name '*.md' -delete
    blob=https://github.com/govengers/auth/blob/main
    for page in docs/wiki/*.md; do
        sed -E -e "s|\]\(\.\./\.\./([^)]*)\)|](${blob}/\1)|g" -e "s|\]\(\.\./([^)]*)\)|](${blob}/docs/\1)|g" -e 's|\]\(([A-Za-z-]+)\.md(#[^)]*)?\)|](\1\2)|g' "$page" > "$target/$(basename "$page")"
    done
    printf 'Mirror of [docs/wiki](%s/docs/wiki) at %s. Edit the repository, not this wiki.\n' "$blob" "$(git rev-parse --short HEAD)" > "$target/_Footer.md"
    git -C "$target" add -A
    git -C "$target" diff --cached --quiet || git -C "$target" commit --quiet -m "Mirror docs/wiki at $(git rev-parse --short HEAD)"
    git -C "$target" push --quiet

# Everything CI runs
check: lint test test-e2e vulncheck
