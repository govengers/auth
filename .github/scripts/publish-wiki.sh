#!/usr/bin/env bash
# Mirrors docs/wiki of a release tag (or of main) to the GitHub wiki; the repository stays the source. Pages are
# taken from the committed tree, never the working copy. Wiki-page links lose ".md", repo-relative links become
# github.com blob URLs of the same ref, and a footer names the ref and commit.
#
# Usage: publish-wiki.sh [<tag>|main]   default: the newest stable release tag (vX.Y.Z)
# With GITHUB_TOKEN set (CI) that token authenticates the clone and push; without it, git's credential helper.
set -euo pipefail

git fetch --quiet --tags origin main
ref="${1:-$(git tag --list 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n 1)}"
case "$ref" in
    main) source=origin/main ;;
    v*) source="refs/tags/$ref" ;;
    *) echo "publish-wiki: $ref is neither main nor a v* tag" >&2; exit 1 ;;
esac
commit="$(git rev-parse --short "$source^{commit}")"
target="$(mktemp -d)" pages="$(mktemp -d)"
trap 'rm -rf "$target" "$pages"' EXIT
git archive "$source" docs/wiki | tar -x -C "$pages"
# actions/checkout scopes its credentials to the repository's own .git, so a second clone needs the token itself.
auth=()
if [ -n "${GITHUB_TOKEN:-}" ]; then
    auth=(-c "http.https://github.com/.extraheader=AUTHORIZATION: basic $(printf 'x-access-token:%s' "$GITHUB_TOKEN" | base64 | tr -d '\n')")
fi
git ${auth[@]+"${auth[@]}"} clone --quiet https://github.com/govengers/auth.wiki.git "$target"
# an exact mirror: every page and directory goes, only the wiki's .git stays
find "$target" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
blob="https://github.com/govengers/auth/blob/$ref"
for page in "$pages"/docs/wiki/*.md; do
    sed -E -e "s|\]\(\.\./\.\./([^)]*)\)|](${blob}/\1)|g" -e "s|\]\(\.\./([^)]*)\)|](${blob}/docs/\1)|g" -e 's|\]\(([A-Za-z-]+)\.md(#[^)]*)?\)|](\1\2)|g' "$page" > "$target/$(basename "$page")"
done
printf 'Mirror of [docs/wiki](%s/docs/wiki) at %s (%s). Edit the repository, not this wiki.\n' "$blob" "$ref" "$commit" > "$target/_Footer.md"
git -C "$target" add -A
git -C "$target" diff --cached --quiet || git -C "$target" commit --quiet -m "Mirror docs/wiki at $ref ($commit)"
git -C "$target" ${auth[@]+"${auth[@]}"} push --quiet
