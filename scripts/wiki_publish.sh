#!/usr/bin/env bash
# Clone the GitHub wiki, copy docs/admin into it, rewrite links, and push.
# Required env: GITHUB_TOKEN, GITHUB_REPOSITORY
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
TOKEN="${GITHUB_TOKEN:?GITHUB_TOKEN is required}"
# Pin blob/tree URLs at main so a v* tag publish does not flip every wiki link
# to blob/v1.2.3 and the next main push flip them back.
BLOB="https://github.com/${REPO}/blob/main/docs"

WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

WIKI_DIR="$WORKDIR/wiki"
# Keep the token out of remote URLs so a failed clone cannot leak it in logs.
GIT_AUTH=( -c "http.https://github.com/.extraheader=AUTHORIZATION: bearer ${TOKEN}" )

clone_err="$WORKDIR/clone.err"
set +e
GIT_TERMINAL_PROMPT=0 git "${GIT_AUTH[@]}" clone --depth 1 \
  "https://github.com/${REPO}.wiki.git" "$WIKI_DIR" 2>"$clone_err"
clone_status=$?
set -e
if [[ "$clone_status" -ne 0 ]]; then
  cat "$clone_err" >&2
  echo "::error::Could not clone ${REPO}.wiki.git. Enable Settings → General → Features → Wikis (one-time), add a placeholder Home page if the wiki has never been used, then re-run this workflow."
  exit 1
fi

# Repo Markdown uses sibling .md links and ../API.md; the wiki is a separate git
# repo, so those become extensionless page names and blob URLs.
find "$WIKI_DIR" -maxdepth 1 -name '*.md' -delete
cp "$ROOT/docs/admin/"*.md "$WIKI_DIR/"
for f in "$WIKI_DIR"/*.md; do
  tmp="$(mktemp)"
  sed -E \
    -e "s|\\]\\(\\.\\./([A-Za-z0-9._-]+\\.md)(#[^)]*)?\\)|](${BLOB}/\\1\\2)|g" \
    -e "s|\\]\\(\\./([A-Za-z0-9._-]+)\\.md(#[^)]*)?\\)|](\\1\\2)|g" \
    -e "s|\\]\\(([A-Za-z0-9._-]+)\\.md(#[^)]*)?\\)|](\\1\\2)|g" \
    "$f" > "$tmp"
  mv "$tmp" "$f"
done

cat > "$WIKI_DIR/_Footer.md" <<EOF
Published from [\`docs/admin/\`](https://github.com/${REPO}/tree/main/docs/admin) in the repository. Edit those files in a pull request; this wiki is overwritten on every push to \`main\` and on every \`v*\` version tag.
EOF

if grep -nE '\]\(\.\./|\]\(\./[A-Za-z0-9._-]+\.md|\]\([A-Za-z0-9._-]+\.md' "$WIKI_DIR"/*.md; then
  echo "link rewrite left repo-style targets" >&2
  exit 1
fi

git -C "$WIKI_DIR" config user.name "github-actions[bot]"
git -C "$WIKI_DIR" config user.email "41898282+github-actions[bot]@users.noreply.github.com"

git -C "$WIKI_DIR" add -A
if git -C "$WIKI_DIR" diff --staged --quiet; then
  echo "Wiki already up to date."
  exit 0
fi

SHA="${GITHUB_SHA:-$(git -C "$ROOT" rev-parse HEAD)}"
git -C "$WIKI_DIR" commit -m "Publish administration guide from ${SHA}"
BRANCH="$(git -C "$WIKI_DIR" rev-parse --abbrev-ref HEAD)"
git -C "$WIKI_DIR" "${GIT_AUTH[@]}" push origin "HEAD:${BRANCH}"
