#!/usr/bin/env bash
# Rewrite docs/admin into a wiki checkout and push.
# Required env: GITHUB_REPOSITORY, WIKI_DIR (git checkout of owner/repo.wiki)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
WIKI_DIR="${WIKI_DIR:?WIKI_DIR is required}"
# Pin blob/tree URLs at main so a v* tag publish does not flip every wiki link
# to blob/v1.2.3 and the next main push flip them back.
BLOB="https://github.com/${REPO}/blob/main/docs"

if [[ ! -d "$WIKI_DIR/.git" ]]; then
  echo "WIKI_DIR is not a git checkout: $WIKI_DIR" >&2
  echo "The Wiki workflow must check out ${REPO}.wiki first. If that clone failed, enable Settings → General → Features → Wikis and add a placeholder Home page." >&2
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
# Fail closed on a detached wiki checkout; default-branch checkout is a named ref.
BRANCH="$(git -C "$WIKI_DIR" symbolic-ref --short HEAD)"
git -C "$WIKI_DIR" push origin "HEAD:${BRANCH}"
