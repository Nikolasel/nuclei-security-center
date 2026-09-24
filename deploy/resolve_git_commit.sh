#!/bin/sh
# Print the commit that HEAD names, or nothing when it cannot be read.
#
# The backend image build uses this when GIT_COMMIT is empty. It reads HEAD,
# one ref file, and packed-refs. It does not run git, and it does not follow a
# worktree gitdir pointer (that path is outside the Docker build context).
# Usage: resolve_git_commit.sh [git-dir]
set -eu

gitdir=${1:-.git}

if [ ! -f "$gitdir/HEAD" ]; then
	exit 0
fi

first_line() {
	awk 'NR==1 { sub(/\r$/, ""); print; exit }' "$1"
}

emit() {
	value=$(printf '%s' "$1" | tr 'A-F' 'a-f')
	if printf '%s' "$value" | grep -Eq '^[0-9a-f]{7,64}$'; then
		printf '%s\n' "$value"
	fi
}

head=$(first_line "$gitdir/HEAD")
case "$head" in
"ref: "*)
	ref=${head#"ref: "}
	ref=$(printf '%s' "$ref" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
	case "$ref" in
	refs/*) ;;
	*) exit 0 ;;
	esac
	case "$ref" in
	*..* | *//* | *' '* | *'\\'* ) exit 0 ;;
	esac
	if [ -f "$gitdir/$ref" ]; then
		emit "$(first_line "$gitdir/$ref")"
		exit 0
	fi
	if [ -f "$gitdir/packed-refs" ]; then
		sha=$(awk -v ref="$ref" '$1 ~ /^[0-9a-fA-F]+$/ && $2 == ref { print $1; exit }' "$gitdir/packed-refs")
		emit "$sha"
	fi
	;;
*)
	emit "$head"
	;;
esac
exit 0
