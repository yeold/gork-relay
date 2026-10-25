#!/bin/sh
# Put FILE... on the Forgejo release $TAG, making the release if there is
# none yet, with $NOTES (a file) as its notes.  Files already there are
# left alone.  GitHub's release is made by GitHub Actions.
# Needs curl and jq, and FORGEJO_TOKEN:
#     TAG=v0.2 NOTES=notes.md sh release.sh out/*.exe
set -eu
: "${TAG:?}" "${FORGEJO_TOKEN:?}"
FJ=${FJ:-https://git.yeold.org/api/v1/repos/yeold/gork-relay}

fj() { curl -fsS -H "Authorization: token $FORGEJO_TOKEN" "$@"; }

if r=$(fj "$FJ/releases/tags/$TAG" 2>/dev/null); then
    id=$(printf '%s\n' "$r" | jq -r .id)
else
    id=$(jq -nc --arg tag "$TAG" --rawfile body "${NOTES:-/dev/null}" \
            '{tag_name: $tag, name: ("gork-relay " + $tag), body: $body}' |
         fj -X POST -H 'Content-Type: application/json' "$FJ/releases" -d @- |
         jq -r .id)
fi
have=$(fj "$FJ/releases/$id/assets" | jq -r '.[].name')
for f in "$@"; do
    n=$(basename "$f")
    if printf '%s\n' "$have" | grep -qx "$n"; then
        echo "forgejo: $n is there already"
        continue
    fi
    echo "forgejo: $n"
    fj -F "attachment=@$f" "$FJ/releases/$id/assets?name=$n" >/dev/null
done
