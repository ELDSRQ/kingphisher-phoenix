#!/usr/bin/env bash
# Merge the human-ready workstream PRs in dependency order, waiting for CI.
#
# No --admin: a PR only merges once its required checks are green (the
# repo's "wait for required CI gates" rule). Polls mergeStateStatus and
# refuses on BEHIND/DIRTY instead of papering over a broken branch.
set -euo pipefail

merge_one() {
  local n="$1"
  echo "==> PR #$n"
  while true; do
    state=$(gh pr view "$n" --json mergeStateStatus --jq .mergeStateStatus)
    case "$state" in
      CLEAN)
        break
        ;;
      BEHIND | DIRTY | BLOCKED)
        echo "    #$n not mergeable ($state) — needs a rebase/review/conflict fix"
        exit 1
        ;;
      *)
        echo "    #$n not ready ($state) — waiting for CI"
        sleep 30
        ;;
    esac
  done
  gh pr merge "$n" --merge --delete-branch
  echo "    merged #$n"
}

# 1) #32 first (the aggregation eval harness + DNS click-to-copy). #35 depends
#    on it, so after #32 lands we retarget #35 from #32's branch to main.
merge_one 32
sleep 10
gh pr edit 35 --base main
merge_one 35

# 2) Independent workstream PRs, any order.
for n in 33 34 36 37 38 25; do
  merge_one "$n"
done

echo "Done."
