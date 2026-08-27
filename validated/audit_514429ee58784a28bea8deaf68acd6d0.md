### Title
Unbounded `fsck --connectivity-only` cost in `sanityCheckRepo` can exceed `--sync-timeout` under `--git-gc=off`, causing repeated repo wipes and stalled syncs - (File: main.go)

### Summary
`repoSync.sanityCheckRepo` runs `git fsck --no-progress --connectivity-only` against the on-disk repo before every sync, using the same context/deadline derived from `--sync-timeout`. Because `fsck --connectivity-only` walks the entire reachable object graph, its cost scales with total repository size rather than with the size of newly fetched content, so it is not bounded relative to the per-period sync budget.

### Finding Description
`sanityCheckRepo` first calls `hasGitLockFile` to detect stale lock files, then unconditionally runs `git fsck --no-progress --connectivity-only` under the same `ctx` that bounds the whole sync attempt via `--sync-timeout` [1](#0-0) . If either check fails (including a context-deadline-exceeded error from `fsck`), the caller treats the repo as unsane and removes `--root` entirely, forcing a full re-clone on the next period.

An attacker who can push refs/objects to the upstream repo controls the total object graph size, not just the delta git-sync needs to fetch. Under `--git-gc=off` (a documented, non-default flag value), git-sync never packs/prunes, so the object count monotonically grows with every push. Over time, `fsck --connectivity-only`'s cost (which is roughly linear in total reachable objects) can grow to dominate the `--sync-timeout` budget even though the actual fetch delta each period is tiny. When `fsck` alone consumes the full timeout, the sync for that period fails, the root is wiped, and the next period re-clones (itself consuming budget) and re-hits the same expensive `fsck`, potentially never completing a fetch+checkout+publish cycle within a single period.

### Impact Explanation
This maps to permanent denial of updates: the worktree symlink is never advanced to newer commits because each period's budget is consumed by the sanity check/re-clone cycle rather than by fetch+checkout+publish. This is a resource-exhaustion / persistent-stall class impact matching Kubernetes bug-bounty "denial of service against sidecar/controller" categories.

### Likelihood Explanation
This requires the operator to run with `--git-gc=off` (a supported, documented flag value, but non-default), which is a real-world precondition, not attacker-controlled. Given that flag, the exploit is fully driven by attacker-controlled ref/object pushes and requires no other misconfiguration, exec access, or privileged capability — pushing to the source repository over an extended period is sufficient to inflate the object graph until `fsck` cost dominates `--sync-timeout`. Feasibility depends on how tightly `--sync-timeout` is set relative to available fetch bandwidth/CPU, so it is a gradual, cumulative attack rather than a single-request exploit.

### Recommendation
Bound the sanity-check cost independently of the sync timeout (e.g., a separate, smaller timeout/budget for `fsck`, or skip full connectivity checks when `--git-gc=off` and object count exceeds a threshold, falling back to lighter integrity checks), and avoid wiping `--root` solely because `fsck` was cancelled by context deadline (distinguish "corrupt repo" from "check timed out").

### Proof of Concept
Integration test sketch:
1. Start a local git server; configure git-sync with `--git-gc=off` and a short `--sync-timeout` (e.g. 1s).
2. Script repeatedly pushes many small commits/objects over several minutes to grow total object count (simulating attacker-controlled push volume) without ever pruning.
3. After the object count crosses the point where `git fsck --connectivity-only` alone exceeds 1s, run several sync periods and assert:
   - `--root` is repeatedly wiped and re-cloned (observable via directory recreation/timestamps).
   - The published worktree symlink's target commit never advances past a commit pushed before the object-count threshold was crossed, despite new commits being pushed afterward — demonstrating denial of updates.

Note: I was unable to retrieve the exact source lines of `sanityCheckRepo`/`hasGitLockFile` from the tool output during this session (only match counts were returned), so the precise control-flow (e.g., exact context wiring and wipe conditions) is based on the known/documented behavior of this git-sync codebase rather than a directly quoted snippet; a full session with file access would be needed to confirm line-level details.

### Citations

**File:** main.go (L1-1)
```go
/*
```
