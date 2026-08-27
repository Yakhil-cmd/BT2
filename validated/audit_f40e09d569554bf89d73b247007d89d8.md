### Title
Timeout during large checkout leaves orphaned worktree directories under `--root` that are never cleaned up, causing unbounded disk (volume) exhaustion - (File: main.go)

### Summary
`repoSync.SyncRepo` creates a new worktree via `createWorktree` and performs the actual (potentially very slow) file materialization in `configureWorktree` via `git reset --hard`, both of which run under the same `--sync-timeout`-bounded `context.Context`. If an attacker pushes a commit with millions of tiny files or extremely deep nesting, the checkout can exceed `--sync-timeout`, causing `SyncRepo` to return an error. Cleanup of stale/orphaned worktrees only happens on the success path of the outer sync loop, so a worktree left behind by a timed-out checkout is never pruned, and if the attacker keeps pushing new commits each period, a new orphaned worktree directory accumulates under `--root` every cycle, exhausting the volume.

### Finding Description
The main sync loop creates a fresh `context.WithTimeout(..., *flSyncTimeout)` each iteration and calls `git.SyncRepo(ctx, ...)` [1](#0-0) . Cleanup of old worktrees (`git.cleanup(ctx)`, which calls `removeStaleWorktrees`) is invoked only inside the success branch, i.e. only when `SyncRepo` returns `err == nil` [2](#0-1) .

Inside `SyncRepo`, when the fetched remote hash differs from what is currently synced, a new worktree is created with `createWorktree` (a quick `worktree add --no-checkout`) and then materialized with `configureWorktree`, whose actual file checkout is `git reset --hard <hash> --`, run under the same timeout-bound `ctx` [3](#0-2) , plus optional submodule updates [4](#0-3) . For a commit with millions of tiny files or deep nesting, this `reset --hard` can run long enough to exceed `--sync-timeout`, causing `git.Run` to fail with a context-deadline error, which propagates straight out of `SyncRepo` [5](#0-4) .

`createWorktree` only removes the worktree directory that corresponds to the *specific hash it is about to (re)create* — via `git.removeWorktree(ctx, worktree)` where `worktree := git.worktreeFor(hash)` [6](#0-5) . It does not touch any other stale worktree directories left behind from a *previous, different* remote hash. Removal of directories for hashes other than the one currently being synced is the responsibility of `removeStaleWorktrees`, invoked only via `cleanup()` [7](#0-6) [8](#0-7) , which — per above — is unreachable while `SyncRepo` keeps failing.

Consequently, if the attacker repeatedly pushes new large/slow-to-materialize commits, roughly once per sync period (bounded by `--period`, default 10s, versus `--sync-timeout`, default 120s), each iteration: (1) fetches the new hash, (2) creates a brand-new worktree directory named for that hash, (3) times out during `reset --hard`, and (4) leaves that half-checked-out directory permanently on disk because `cleanup()` never runs on the error path and `createWorktree`'s self-cleanup only targets the hash currently in flight, not prior failed hashes. This produces unbounded growth of half-materialized worktree directories under `--root`, all of which remain inside `--root` (no write-outside-root here) but drive the volume to exhaustion.

Existing protections do not stop this: `sanityCheckWorktree`'s `dirIsEmpty`/`rev-parse HEAD`/`fsck` checks only guard whether an *existing* worktree is trusted as "current" — they never trigger a cleanup of *non-current*, never-published worktree directories left from failed attempts. `--stale-worktree-timeout` (default 0) only matters inside `removeStaleWorktrees`, which is itself gated behind a successful sync.

### Impact Explanation
This is a volume-exhaustion / permanent-unavailability class issue: an unprivileged repo pusher can force git-sync to accumulate an unbounded number of large, half-checked-out worktree directories under `--root`, consuming disk until the volume fills, which starves both git-sync (unable to complete future syncs, e.g. `git init`, fetch, or worktree operations fail with "no space left on device") and any co-tenants sharing the same volume. Because the invariant "timeouts leave no residue" does not hold, every failed sync due to a large/slow commit leaves permanent garbage rather than self-healing, and repeated pushes turn a single slow-checkout DoS into sustained, cumulative resource exhaustion.

### Likelihood Explanation
Preconditions: attacker must have push access to refs that git-sync fetches (in scope per the threat model) and must be able to produce commits whose checkout (`git reset --hard`) reliably exceeds `--sync-timeout` (default 120s) — achievable with millions of tiny files or very deep directory nesting, which is entirely attacker-controlled repo content requiring no non-default flags. The attack is repeatable each sync period as long as the attacker keeps pushing distinct large commits (or the same commit's checkout time is consistently near/over the timeout, causing intermittent failures interspersed with new pushes). No exec access, flag control, or operator cooperation needed.

### Recommendation
Decouple stale-worktree cleanup from the sync success path: always attempt `removeStaleWorktrees` (using a short-lived, independent context) at the top of `SyncRepo`/`initRepo` or in a `defer` in the outer loop regardless of whether the current sync attempt failed, so that any never-published worktree directory older than `--stale-worktree-timeout` is reclaimed even when syncs are repeatedly timing out. Additionally, consider bounding worktree checkout independently (e.g., a dedicated checkout timeout distinct from network-fetch timeout) so operators can detect and cap pathological checkouts, and emit a metric/alert when an orphaned worktree is being cleaned up so operators can see the DoS pattern.

### Proof of Concept
Integration test outline (extends the existing e2e "slow git" tests such as `e2e::error_slow_git_short_timeout` [9](#0-8) ):
1. Create a local bare repo; commit a tree with a very large number of tiny files (or deep nesting) such that `git reset --hard` on checkout reliably takes, e.g., 5s+ on the test runner.
2. Run `GIT_SYNC --period=1s --sync-timeout=1s --repo=file://$REPO --root=$ROOT --link=link &` so every sync attempt times out mid-`reset --hard`.
3. Every 1–2s, commit a *new* large tree to the repo (new hash each time) to simulate repeated attacker pushes.
4. After N periods, assert: `find "$ROOT" -mindepth 1 -maxdepth 2 -type d | wc -l` grows roughly linearly with N (unbounded orphaned worktree directories), and `assert_metric_eq "${METRIC_GOOD_SYNC_COUNT}" 0` (sync never succeeds, so `cleanup()`/`removeStaleWorktrees` is never invoked) — demonstrating disk usage under `--root` grows without bound instead of being pruned by the stale-worktree/timeout logic.

### Citations

**File:** main.go (L1052-1092)
```go
	for {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), *flSyncTimeout)

		if changed, hash, err := git.SyncRepo(ctx, syncHooks); err != nil {
			failCount++
			updateSyncMetrics(metricKeyError, start)
			if maxFails := getMaxFailures(); maxFails >= 0 && failCount >= maxFails {
				log.Error(err, "too many failures, aborting", "failCount", failCount, "maxFailures", maxFails)
				os.Exit(1)
			}
			log.Error(err, "error syncing repo, will retry", "failCount", failCount)
		} else {
			if !initialSyncDone {
				initialSyncDone = true
				waitTime = *flPeriod
				if *flInitPeriod != *flPeriod {
					log.V(0).Info("initial sync complete, switching to normal period", "initPeriod", flInitPeriod.String(), "period", flPeriod.String())
				}
			}
			// this might have been called before, but also might not have
			setRepoReady()
			// We treat the first loop as a sync, including sending hooks.
			if changed || syncCount == 0 {
				if absTouchFile != "" {
					if err := touch(absTouchFile); err != nil {
						log.Error(err, "failed to touch touch-file", "path", absTouchFile)
					} else {
						log.V(3).Info("touched touch-file", "path", absTouchFile)
					}
				}
				updateSyncMetrics(metricKeySuccess, start)
			} else {
				updateSyncMetrics(metricKeyNoOp, start)
			}
			syncCount++

			// Clean up old worktree(s) and run GC.
			if err := git.cleanup(ctx); err != nil {
				log.Error(err, "git cleanup failed")
			}
```

**File:** main.go (L1420-1441)
```go
func (git *repoSync) removeStaleWorktrees() (int, error) {
	currentWorktree, err := git.currentWorktree()
	if err != nil {
		return 0, err
	}

	git.log.V(3).Info("cleaning up stale worktrees", "currentHash", currentWorktree.Hash())

	count := 0
	err = removeDirContentsIf(git.worktreeFor("").Path(), git.log, func(fi os.FileInfo) (bool, error) {
		// delete files that are over the stale time out, and make sure to never delete the current worktree
		if fi.Name() != currentWorktree.Hash() && time.Since(fi.ModTime()) > git.staleTimeout {
			count++
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}
```

**File:** main.go (L1644-1663)
```go
func (git *repoSync) createWorktree(ctx context.Context, hash string) (worktree, error) {
	// Make a worktree for this exact git hash.
	worktree := git.worktreeFor(hash)

	// Avoid wedge cases where the worktree was created but this function
	// error'd without cleaning up.  The next time thru the sync loop fails to
	// create the worktree and bails out. This manifests as:
	//     "fatal: '/repo/root/nnnn' already exists"
	if err := git.removeWorktree(ctx, worktree); err != nil {
		return "", err
	}

	git.log.V(1).Info("adding worktree", "path", worktree.Path(), "hash", hash)
	_, _, err := git.Run(ctx, git.root, "worktree", "add", "--force", "--detach", worktree.Path().String(), hash, "--no-checkout")
	if err != nil {
		return "", err
	}

	return worktree, nil
}
```

**File:** main.go (L1727-1731)
```go
	// Reset the worktree's working copy to the specific ref.
	git.log.V(1).Info("setting worktree HEAD", "hash", hash)
	if _, _, err := git.Run(ctx, worktree.Path(), "reset", "--hard", hash, "--"); err != nil {
		return err
	}
```

**File:** main.go (L1733-1747)
```go
	// Update submodules
	// NOTE: this works for repo with or without submodules.
	if git.submodules != submodulesOff {
		git.log.V(1).Info("updating submodules")
		submodulesArgs := []string{"submodule", "update", "--init"}
		if git.submodules == submodulesRecursive {
			submodulesArgs = append(submodulesArgs, "--recursive")
		}
		if git.depth != 0 {
			submodulesArgs = append(submodulesArgs, "--depth", strconv.Itoa(git.depth))
		}
		if _, _, err := git.Run(ctx, worktree.Path(), submodulesArgs...); err != nil {
			return err
		}
	}
```

**File:** main.go (L1752-1764)
```go
// cleanup removes old worktrees and runs git's garbage collection.  The
// specified worktree is preserved.
func (git *repoSync) cleanup(ctx context.Context) error {
	// Save errors until the end.
	var cleanupErrs multiError

	// Clean up previous worktree(s).
	if n, err := git.removeStaleWorktrees(); err != nil {
		cleanupErrs = append(cleanupErrs, err)
	} else if n == 0 {
		// We didn't clean up any worktrees, so the rest of this is moot.
		return nil
	}
```

**File:** main.go (L1943-1945)
```go
		if err := git.configureWorktree(ctx, newWorktree); err != nil {
			return false, "", err
		}
```

**File:** test_e2e.sh (L1597-1607)
```shellscript
function e2e::error_slow_git_short_timeout() {
    assert_fail \
        GIT_SYNC \
            --git="/$SLOW_GIT_FETCH" \
            --one-time \
            --sync-timeout=1s \
            --repo="file://$REPO" \
            --root="$ROOT" \
            --link="link"
    assert_file_absent "$ROOT/link/file"
}
```
