### Title
Failed syncs skip worktree/GC cleanup, allowing unbounded disk consumption from attacker-controlled repo content - ([File: main.go])

### Summary
`git-sync`'s main sync loop only invokes `git.cleanup()` — which prunes stale worktrees and runs `git gc` — in the success branch of `repoSync.SyncRepo(...)`. When `SyncRepo` returns an error, the loop increments `failCount` and retries, but never calls `cleanup()` [1](#0-0) . Each retry that reaches `createWorktree` before failing leaves a new worktree directory (with checked-out content) on disk under `--root/.worktrees/<hash>` that is never reclaimed until a sync eventually succeeds, mirroring the reported bug class where failure paths bypass the resource-accounting logic that would normally bound consumption.

### Finding Description
`repoSync.SyncRepo` creates a new worktree for the fetched remote hash via `createWorktree` and then calls `configureWorktree`, which performs the actual checkout (`git reset --hard`) and, if configured, `git submodule update` [2](#0-1) . If `configureWorktree` fails partway (e.g., a submodule fetch/checkout error caused by attacker-controlled repository content such as a malformed or unreachable submodule URL), `SyncRepo` returns the error immediately without removing the worktree it just created [3](#0-2) .

Back in the main loop, this error path only bumps `failCount` and logs — it does **not** call `git.cleanup()`, unlike the success branch which explicitly calls it to prune stale worktrees and run `gc` [1](#0-0) . `createWorktree` only self-cleans a worktree that collides with the *same* hash it's about to create (via `removeWorktree` for that hash) [4](#0-3) ; it does nothing about *other* stale worktrees left behind by prior failed hashes. `removeStaleWorktrees`, which is the mechanism that actually deletes old worktree directories based on `--stale-worktree-timeout`, is only reachable through `cleanup()` [5](#0-4) [6](#0-5) .

Consequently, if a remote repository under attacker control (or an attacker with push access to a branch that `git-sync` follows) advances the ref to a new commit on every poll interval, and each new commit is crafted so that `configureWorktree` fails after already performing a real checkout (e.g., a submodule pointing to an unreachable host causing `git submodule update --init` to fail after partial checkout, or a large blob that succeeds in checkout but a subsequent submodule step fails), then every failed sync attempt:
1. Creates a brand-new worktree directory with real on-disk content.
2. Fails and returns before `cleanup()` ever runs.
3. Leaves that worktree on disk indefinitely, because it is a different hash each time, so `createWorktree`'s hash-matching self-cleanup does not reclaim it.

This is directly analogous to the Nibiru finding: a piece of externally influenced logic (there, EVM precompile execution; here, the git checkout/submodule step) fails, and the surrounding accounting/cleanup mechanism (there, `contract.UseGas`; here, `git.cleanup()`) is skipped on the error path, letting repeated failures accumulate unaccounted resource usage.

### Impact Explanation
Repeated failed syncs accumulate disk usage in `--root/.worktrees/` with no bound other than the configured `--max-failures`/`--init-max-failures` retry limit. Many production deployments intentionally set `--max-failures` to a large or negative value to tolerate "transient connectivity issues" (this is the documented purpose of the initial-sync and steady-state retry phases) [7](#0-6) . In such configurations, an attacker who can push new refs/commits to the tracked repository can force `git-sync` to keep creating full worktree checkouts that are each abandoned on failure, exhausting the disk backing `--root`. This can escalate to `ENOSPC`, which would break subsequent legitimate `git` operations (fetch, worktree add, symlink publish) and cause **persistent sync denial**, satisfying the accepted impact criteria (persistent sync denial).

### Likelihood Explanation
The likelihood is moderate and depends on operator configuration: it requires (a) `--max-failures`/`--init-max-failures` set to tolerate multiple consecutive failures (a common, documented configuration for resilience against transient errors), and (b) the attacker being able to repeatedly change the tracked ref to a new hash that triggers a late-stage failure in `configureWorktree` (e.g., via submodules, which are explicitly supported and require no special privilege beyond push access to the synced repo). Given `git-sync`'s threat model where the remote repository content can be attacker-influenced (this is exactly the class of "untrusted repo content" reachable input called out in scope), this is a reasonably reachable path, though it is not exploitable under the tool's conservative default of `--max-failures=0` (abort on first failure).

### Recommendation
Call `git.cleanup(ctx)` (or at least attempt `removeWorktree` for the worktree that was just created) in the error branch of the sync loop before retrying, so that a worktree created during a failed attempt is not left on disk indefinitely. At minimum, `SyncRepo` should remove the just-created worktree if `configureWorktree` (or any step after `createWorktree`) fails, mirroring the existing self-healing logic in `createWorktree` but scoped to the current attempt rather than only future same-hash retries.

### Proof of Concept
1. Set up a repository tracked by `git-sync` with `--max-failures=-1` (retry forever) and submodules enabled (`--submodules=recursive`).
2. Add a submodule pointing to an unreachable/slow-to-fail URL so that `git submodule update --init --recursive` in `configureWorktree` fails after the top-level `git reset --hard` checkout has already written real file content to the new worktree directory [8](#0-7) .
3. On each `--period` interval, push a new commit to the tracked ref (changing the hash each time) so the failure recurs against a fresh worktree path (`.worktrees/<new-hash>`).
4. Observe that `main.go`'s sync loop repeatedly logs "error syncing repo, will retry" without ever calling `git.cleanup()` [9](#0-8) , and that `--root/.worktrees/` accumulates one new populated directory per failed attempt, growing disk usage without bound until failures stop or disk is exhausted.

### Citations

**File:** main.go (L1056-1092)
```go
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

**File:** main.go (L1727-1747)
```go
	// Reset the worktree's working copy to the specific ref.
	git.log.V(1).Info("setting worktree HEAD", "hash", hash)
	if _, _, err := git.Run(ctx, worktree.Path(), "reset", "--hard", hash, "--"); err != nil {
		return err
	}

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

**File:** main.go (L1752-1799)
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

	// Let git know we don't need those old commits any more.
	git.log.V(3).Info("pruning worktrees")
	if _, _, err := git.Run(ctx, git.root, "worktree", "prune", "--verbose"); err != nil {
		cleanupErrs = append(cleanupErrs, err)
	}

	// Expire old refs.
	git.log.V(3).Info("expiring unreachable refs")
	if _, _, err := git.Run(ctx, git.root, "reflog", "expire", "--expire-unreachable=all", "--all"); err != nil {
		cleanupErrs = append(cleanupErrs, err)
	}

	// Run GC if needed.
	if git.gc != gcOff {
		args := []string{"gc"}
		switch git.gc {
		case gcAuto:
			args = append(args, "--auto")
		case gcAlways:
			// no extra flags
		case gcAggressive:
			args = append(args, "--aggressive")
		}
		git.log.V(3).Info("running git garbage collection")
		if _, _, err := git.Run(ctx, git.root, args...); err != nil {
			cleanupErrs = append(cleanupErrs, err)
		}
	}

	if len(cleanupErrs) > 0 {
		return cleanupErrs
	}
	return nil
}
```

**File:** main.go (L1929-1946)
```go
		// If we have a new hash, make a new worktree
		newWorktree := currentWorktree
		if changed {
			// Create a worktree for this hash in git.root.
			if wt, err := git.createWorktree(ctx, remoteHash); err != nil {
				return false, "", err
			} else {
				newWorktree = wt
			}
		}

		// Even if this worktree existed and passes sanity, it might not have all
		// the correct settings (e.g. sparse checkout).  The best way to get
		// it all set is just to re-run the configuration,
		if err := git.configureWorktree(ctx, newWorktree); err != nil {
			return false, "", err
		}

```

**File:** README.md (L210-227)
```markdown
SYNC PHASES

    git-sync operates in two phases:

    Initial sync:
        git-sync retries until its first successful sync with the remote
        repo.  During this phase, the retry interval is controlled by
        --init-period (falling back to --period if unset) and the failure
        limit is controlled by --init-max-failures (falling back to
        --max-failures when unset).  This phase is useful for tolerating
        transient connectivity issues at startup while still giving up
        eventually.

    Steady state:
        Once the first sync succeeds, git-sync polls the remote at the
        --period interval and tolerates failures up to --max-failures before
        aborting.  --init-period and --init-max-failures no longer apply.

```
