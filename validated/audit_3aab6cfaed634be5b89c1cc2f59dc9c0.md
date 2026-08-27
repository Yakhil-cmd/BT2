### Title
`sanityCheckWorktree` accepts a worktree as fully synced without verifying that the checkout actually completed, causing partial content to be treated as a good sync indefinitely - (File: `main.go`)

### Summary
Analogous to the DeliHook bug where a fee is charged on the *full intended* swap amount instead of the *actual* amount that was executed, `git-sync`'s `SyncRepo` loop treats a worktree as fully and correctly synced based on an incomplete check, rather than verifying that the actual file content matches what was requested. If a previous checkout died partway through (as the code's own comment acknowledges is possible), `sanityCheckWorktree` will still return `true`, the loop will believe "we already have the right hash", and it will never re-run the checkout to fix the missing/partial files — permanently publishing incomplete content under the same hash.

### Finding Description
`sanityCheckWorktree` is documented to only validate the commit identity, not completeness of the actual checked-out files: [1](#0-0) 

Specifically it only checks that the directory is non-empty, that `rev-parse HEAD` matches the expected hash, and that `git fsck --connectivity-only` succeeds — none of which detect a partially materialized working tree (e.g., killed mid-`checkout`/`reset --hard`, or mid-`submodule update`).

In `SyncRepo`, when the current hash equals the remote hash, this weak check is the *sole* gate used to decide whether the existing worktree is trustworthy: [2](#0-1) 

If `sanityCheckWorktree` returns `true` (which it will for a partially-checked-out but hash-consistent worktree), `currentHash` remains equal to `remoteHash`, so `changed` is `false` and the entire re-checkout/`configureWorktree` path is skipped: [3](#0-2) 

The main loop then records this as a normal sync (or no-op) without error, marks the repo ready, and never retries `configureWorktree` (which is what actually performs `reset --hard`, sparse-checkout configuration, and submodule updates): [4](#0-3) 

This mirrors the DeliHook root cause: the system commits to (and reports success for) the *full, intended* result ("this hash is correctly and completely synced") while only having verified a much weaker proxy (commit identity/object connectivity), not the actual on-disk outcome (complete, correct file tree).

### Impact Explanation
This can result in **persistently publishing wrong or partial content** through the `--link` symlink: if a crash/OOM-kill/eviction interrupts `configureWorktree` (e.g., mid `reset --hard`, mid sparse-checkout application, or mid submodule update) after `git worktree add` but leaves `HEAD` at the correct hash and the object store connectivity intact, every subsequent sync cycle will consider that worktree good indefinitely — consumers reading from the symlink will silently receive an incomplete/stale checkout with no error ever raised, and no future upstream change of the same hash can trigger a repair since re-sync only occurs on hash change. This matches the accepted impact class "publishing wrong or partial content, or persistent sync denial."

### Likelihood Explanation
Requires that a checkout process gets interrupted between `git worktree add ... --no-checkout` and full completion of `configureWorktree` (`reset --hard`, sparse-checkout write, submodule update) — a realistic scenario in Kubernetes sidecars subject to OOM-kill, pod eviction, node restarts, or `--sync-timeout` expiry, all of which are normal operational conditions rather than requiring a malicious actor. Given `git-sync`'s stated purpose is exactly to guard against such non-atomic checkout failures, this is a meaningful gap in the intended atomicity guarantee.

### Recommendation
Strengthen `sanityCheckWorktree` (or `configureWorktree`) to positively verify the actual checked-out content, not just commit identity — e.g., compare `git status --porcelain`/`diff --stat HEAD` against expectation, verify submodule status, or persist an explicit "checkout complete" marker written only after `configureWorktree` fully succeeds, and treat its absence as a sanity failure requiring a redo of `configureWorktree` even when the hash matches.

### Proof of Concept
1. Run `git-sync` against a repo with submodules or a `--sparse-checkout-file`.
2. During the `configureWorktree` step (e.g. mid `submodule update --init --recursive`), kill the process (simulating an OOM-kill/eviction) — `HEAD` is already set to the target hash from the `reset --hard`, but submodules/sparse content are incomplete.
3. Restart `git-sync` with the same `--ref`. Because `currentHash == remoteHash` and `sanityCheckWorktree` only checks `rev-parse HEAD` and `fsck --connectivity-only`, it returns `true`; `configureWorktree` is never re-run, and the incomplete worktree is published/kept as-is on every subsequent cycle.

### Citations

**File:** main.go (L1064-1092)
```go
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

**File:** main.go (L1501-1536)
```go
// sanityCheckWorktree tries to make sure that the dir is a valid git
// repository.  Note that this does not guarantee that the worktree has all the
// files checked out - git could have died halfway through and the repo will
// still pass this check.
func (git *repoSync) sanityCheckWorktree(ctx context.Context, worktree worktree) bool {
	git.log.V(3).Info("sanity-checking worktree", "repo", git.root, "worktree", worktree)

	// If it is empty, we are done.
	if empty, err := dirIsEmpty(worktree.Path()); err != nil {
		git.log.Error(err, "can't list worktree directory", "path", worktree.Path())
		return false
	} else if empty {
		git.log.V(0).Info("worktree is empty", "path", worktree.Path())
		return false
	}

	// Make sure it is synced to the right commmit.
	stdout, _, err := git.Run(ctx, worktree.Path(), "rev-parse", "HEAD")
	if err != nil {
		git.log.Error(err, "can't get worktree HEAD", "path", worktree.Path())
		return false
	}
	if stdout != worktree.Hash() {
		git.log.V(0).Info("worktree HEAD does not match worktree", "path", worktree.Path(), "head", stdout)
		return false
	}

	// Consistency-check the worktree.  Don't use --verbose because it can be
	// REALLY verbose.
	if _, _, err := git.Run(ctx, worktree.Path(), "fsck", "--no-progress", "--connectivity-only"); err != nil {
		git.log.Error(err, "worktree fsck failed", "path", worktree.Path())
		return false
	}

	return true
}
```

**File:** main.go (L1899-1910)
```go
	if currentHash == remoteHash {
		// We seem to have the right hash already.  Let's be sure it's good.
		git.log.V(3).Info("current hash is same as remote", "hash", currentHash)
		if !git.sanityCheckWorktree(ctx, currentWorktree) {
			// Sanity check failed, nuke it and start over.
			git.log.V(0).Info("worktree failed checks or was empty", "path", currentWorktree)
			if err := git.removeWorktree(ctx, currentWorktree); err != nil {
				return false, "", err
			}
			currentHash = ""
		}
	}
```

**File:** main.go (L1912-1946)
```go
	// This catches in-place upgrades from older versions where the worktree
	// path was different.
	changed := (currentHash != remoteHash) || (currentWorktree != git.worktreeFor(currentHash))

	// We have to do at least one fetch, to ensure that parameters like depth
	// are set properly.  This is cheap when we already have the target hash.
	if changed || git.syncCount == 0 {
		git.log.V(0).Info("update required", "ref", git.ref, "local", currentHash, "remote", remoteHash, "syncCount", git.syncCount)
		metricFetchCount.Inc()

		// Reset the repo (note: not the worktree - that happens later) to the new
		// ref.  This makes subsequent fetches much less expensive.  It uses --soft
		// so no files are checked out.
		if _, _, err := git.Run(ctx, git.root, "reset", "--soft", remoteHash, "--"); err != nil {
			return false, "", err
		}

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
