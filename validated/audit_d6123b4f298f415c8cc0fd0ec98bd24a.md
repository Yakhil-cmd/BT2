### Title
Unbounded `git submodule update --recursive` triggered by attacker-controlled `.gitmodules` causes persistent sync denial - (File: main.go)

### Summary
`git-sync`'s `configureWorktree` runs `git submodule update --init --recursive` on every checked-out commit without any limit on the number of submodules, the recursion depth, or the total amount of data/time this can consume. Because `.gitmodules` and the list of submodule entries are part of the tracked repository content, an attacker who can push a commit to the synced ref (the same threat model as the reported PrizePool "unbounded external tokens list") can add an arbitrarily large or deeply-nested submodule graph. This can make every sync attempt exceed `--sync-timeout`, exhaust disk/network resources, and permanently block git-sync from ever publishing a new revision — an unbounded "linked list of external references" processed on every cycle, exactly analogous to the reported bug class.

### Finding Description
`configureWorktree` unconditionally updates submodules whenever `git.submodules != submodulesOff` (the default is `recursive`): [1](#0-0) 

The submodule mode itself is attacker-agnostic and defaults to `recursive`, with no cap on the number of submodules or recursion depth: [2](#0-1) 

Similar to `MappedSinglyLinkedList.addAddress()` in the Solidity report — where an admin can append unboundedly many token addresses that are later iterated in full inside `_awardExternalErc721s`/`_awardExternalErc20s` — here the "list" is the set of `.gitmodules` entries (and their own nested `.gitmodules`, recursively) that ships inside the tracked git history. There is no limit enforced by git-sync on:
- the number of submodule entries,
- the recursion depth (`--recursive`), or
- the cumulative amount of data fetched for submodules (per-submodule `--depth` is honored, but there's no bound on submodule *count* or nesting).

Every sync loop iteration calls `SyncRepo` → `configureWorktree`, which re-runs the full recursive submodule update whenever a new commit is fetched: [3](#0-2) 

If this operation exceeds the sync timeout, `SyncRepo` returns an error, `failCount` increments, and (unless `--max-failures` is unlimited) git-sync eventually aborts; if failures are allowed to retry forever (the default `-1`/unbounded case documented for `--max-failures`), it will retry indefinitely and never make forward progress, exactly like the reported "gas DoS" scenario where a legitimate caller can never successfully complete the operation: [4](#0-3) 

### Impact Explanation
A malicious commit can cause `git submodule update --init --recursive` to run for an extremely long time (many thousands of submodule remotes to contact, or deep recursive nesting), consistently exceeding `--sync-timeout`. This results in **persistent sync denial**: the sidecar can never publish the new (or even current) revision, the shared volume becomes stale, and dependent application containers keep serving outdated content indefinitely. This matches one of the explicitly accepted impacts (persistent sync denial).

### Likelihood Explanation
This requires only push access to the branch/ref git-sync is configured to track (or, in supply-chain-adjacent scenarios, control over a mirrored/forked upstream) — the same "attacker-pushed commit" precondition assumed for the underlying bug class. No special git-sync flags beyond the default `--submodules=recursive` (the default value) are required. This is a plausible but non-trivial attack requiring write access to the source repository, so likelihood is moderate rather than trivial.

### Recommendation
- Add a configurable limit on submodule count and/or recursion depth (e.g., a `--submodules-max-count` / cap the effective recursion), or default to non-recursive submodule updates.
- Consider running submodule updates with the same `--depth`/timeout controls applied recursively, and treat submodule-update timeouts as a distinct, more aggressively bounded failure mode rather than folding them into the general sync retry loop.
- Document that `--submodules=off` should be used for untrusted repositories, and consider making `off` the safer default when the source is not fully trusted.

### Proof of Concept
1. Attacker with push access to the tracked branch adds hundreds/thousands of submodule entries to `.gitmodules` (or a submodule chain nested many levels deep, each adding more submodules), committing this to the ref git-sync follows.
2. git-sync fetches the new commit and, per `configureWorktree` (`main.go:1733-1747`), runs `git submodule update --init --recursive`.
3. Because the number/depth of submodules is unbounded, the command runs past `--sync-timeout` (default 120s), causing `SyncRepo` to return an error on every attempt.
4. The sync loop (`main.go:1056-1092`) keeps retrying (or aborts after `--max-failures` if configured), and the published symlink never advances to the malicious or any subsequent commit — a persistent denial of the sync service.

### Citations

**File:** main.go (L182-184)
```go
	flSubmodules := pflag.String("submodules",
		envString("recursive", "GITSYNC_SUBMODULES", "GIT_SYNC_SUBMODULES"),
		"git submodule behavior: one of 'recursive', 'shallow', or 'off'")
```

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

**File:** main.go (L1918-1945)
```go
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
