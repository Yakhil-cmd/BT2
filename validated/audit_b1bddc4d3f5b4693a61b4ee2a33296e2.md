### Title
Unbounded disk growth from attacker-controlled fetches when sync repeatedly fails after `git fetch` succeeds - (File: main.go)

### Summary
`git-sync` fetches objects from an attacker-influenced upstream ref on every sync attempt, but only calls `cleanup()` (which prunes worktrees, expires unreachable reflogs, and runs `git gc`) when the *overall* `SyncRepo` call succeeds. If a remote repository is crafted so that the fetch phase succeeds (downloading new pack data into `.git/objects`) but a later phase of the same sync (worktree creation, checkout, hooks, sanity checks, etc.) fails, the loop increments `failCount` and retries indefinitely without ever pruning or garbage-collecting the newly-fetched objects.

### Finding Description
The main sync loop distinguishes success and failure paths explicitly: [1](#0-0) 

`cleanup()` — which does `worktree prune`, `reflog expire --expire-unreachable=all`, and conditionally `git gc` — is only reached in the `else` (success) branch: [2](#0-1) 

However, `SyncRepo` performs the network-facing `fetch` *before* any of the steps that can fail and cause a non-nil error return (worktree creation, `configureWorktree`, `beforePublish`/`afterPublish` hooks, symlink publish): [3](#0-2) 

The `fetch` step always passes `--no-auto-gc`, so git itself will never opportunistically collect garbage on the attacker's behalf: [4](#0-3) 

Because git-sync always fetches "exactly the ref it needs" every cycle (per the v4 design), an upstream repository fully controlled by an attacker can push a new commit each period pointing at large/garbage blobs. If any post-fetch step is made to fail consistently (e.g., a hook that always errors, a `--sparse-checkout-file` pattern that can't be satisfied, or exceeding `--sync-timeout` during checkout of a very large tree), `SyncRepo` returns an error every time, `cleanup()` is never invoked, and each retry's `git fetch` (with `--prune` but no GC) keeps depositing new pack objects into `git.root/.git/objects` without ever being pruned or GC'd. With `--max-failures` set to a negative value (retry forever), which the docs explicitly recommend for resiliency: [5](#0-4) 

git-sync will retry forever, accumulating attacker-supplied objects on disk indefinitely.

### Impact Explanation
This can lead to persistent disk exhaustion (denial of service) on the host/volume backing `--root`, analogous to the Bitcoin Core issue where repeatedly-sent invalid blocks were stored before full validation and never cleaned up. In Kubernetes, this can exhaust the node's storage backing the shared `emptyDir`/volume, affecting the sidecar and potentially the whole pod/node.

### Likelihood Explanation
Requires: (1) the operator points git-sync at an attacker-controlled or attacker-writable repository (which is the standard "attacker-pushed commit/ref" threat model for this tool), and (2) `--max-failures` set to retry indefinitely (a commonly recommended configuration per the docs) or a long-running failure window before the process aborts. The exact mechanism for forcing a *reliable* post-fetch failure on every cycle (e.g., an always-failing exec hook, sparse-checkout misconfiguration, or timeout during checkout of oversized content) is architecture-dependent and was not fully verified against a concrete git command failure signature in this pass — this is the main uncertainty in the analysis.

### Recommendation
Run `cleanup()` (or at least `git gc`/`prune`) regardless of whether the post-fetch phases of `SyncRepo` succeed, so that fetched objects are never allowed to accumulate unboundedly across failed sync attempts. Alternatively, bound the total repository size/object count and abort/alert when a threshold is exceeded, independent of `--max-failures`.

### Proof of Concept
Conceptual (not fully verified end-to-end due to tool-call limits):
1. Host a repository the victim git-sync instance is configured to track with `--max-failures=-1` (retry forever).
2. Configure a `--exec-hook-command` or `--sparse-checkout-file` on the victim side that is guaranteed to fail after checkout of certain content (or rely on `--sync-timeout` being exceeded during checkout of very large trees).
3. As the attacker (controlling the upstream repo), push a new commit each period containing large, unique blobs, so each `git.fetch` at [4](#0-3)  downloads new pack data.
4. Because the post-fetch phase fails every time, `SyncRepo` returns an error at [6](#0-5) , and `cleanup()` at [7](#0-6)  is never called, so `.git/objects` under `--root` grows without bound across sync cycles.

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

**File:** main.go (L1883-1945)
```go
	// This should be very fast if we already have the hash we need. Parameters
	// like depth are set at fetch time.
	if err := git.fetch(ctx, git.ref); err != nil {
		return false, "", err
	}

	// Figure out what we got.  The ^{} syntax "peels" annotated tags to
	// their underlying commit hashes, but has no effect if we fetched a
	// branch, plain tag, or hash.
	var remoteHash string
	if output, _, err := git.Run(ctx, git.root, "rev-parse", "FETCH_HEAD^{}"); err != nil {
		return false, "", err
	} else {
		remoteHash = strings.Trim(output, "\n")
	}

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

**File:** main.go (L2001-2029)
```go
// fetch retrieves the specified ref from the upstream repo.
func (git *repoSync) fetch(ctx context.Context, ref string) error {
	git.log.V(2).Info("fetching", "ref", ref, "repo", redactURL(git.repo))

	// Fetch the ref and do some cleanup, setting or un-setting the repo's
	// shallow flag as appropriate.
	args := []string{"fetch", git.repo, ref, "--verbose", "--no-progress", "--prune", "--no-auto-gc"}
	if git.depth > 0 {
		args = append(args, "--depth", strconv.Itoa(git.depth))
	} else {
		// If the local repo is shallow and we're not using depth any more, we
		// need a special case.
		shallow, err := git.isShallow(ctx)
		if err != nil {
			return err
		}
		if shallow {
			args = append(args, "--unshallow")
		}
	}
	if git.filter != "" {
		args = append(args, "--filter", git.filter)
	}
	if _, _, err := git.Run(ctx, git.root, args...); err != nil {
		return err
	}

	return nil
}
```

**File:** README.md (L442-446)
```markdown
    --max-failures <int>, $GITSYNC_MAX_FAILURES
            The number of consecutive failures allowed before aborting.
            Setting this to a negative value will retry forever.  If not
            specified, this defaults to 0, meaning any sync failure will
            terminate git-sync.
```
