### Title
Attacker-controlled repo content (malicious `.gitmodules`/submodule ref) causes permanent `configureWorktree` failure and persistent sync denial - ([File: main.go])

### Summary
The reported dTRINITY issue is a DeFi-specific bug (reverting withdraw due to a downstream protocol interaction) and has no direct analog in `git-sync`. However, the underlying bug *class* — "an operation in the middle of a multi-step commit/publish flow can be made to fail deterministically by attacker-supplied data, causing the whole flow to fail every time it is retried" — does map onto `git-sync`'s sync pipeline. An attacker who can push commits to the tracked repository (the same untrusted-content actor assumed by the harness) can craft a commit whose `.gitmodules`/submodule configuration makes `git submodule update --init [--recursive]` fail deterministically. Because that command runs *after* the worktree has already been created and pointed at the new hash, every subsequent sync attempt reaches the same failing command and never publishes the new commit, and because the failed worktree/hash lingers, git-sync can loop forever failing (or terminate) depending on `--max-failures`.

### Finding Description
`repoSync.SyncRepo` performs, in order: fetch → `createWorktree` (git worktree add for the new hash) → `configureWorktree` (sparse-checkout setup, hard reset, then `git submodule update --init`) → publish symlink [1](#0-0) . The submodule update step directly executes `git submodule update --init [--recursive] [--depth N]` using arguments and repository state that come from the fetched (attacker-controlled) ref, and any non-zero exit is propagated as a hard error from `SyncRepo` [2](#0-1) .

If a pushed commit contains a `.gitmodules` entry or submodule gitlink that git cannot resolve (e.g., an invalid/unreachable submodule URL, a submodule commit that requires disallowed protocols, or a path/config that trips git's submodule-name sanitization), `git submodule update --init` fails every time it is invoked, regardless of retries, because the same broken commit/worktree is re-processed identically on each loop iteration. The main loop's failure handling simply increments `failCount`, logs, and retries after `waitTime`, or aborts via `os.Exit(1)` once `failCount` reaches the effective max-failure limit — but the offending commit is never skipped or worked around [3](#0-2) .

The `currentWorktree()`/`SyncRepo` logic recomputes `changed` from the on-disk symlink target vs. the remote hash on every iteration; since the symlink was never advanced (publish never reached), `changed` stays true and `createWorktree`+`configureWorktree` are re-attempted for the *same* broken hash on every single sync cycle [4](#0-3) .

### Impact Explanation
This is a persistent sync denial: legitimate consumers relying on the `--link` symlink for the latest tree never receive the new (or any subsequent) commit, because the pipeline can never get past the submodule step for the poisoned commit, and no forward progress is made even though later, valid commits exist on the same ref. If `--max-failures` is non-negative (default `0`, meaning "abort on first failure" per the flag's documented default) [5](#0-4) , the process exits entirely, taking down the sidecar container until manually restarted/recovered — a full DoS of the sync sidecar triggered purely by content an unprivileged repo-writer pushed.

### Likelihood Explanation
This requires only push/commit access to the tracked repository (the same "untrusted repo content" threat actor assumed by the scan scope) and the default or commonly-used `--submodules=recursive`/`shallow` configuration (submodule handling is enabled by default in git-sync) [6](#0-5) . No special git-sync flags beyond normal submodule support are required; the only mitigating factor is deployments that explicitly set `--submodules=off`, in which case this path is not reachable.

### Recommendation
- Treat `configureWorktree` failures (specifically submodule update failures) as recoverable per-hash errors: if a specific commit's submodule step fails repeatedly, avoid infinitely retrying the exact same known-bad hash — e.g., detect and skip/quarantine a hash that fails N consecutive attempts and continue polling for a newer ref, rather than deadlocking on it.
- Consider making the submodule update failure mode configurable (e.g., "best effort" submodule sync) so that a broken submodule doesn't block publishing of the top-level tree.
- Ensure `--max-failures`/`--init-max-failures` guidance clearly documents that a malicious/broken commit in the tracked repo can permanently block sync progress, and consider surfacing this state distinctly in metrics/health endpoint so operators can detect "stuck on the same failing hash" versus generic transient failures.

### Proof of Concept
1. Attacker with push access to the tracked repo adds/modifies `.gitmodules` to reference a submodule URL that is unreachable or disallowed (e.g., `file://` or a protocol not permitted by `protocol.*.allow`, or a nonexistent host), and commits a corresponding gitlink; pushes this commit as the new HEAD of the tracked ref.
2. `git-sync`'s next `SyncRepo` iteration fetches the new hash, creates a worktree for it (`createWorktree`), then calls `configureWorktree`, which runs `git submodule update --init ...` and fails [2](#0-1) .
3. `SyncRepo` returns the error before `publishSymlink` is ever called, so the `--link` symlink still points at the old hash [7](#0-6) .
4. On every subsequent loop iteration, `currentWorktree()`/hash comparison again finds `changed == true` for the same broken remote hash and repeats steps 2–3 indefinitely [4](#0-3) , until `failCount` hits `--max-failures` (default 0) and the process exits [3](#0-2) , or (with `--max-failures` negative) it loops forever without ever converging on new content — either way, a persistent denial of the sync service.

### Citations

**File:** main.go (L1056-1063)
```go
		if changed, hash, err := git.SyncRepo(ctx, syncHooks); err != nil {
			failCount++
			updateSyncMetrics(metricKeyError, start)
			if maxFails := getMaxFailures(); maxFails >= 0 && failCount >= maxFails {
				log.Error(err, "too many failures, aborting", "failCount", failCount, "maxFailures", maxFails)
				os.Exit(1)
			}
			log.Error(err, "error syncing repo, will retry", "failCount", failCount)
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

**File:** main.go (L1899-1963)
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

		// If we have a new hash, update the symlink to point to the new worktree.
		if changed {
			// If the previous run crashed before publishing the link, then we
			// must call the pre-publish hook, and since changed is true, we will.
			// we will. If the previous run crashed after publishing the link,
			// then we do not need to call the pre-publish hook, and since
			// changed is false, we won't. The post-publish hooks are called in
			// both cases.
			err := syncHooks.beforePublish(newWorktree.Hash())
			if err != nil {
				return false, "", err
			}

			err = git.publishSymlink(newWorktree)
			if err != nil {
				return false, "", err
			}
```

**File:** main.go (L2790-2794)
```go
    --max-failures <int>, $GITSYNC_MAX_FAILURES
            The number of consecutive failures allowed before aborting.
            Setting this to a negative value will retry forever.  If not
            specified, this defaults to 0, meaning any sync failure will
            terminate git-sync.
```
