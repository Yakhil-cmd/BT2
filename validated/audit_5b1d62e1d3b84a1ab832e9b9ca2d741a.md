### Title
Attacker-controlled `.gitmodules`/submodule content in the synced repo can force `configureWorktree()` to fail every sync attempt, causing persistent sync denial - (File: main.go)

### Summary
The Velocimeter `poke()` bug is a case where an attacker-controlled input can be crafted so that a mandatory state-transition check (`_poolWeight != 0`) is guaranteed to fail on every future invocation, permanently blocking the honest "revote" flow and corrupting reward accounting. The closest reachable analog in `git-sync` is that content pushed to the synced git repository (which `git-sync` treats as untrusted/`sync`-time-only input) is fed directly into git subcommands invoked by `git-sync`'s own sync state machine, and a single crafted commit can make one of those subcommands fail deterministically on *every* sync attempt for that ref, permanently blocking the atomic-symlink publish contract until the offending commit is reverted or fixed upstream.

### Finding Description
`repoSync.SyncRepo()` drives the whole per-period state machine: fetch → decide `changed` → `createWorktree()` → `configureWorktree()` → `publishSymlink()` [1](#0-0) . `configureWorktree()` unconditionally runs `git submodule update --init [--recursive]` against whatever `.gitmodules`/submodule refs are present in the just-fetched commit, with no sanitization of submodule URLs, paths, or protocols beyond what `git` itself enforces: [2](#0-1) 

If the tracked commit's `.gitmodules` references an unreachable, disallowed, or otherwise-failing submodule (e.g. an invalid protocol, unreachable host, or path that a locally-installed submodule/allow policy rejects), `git submodule update` returns a non-zero exit and `configureWorktree()` propagates the error, which makes `SyncRepo()` return an error for that call [3](#0-2) .

Crucially, this is not a one-off failure: `createWorktree()` always removes and recreates the worktree for the target hash before configuring it [4](#0-3) , so as long as the remote ref still points at the poisoned commit, every subsequent sync attempt repeats the exact same fetch → worktree → submodule-update sequence and fails identically — the git-sync analog of `poke()` always hitting `require(_poolWeight != 0)`.

In the outer loop, `--max-failures` defaults to `0`, meaning "any sync failure will terminate git-sync" [5](#0-4) , and the loop enforces this by calling `os.Exit(1)` as soon as `failCount >= maxFails` [6](#0-5) . With the default configuration, the very first failed sync (caused entirely by attacker-controlled repo content) terminates the sidecar process outright, which is a stronger and more immediate denial than a mere transient error.

### Impact Explanation
Any party with commit/merge access to the synced ref (the "attacker-pushed commit" scenario explicitly in scope) can publish a single commit with a malicious `.gitmodules`/submodule reference. From that point on:
- The symlink is never atomically flipped to the new commit (no publish occurs), so consumers are stuck on the last good revision — a **persistent sync denial** consistent with the accepted impact categories.
- With the default `--max-failures=0`, `git-sync` calls `os.Exit(1)` on the very first failed sync, crashing the sidecar container. In a Kubernetes Deployment this typically causes repeated CrashLoopBackOff, escalating a content-level issue into an availability incident for the whole pod, not just the sync subsystem.
- This is deterministic and repeatable for as long as the bad commit remains at the tracked ref/branch tip, mirroring the "hold the exploited state forever" characteristic of the `poke()` DoS.

### Likelihood Explanation
This requires only ordinary write/merge access to the tracked branch/tag of `--repo` (or the ability to get such a commit merged) — no special git-sync misconfiguration beyond defaults (`--submodules=recursive` is in fact the default) [7](#0-6) . No credential compromise, no reliance on a malicious operator of git-sync itself, and no dependency-only bug is needed — the failure path is entirely inside git-sync's own `configureWorktree`/`SyncRepo` orchestration reacting to content it fetched from the configured (potentially less-trusted) remote.

### Recommendation
- Do not let a single content-triggered git-command failure immediately terminate the process by default; consider defaulting `--max-failures` away from `0`, or distinguishing "fatal config errors" from "content/data errors" that are expected to be transient/attacker-influenced.
- Add a recovery/quarantine mechanism: if `configureWorktree` (specifically the submodule step) fails repeatedly for the *same* resolved hash, keep serving the last good symlink target indefinitely (already true) but surface a distinct, actionable metric/error so operators are not forced into crash-looping while they wait for an upstream revert.
- Consider bounding or making optional the recursive submodule fetch/update (e.g., failing open with a warning rather than aborting the whole sync) when `--submodules` processing fails but the primary worktree content was otherwise successfully checked out.

### Proof of Concept
1. Deploy `git-sync` with defaults (`--submodules=recursive`, `--max-failures=0`) tracking a branch the "attacker" can commit to.
2. Attacker pushes a commit adding a `.gitmodules` entry with a submodule URL that will fail during `git submodule update --init --recursive` in the sync environment (e.g., an unreachable host, or a URL scheme disallowed by the runtime's `protocol.*.allow` policy).
3. Observe: `git.fetch` and `createWorktree` succeed, but `configureWorktree`'s submodule step fails every time; `SyncRepo` returns an error on every loop iteration for that commit.
4. With default `--max-failures=0`, the process exits after the very first failed attempt [6](#0-5) , and the symlink never advances past the last good pre-attack commit, demonstrating persistent sync denial driven purely by attacker-controlled repository content.

### Citations

**File:** main.go (L182-184)
```go
	flSubmodules := pflag.String("submodules",
		envString("recursive", "GITSYNC_SUBMODULES", "GIT_SYNC_SUBMODULES"),
		"git submodule behavior: one of 'recursive', 'shallow', or 'off'")
```

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

**File:** main.go (L1642-1663)
```go
// createWorktree creates a new worktree and checks out the given hash.  This
// returns the path to the new worktree.
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

**File:** main.go (L1858-1946)
```go
// SyncRepo syncs the repository to the desired ref, publishes it via the link,
// and tries to clean up any detritus.  This function returns whether the
// current hash has changed and what the new hash is.
func (git *repoSync) SyncRepo(ctx context.Context, syncHooks syncHooks) (bool, string, error) {
	git.log.V(3).Info("syncing", "repo", redactURL(git.repo))

	if err := syncHooks.refreshCreds(ctx); err != nil {
		return false, "", fmt.Errorf("credential refresh failed: %w", err)
	}

	// Initialize the repo directory if needed.
	if err := git.initRepo(ctx); err != nil {
		return false, "", err
	}

	// Find out what we currently have synced, if anything.
	var currentWorktree worktree
	if wt, err := git.currentWorktree(); err != nil {
		return false, "", err
	} else {
		currentWorktree = wt
	}
	currentHash := currentWorktree.Hash()
	git.log.V(3).Info("current state", "hash", currentHash, "worktree", currentWorktree)

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

**File:** main.go (L2790-2794)
```go
    --max-failures <int>, $GITSYNC_MAX_FAILURES
            The number of consecutive failures allowed before aborting.
            Setting this to a negative value will retry forever.  If not
            specified, this defaults to 0, meaning any sync failure will
            terminate git-sync.
```
