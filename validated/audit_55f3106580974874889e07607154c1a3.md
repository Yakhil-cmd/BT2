### Title
Unbounded per-commit worktree accumulation can exhaust `--root` disk and cause persistent sync denial - (File: main.go)

### Summary
`git-sync` creates a brand-new, fully-checked-out `git worktree` directory keyed by commit hash every time the tracked `--ref` resolves to a new tip, and only reclaims that disk space through a time-based staleness check that intentionally never touches the currently-published worktree. When an operator uses the documented `--stale-worktree-timeout` retention window (a normal, recommended-for-rollback setting, not a misconfiguration), an attacker who can push distinct commits to the synced ref can force one new full-size worktree per poll cycle for the entire retention window, exhausting the `--root` filesystem and permanently blocking future syncs — the same class of "unbounded, attacker-driven creation of a checkpoint/cleanup-gated resource" flagged in the source Llama finding (unbounded action creation defeating a timestamp-gated invariant).

### Finding Description
Worktrees are named strictly by git hash and are never limited in count: [1](#0-0) 

Each detected change to the remote ref creates a new full worktree via `git worktree add`, unconditionally: [2](#0-1) 

The only cleanup path is `removeStaleWorktrees`, invoked from `cleanup()` once per sync loop iteration. It deletes a non-current worktree **only** once `time.Since(fi.ModTime()) > git.staleTimeout`, and it explicitly never deletes the worktree currently pointed to by `--link`: [3](#0-2) [4](#0-3) 

`--stale-worktree-timeout` is user/operator configurable and documented as a supported feature (its purpose is to retain older worktrees, e.g. to support fast rollback), defaulting to `0` but commonly set to non-zero durations in production: [5](#0-4) 

The sync loop's own comment confirms this cleanup only runs on the normal periodic cadence, i.e. once per `--period` tick, not synchronously with each worktree creation: [6](#0-5) 

Because worktree creation is driven entirely by the remote repository's history (the "untrusted repo content" reachable to any party with push/force-push access to the tracked `--ref`), and disk reclamation is gated purely by elapsed wall-clock time relative to a timeout that has no relationship to the *number* of distinct hashes produced, an attacker who can land one new commit per poll cycle can force git-sync to accumulate `(staleTimeout / period)` full checkouts simultaneously on disk. There is no maximum-worktree-count guard, no disk-quota check, and no rate limiting tied to the number of hashes observed — directly analogous to `LlamaCore._createAction` having no limit on the number of actions a role holder can create while `LlamaPolicy` relies on a same-timestamp check that unbounded action creation can defeat.

### Impact Explanation
If the `--root` volume fills up, subsequent `git worktree add` calls at `main.go:1657` fail, `publishSymlink` (which only runs after a successful worktree checkout) never executes for new revisions, and the process enters a failure loop bounded only by `--max-failures`/`--init-max-failures`, ultimately exiting or looping in `pid1`. Even if the process is restarted by Kubernetes, the accumulated worktree directories persist under `--root` until manually cleared, and `PersistentVolume`-backed deployments (a common pattern per `docs/kubernetes.md`) can remain wedged. This satisfies the accepted impact category of **persistent sync denial** and, on shared nodes without a `PersistentVolume`, can also produce Kubernetes disk-pressure eviction of the pod/node, affecting other workloads.

### Likelihood Explanation
Medium. It requires: (1) the operator to configure a non-zero `--stale-worktree-timeout` (an explicitly documented, legitimate use case, not a misconfiguration or malicious-operator scenario), and (2) an attacker with write/force-push access to the synced `--ref` (e.g., a shared GitOps/config repository, a mono-repo with broad contributor access, or any deployment where the trust boundary of "who can commit to the synced branch" is wider than "who operates the git-sync sidecar"). No credentials, mocked components, or malicious node/operator behavior are needed — only ordinary commit pushes to the tracked ref, which is squarely within the "untrusted repo content" threat model.

### Recommendation
Bound the number of retained worktrees independently of elapsed time — e.g., cap the maximum number of worktrees kept under `.worktrees/` regardless of `--stale-worktree-timeout`, or enforce a disk-usage/inode quota check in `removeStaleWorktrees`/`cleanup` that proactively evicts the oldest non-current worktrees once a configurable count or size threshold is exceeded, in addition to the existing time-based rule.

### Proof of Concept
1. Deploy `git-sync` against a repository the attacker (or a low-trust contributor) can push to, with:
   ```
   --repo=<attacker-writable-repo>
   --ref=<tracked-branch>
   --root=/tmp/root
   --link=link
   --period=1s
   --stale-worktree-timeout=1h
   ```
2. Attacker pushes a new distinct commit to `<tracked-branch>` every ~1s (trivial: `git commit --allow-empty -m x && git push`).
3. Each poll cycle, `SyncRepo` (`main.go:1858`) detects `remoteHash != currentHash`, calls `createWorktree` (`main.go:1642`) to check out a brand-new full worktree under `.worktrees/<hash>`.
4. `removeStaleWorktrees` (`main.go:1420`) will not delete any of these worktrees for 1 hour (`--stale-worktree-timeout=1h`), so up to `3600` full checkouts accumulate concurrently on disk.
5. For a repository whose checkout is even a few MB, `--root` fills up within the hour; subsequent `git worktree add` invocations fail, `publishSymlink` stops advancing, and the sync is persistently denied until an operator manually purges `--root`.

### Citations

**File:** main.go (L228-229)
```go
	flStaleWorktreeTimeout := pflag.Duration("stale-worktree-timeout", envDuration(0, "GITSYNC_STALE_WORKTREE_TIMEOUT"),
		"how long to retain non-current worktrees")
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

**File:** main.go (L1838-1840)
```go
func (git *repoSync) worktreeFor(hash string) worktree {
	return worktree(git.root.Join(".worktrees", hash))
}
```

**File:** main.go (L1978-1985)
```go
		// Mark ourselves as "ready".
		setRepoReady()
		git.syncCount++
		git.log.V(0).Info("updated successfully", "ref", git.ref, "remote", remoteHash, "syncCount", git.syncCount)

		// Regular cleanup will happen in the outer loop, to catch stale
		// worktrees.

```
