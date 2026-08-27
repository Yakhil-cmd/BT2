## Title
Silently ignored `os.RemoveAll` failure when un-configuring sparse-checkout leaves stale, partial content permanently published without any error or retry recovery - (File: main.go)

### Summary
This is a structural analog of the reward-capping bug in the report: in both cases, the code encounters a shortfall (Ajna balance too low / removal of a stale config file fails) and **silently accepts the degraded outcome instead of failing or tracking the deficit**, so the deficiency becomes permanent and unrecoverable through the normal happy path. In git-sync, this occurs in `repoSync.configureWorktree` when disabling sparse-checkout.

### Finding Description
When a worktree is (re-)configured, git-sync decides whether to enable or clear git's sparse-checkout state for that worktree: [1](#0-0) 

```go
gitInfoPath := filepath.Join(git.root.String(), ".git/worktrees", hash, "info")
gitSparseConfigPath := filepath.Join(gitInfoPath, "sparse-checkout")
if git.sparseFile == "" {
    os.RemoveAll(gitSparseConfigPath)
} else {
    ...
```

When `--sparse-checkout-file` is unset (or was previously set and is now removed), git-sync calls `os.RemoveAll(gitSparseConfigPath)` but **discards the returned error entirely**. If this removal fails (e.g. the `info` directory or file is on a read-only mount segment, has restrictive permissions from a previous run, an immutable attribute, or a race with a concurrent process), the stale `sparse-checkout` file remains in place. `configureWorktree` proceeds unconditionally to `git reset --hard <hash>`, which git itself will *honor the leftover sparse-checkout rules*, meaning only a subset of tracked files get materialized in the new worktree even though the operator asked for a full checkout.

Because `configureWorktree` returns `nil` in this branch regardless of the `RemoveAll` outcome, `SyncRepo` treats the whole operation as fully successful: [2](#0-1) 

The symlink is flipped to the new worktree, the `afterPublish` hooks fire, and the sync-success metric/log line is emitted — there is no signal to the operator that the published tree is incomplete. This mirrors the referenced bug class: a resource shortfall (available balance / successful cleanup) is silently capped/degraded rather than surfaced as an error, and the system has **no mechanism to retroactively correct the already-published, partial state** on the next iteration, since the exact same `RemoveAll` will keep failing for the same underlying reason (e.g., persistent permission/immutable-attribute issue), reproducing the same silent partial-publish forever.

### Impact Explanation
This falls squarely into "publishing wrong or partial content": consumers reading through the `--link` symlink believe they have the full repository (per the documented contract in `README.md` that the symlink represents "the most recently synced data"), but in fact only files matching a stale sparse-checkout filter are present. Because the failure is swallowed, there's also no operator-visible error, so the condition can persist indefinitely across sync cycles (persistent silent degradation, analogous to persistent sync denial of *correct* content, since correct full content is never re-attempted or recovered).

### Likelihood Explanation
This requires a somewhat unusual but plausible environmental condition: the `.git/worktrees/<hash>/info` directory or the `sparse-checkout` file within it must be resistant to removal (permission bits from a previous restrictive run, an immutable file flag, SELinux/AppArmor restriction, or a transient filesystem issue). It is not attacker-triggerable directly over the network/git-content path in the way the original report's balance shortfall was economically triggerable, but it is a realistic operational misconfiguration/edge case reachable purely through normal `--root`/worktree lifecycle handling, with no privileged operator action needed beyond ordinary filesystem state.

### Recommendation
Check and propagate the error from `os.RemoveAll(gitSparseConfigPath)` (and any other such fire-and-forget cleanup calls, e.g. `os.RemoveAll(currentWorktree.Path().String())` in `SyncRepo`) instead of ignoring it, failing the sync attempt (or at minimum surfacing a warning that stale sparse-checkout state may still apply) rather than silently publishing a worktree whose content may not match the requested full checkout.

### Proof of Concept
1. Start git-sync once with `--sparse-checkout-file=<file>` so `.git/worktrees/<hash>/info/sparse-checkout` is created and populated.
2. Make that specific file resistant to deletion in a way permitted by the host but not obviously visible (e.g., `chattr +i` on Linux, or narrow the directory permissions on `.git/worktrees/<hash>/info` so the sync UID can no longer unlink the file, while it can still read/write existing content used by `git reset --hard`).
3. Restart/re-run git-sync without `--sparse-checkout-file`.
4. Observe: `configureWorktree` calls `os.RemoveAll`, which fails silently; `git reset --hard <hash>` still applies the old sparse rules; `SyncRepo` reports success, the symlink flips, and `assert_file_exists`-style consumer checks for files outside the old sparse set will fail even though git-sync logs a normal successful sync.

### Citations

**File:** main.go (L1685-1691)
```go
	// If sparse checkout is requested, configure git for it, otherwise
	// unconfigure it.
	gitInfoPath := filepath.Join(git.root.String(), ".git/worktrees", hash, "info")
	gitSparseConfigPath := filepath.Join(gitInfoPath, "sparse-checkout")
	if git.sparseFile == "" {
		os.RemoveAll(gitSparseConfigPath)
	} else {
```

**File:** main.go (L1940-1963)
```go
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
