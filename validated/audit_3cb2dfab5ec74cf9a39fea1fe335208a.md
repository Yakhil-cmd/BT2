### Title
Sanity check silently accepts an incompletely checked-out worktree, allowing publication of partial content - (File: main.go)

### Summary
The Solmate report's core defect is a "cheap" validation that returns success without verifying the actual, complete result of an operation, letting an attacker exploit the gap between "looks done" and "is actually done." `git-sync`'s `sanityCheckWorktree` in [1](#0-0)  has the same class of gap: it only checks that the worktree directory is non-empty and that `rev-parse HEAD` matches the expected hash, which the code's own comment admits is insufficient.

### Finding Description
`sanityCheckWorktree` is documented as incomplete by its own author: [2](#0-1) 

It performs three checks — non-empty directory, `rev-parse HEAD` equals the expected hash, and `git fsck --connectivity-only` — none of which verify that every tracked file was actually written to disk. `git fsck --connectivity-only` only checks that objects reachable from refs exist in the object database; it does not check the working tree contents against the index. `rev-parse HEAD` succeeds as soon as the ref file is updated, which in a `git reset --hard <hash>` can occur (or be observed) independent of whether every blob was fully materialized on disk (e.g., if the process is interrupted by `--sync-timeout` mid checkout, per [3](#0-2) , or the submodule step in [4](#0-3)  is interrupted after some submodules are populated and others are not).

This check is invoked in the steady-state branch of `SyncRepo` precisely when `currentHash == remoteHash`, i.e., when git-sync believes "nothing changed, so no need to run `configureWorktree` again": [5](#0-4) 

If the check returns `true` for a worktree that is only partially checked out, git-sync will treat the already-published symlink target as good indefinitely (as long as the upstream ref doesn't move), and the already-served `--link` output remains partial/incomplete without git-sync ever noticing or attempting to repair it during that run. This mirrors the ERC20 pattern: a shallow, "it returned success" check stands in for genuine confirmation that the expected side effect (a token credit / a fully materialized working tree) occurred.

### Impact Explanation
If exploited, this results in **publishing wrong or partial content** to consumers of the `--link` path — the exact contract git-sync promises never to violate ("consumers will not see a partially updated or inconsistent state," per the README's atomic-symlink contract). Downstream containers/applications reading from `--link` could silently operate on truncated repository content (missing files, incomplete submodules) while git-sync continues to report success (`git_sync_count_total`/no error), because the shallow sanity check keeps passing on subsequent loops.

### Likelihood Explanation
This requires a specific interruption window (process kill, `--sync-timeout` expiry, OOM, or disk pressure) to occur *during* `configureWorktree`'s `reset --hard` or `submodule update` step, after the ref/HEAD has been updated but before all files are written — combined with the upstream ref not changing afterward (so `configureWorktree` is never re-run to fully "heal" the state on next process start via the `git.syncCount == 0` re-configure path in [6](#0-5) ). An attacker who controls the upstream repository content (e.g., very large blobs/submodules to make checkout slow and increase the chance of a timeout mid-write, combined with a tight `--sync-timeout`) can increase the likelihood of triggering this window, but cannot deterministically force it — this is analogous to the original finding being rated "incredibly unlikely" but still accepted as Medium.

### Recommendation
Strengthen `sanityCheckWorktree` to verify the working tree actually matches the index/expected tree, not just that `HEAD` points to the right commit and objects are connectible. For example, run `git status --porcelain` (checking for no unexpected deletions vs. index) or `git diff --quiet HEAD` / `git diff-index --quiet HEAD --` to confirm the working tree exactly matches the checked-out commit, and verify submodule status (`git submodule status --recursive`) reports no uninitialized (`-`) or out-of-date submodules when `--submodules` is enabled. Only treat the worktree as valid ("no update required") if these stronger checks pass; otherwise force a full re-`configureWorktree` (as already happens for `syncCount == 0`) even when `currentHash == remoteHash`.

### Proof of Concept
1. Attacker pushes a commit containing a large file (or several submodules) to the synced repository/branch, or specifically to a submodule referenced from `.gitmodules`, sized so that `git reset --hard <hash>` / `git submodule update --init --recursive` in [7](#0-6)  takes longer than `--sync-timeout` to complete under load.
2. `git-sync` starts the sync loop with `context.WithTimeout(..., *flSyncTimeout)`; the loop begins `configureWorktree`, and `reset --hard` updates `HEAD`/the ref before the context deadline is hit mid checkout of large blobs.
3. The sync-timeout context cancels the `git.Run` call; `SyncRepo` returns an error without ever calling `publishSymlink`, but the on-disk worktree directory under `.worktrees/<hash>` is left with `HEAD` correctly pointing at the target hash while some files are missing/truncated.
4. On a subsequent loop iteration (or after the process/container restarts and this exact worktree happens to still be the linked target from a prior partial success under different git internals/versions), if `currentHash == remoteHash` for this worktree, `sanityCheckWorktree` is invoked: `dirIsEmpty` returns false (some files exist), `rev-parse HEAD` returns the correct hash, and `git fsck --connectivity-only` succeeds (all committed objects are present in the object database even if not checked out to disk). The function returns `true`.
5. Git-sync logs "update not required" and keeps serving the (partially checked out) worktree via `--link` to consumers indefinitely, until the upstream ref changes again.

Note: I could not fully verify within this session whether current git internals allow `HEAD`/ref update to be observably "ahead" of a fully-written working tree strictly inside the exact window a `context.CancelFunc` would fire (this depends on git's internal write ordering, which I did not trace at the C-source level) — this is the main area of uncertainty in establishing deterministic exploitability versus the crash/kill-based variant already anticipated by the code's own comment.

### Citations

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

**File:** main.go (L1918-1918)
```go
	if changed || git.syncCount == 0 {
```
