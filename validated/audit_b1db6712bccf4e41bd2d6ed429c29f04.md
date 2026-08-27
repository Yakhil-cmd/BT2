### Title
Newly created worktrees are published via the symlink without integrity verification, unlike reused worktrees - (File: main.go)

### Summary
`SyncRepo()` treats a successful exit code from the `git reset --hard` / `git submodule update` commands as sufficient proof that a new worktree is fully and correctly checked out, then immediately flips the publish symlink and calls `setRepoReady()`. This mirrors the reported bug class ("state is marked as successfully completed/finalized without independently verifying the underlying operation actually completed correctly") — the git-sync analog of "marking a promo as `claimed` without verifying the on-chain receipt."

### Finding Description
In `repoSync.SyncRepo` [1](#0-0) , when the locally cached hash already equals the remote hash, git-sync explicitly re-validates the worktree with `sanityCheckWorktree()` — checking that the directory isn't empty, that `HEAD` matches the expected hash, and running `git fsck --connectivity-only` — before trusting it.

However, for the "changed" path, where a *new* worktree is created for a newly fetched commit, no equivalent verification is performed. `createWorktree()` and `configureWorktree()` are invoked [2](#0-1) , and as long as those functions return `nil` (i.e., the underlying `git worktree add`, `git reset --hard`, and `git submodule update` subprocess calls exit 0), the code proceeds directly to `syncHooks.beforePublish`, `git.publishSymlink(newWorktree)`, `syncHooks.afterPublish`, and finally `setRepoReady()` [3](#0-2) . `sanityCheckWorktree` (defined at [4](#0-3) ) is never called on the freshly built worktree before it is published.

This is structurally the same class of defect as the reported bug: an exit-code-only success signal (analogous to a `transfer()` call not reverting) is trusted to mark durable state as complete/published, instead of performing the same independent verification that the codebase itself already performs elsewhere for the "unchanged" case (analogous to the missing `status='pending'` guard / missing receipt verification).

### Impact Explanation
If a checkout, sparse-checkout application, or submodule update ends up leaving an inconsistent or partial worktree without git returning a non-zero exit code (e.g., partially completed nested-submodule updates, sparse-checkout misconfiguration, or a worktree left in an inconsistent state from an interrupted prior run of `configureWorktree` that doesn't surface as a command failure), git-sync will still flip the symlink and report a successful, "ready" sync (`METRIC_GOOD_SYNC_COUNT`/`setRepoReady()`), causing consumers to read wrong or partial content while git-sync's health/metrics indicate success. This falls under "publishing wrong or partial content."

### Likelihood Explanation
Likelihood is limited because `git reset --hard` and `git submodule update` normally do return non-zero exit codes on real checkout failures, so this gap is only exploitable in edge cases (e.g., disk pressure, killed subprocess without propagating a git-level error, or submodule states that git tolerates without erroring). It requires no special flags, but it does require an untrusted-content-driven or environmental corner case that produces a "successful" exit code from git despite an incomplete/incorrect checkout — a narrower condition than a straightforward validation bypass.

### Recommendation
Call `sanityCheckWorktree(ctx, newWorktree)` (or an equivalent check tailored to a freshly built worktree, since `dirIsEmpty`/`HEAD`-match/`fsck` are all applicable) after `configureWorktree` succeeds and before `publishSymlink` is invoked, mirroring the verification already applied to the reused-worktree branch. If the check fails, treat it the same way as the reused-worktree case: remove the worktree and retry rather than publishing it.

### Proof of Concept
1. Configure git-sync with `--submodules` enabled against a repo whose remote content/submodule state can be manipulated by the attacker (e.g., an attacker-controlled upstream branch/ref).
2. Craft a commit/submodule state transition such that `git submodule update --init [--recursive]` exits `0` while leaving the submodule worktree content incomplete or stale relative to the target commit (this is the kind of edge case `sanityCheckWorktree`'s `HEAD`-match and `fsck` checks are designed to catch for the reused-worktree path but are never invoked for the newly-created-worktree path).
3. Observe that `SyncRepo` proceeds to `publishSymlink`, `setRepoReady()`, and reports a successful sync in metrics/logs, even though the published `--link` target does not match the expected/complete content for the target hash — because the integrity check present at [1](#0-0)  is never applied to the path taken at [5](#0-4) .

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

**File:** main.go (L1929-1981)
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
			if currentWorktree != "" {
				// Start the stale worktree removal timer.
				err = touch(currentWorktree.Path())
				if err != nil {
					git.log.Error(err, "can't change stale worktree mtime", "path", currentWorktree.Path())
				}
			}
		}

		err := syncHooks.afterPublish(newWorktree.Hash())
		if err != nil {
			return false, "", err
		}

		// Mark ourselves as "ready".
		setRepoReady()
		git.syncCount++
		git.log.V(0).Info("updated successfully", "ref", git.ref, "remote", remoteHash, "syncCount", git.syncCount)
```
