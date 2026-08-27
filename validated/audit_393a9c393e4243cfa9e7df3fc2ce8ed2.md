## Analysis

The reported bug class is: an operation that reports "success" (no error/revert) while not actually completing the expected state change, allowing insolvency/partial-content delivery to downstream consumers. The strongest reachable analog in `git-sync` is the `sanityCheckWorktree` gap that is explicitly documented but not fixed in the code.

### Title
Incomplete-checkout detection gap allows a crafted repo to make git-sync durably publish a partial/corrupted worktree - (File: `main.go`)

### Summary
`git-sync`'s atomic-publish contract relies on `sanityCheckWorktree` to decide whether an already-published worktree is trustworthy before re-using it (i.e., before deciding a re-sync/re-checkout is unnecessary). This function only checks that the directory is non-empty, that `HEAD` matches the expected hash, and that `git fsck --connectivity-only` passes — none of which guarantee the working tree files were actually fully checked out.

### Finding Description
`sanityCheckWorktree` explicitly documents its own weakness: [1](#0-0) 

```
// sanityCheckWorktree tries to make sure that the dir is a valid git
// repository.  Note that this does not guarantee that the worktree has all the
// files checked out - git could have died halfway through and the repo will
// still pass this check.
```

The check itself only verifies emptiness, `HEAD`, and `fsck` connectivity: [2](#0-1) 

In `SyncRepo`, this function is the *only* gate used to decide whether the currently-published worktree (reached via the `--link` symlink) can continue to be served when the remote hash has not changed: [3](#0-2) 

Meanwhile, when a *new* hash is checked out, `createWorktree` + `configureWorktree` (which performs the actual `git reset --hard <hash> --` that populates files) are called, and if they return without error the code proceeds directly to `publishSymlink` with no post-checkout sanity/completeness verification at all: [4](#0-3) [5](#0-4) 

If the git-sync process is terminated (e.g., OOM-killed by the container runtime, which is the documented deployment model for this tool as a Kubernetes sidecar) in the middle of `git reset --hard`, the working tree can be left with a subset of files materialized while the git index/HEAD metadata already reflects the target hash. On the very next sync loop iteration, since the remote hash is unchanged, `sanityCheckWorktree` will pass (non-empty, correct `HEAD`, `fsck --connectivity-only` succeeds because the object database itself is intact even though the working copy isn't fully populated), so git-sync will conclude "no update required" and continue silently serving the partial directory through the `--link` symlink indefinitely.

An attacker who controls the content of the synced repository (a normal, expected threat actor for `git-sync`, which fetches attacker/author-controlled refs) can deliberately shape a commit to maximize the chance of this race — e.g., very large blobs/many files that make `git reset --hard` slow and memory/IO intensive, increasing the odds that a resource-constrained sidecar container gets killed mid-checkout.

### Impact Explanation
This matches the accepted impact category "publishing wrong or partial content" and "persistent sync denial": once the partial worktree passes `sanityCheckWorktree`, git-sync has no mechanism to detect or self-heal the corruption — it will keep reporting the sync as healthy (`setRepoReady`, `metricGoodSyncCount`) while consumers of the `--link` directory silently read an incomplete/inconsistent tree, breaking the atomic-publish guarantee that is the entire design purpose of `git-sync` (see the "Atomic Update Contract" in the project's own docs).

### Likelihood Explanation
Likelihood is moderate: it requires the git-sync process itself (not just the `git` subprocess) to be terminated mid-checkout, which is a plausible and even common occurrence in Kubernetes environments (OOM kills, node evictions, `SIGKILL` on pod termination) especially if an attacker crafts an oversized/resource-heavy commit to increase the checkout window and memory pressure. This does not require any credential compromise, malicious operator, or malicious node — only attacker-controlled repository content plus a normal container lifecycle event.

### Recommendation
- Strengthen `sanityCheckWorktree` to verify actual working-tree completeness against the index, e.g. `git status --porcelain` (expect empty) or comparing `git ls-files` counts to on-disk files, rather than relying solely on `fsck --connectivity-only` and `rev-parse HEAD`.
- After `configureWorktree` performs `git reset --hard`, explicitly re-run the sanity check on the *new* worktree before calling `publishSymlink`, instead of trusting a clean exit code from `git.Run` alone.
- Consider using a marker file (write-then-fsync, then rename) inside the worktree that is only created after checkout fully completes, and gate both initial-use and republish decisions on that marker's presence — an approach analogous to the recommended "sanity check enforcing balance increased by the desired amount" from the original ERC20 report, applied to filesystem completeness instead of token balances.

### Proof of Concept
1. Configure `git-sync` against a repo containing a very large tree/blob set so that `git reset --hard <hash>` inside `configureWorktree` (`main.go:1729`) takes a long time and consumes significant memory/IO.
2. While the sidecar is mid-checkout, send `SIGKILL` to the `git-sync` process (simulating an OOM-kill/eviction) — this can be done deterministically in a test harness by sending the signal right after observing (via strace or a debug hook) that `git reset --hard` has started but before it completes.
3. Restart `git-sync` with the same `--root`/`--link` pointing at the partially-populated worktree, and same `--ref` (remote hash unchanged).
4. Observe that `sanityCheckWorktree` (`main.go:1505-1536`) returns `true` because `HEAD` already matches and `fsck --connectivity-only` succeeds, even though `git status --porcelain` inside the worktree would show missing/unmodified files versus a full checkout.
5. `SyncRepo` logs "update not required" and continues serving the partial worktree through `--link` indefinitely, with `metricGoodSyncCount`/`setRepoReady` showing a healthy state to observers.

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

**File:** main.go (L1727-1731)
```go
	// Reset the worktree's working copy to the specific ref.
	git.log.V(1).Info("setting worktree HEAD", "hash", hash)
	if _, _, err := git.Run(ctx, worktree.Path(), "reset", "--hard", hash, "--"); err != nil {
		return err
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

**File:** main.go (L1929-1963)
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
```
