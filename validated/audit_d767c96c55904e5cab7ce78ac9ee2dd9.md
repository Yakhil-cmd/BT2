### Title
Incomplete worktree checkout can pass sanity checks and be published as valid, permanently serving partial content - ([File: main.go])

### Summary
`git-sync`'s "atomic publish" contract promises that consumers only ever see a fully-synced worktree via the `--link` symlink. This mirrors the raffle contract in the referenced report: a party (the raffle creator / here, the checkout step) is trusted to fully deliver before consumers are told the transaction is done. Just as the raffle creator's `ownerOf` check at `initialize` does not guarantee the NFT stays available for the actual draw, git-sync's `sanityCheckWorktree` check does not guarantee the working tree files are actually fully checked out before the hash is accepted as valid and (re)published.

### Finding Description
`sanityCheckWorktree` explicitly documents this limitation: [1](#0-0) 

It only checks that the directory is non-empty, that `HEAD` matches the expected hash, and runs `git fsck --connectivity-only` (an object-graph reachability check, not a working-tree content check). The actual checkout is performed by `git reset --hard <hash>` in `configureWorktree`: [2](#0-1) 

This command runs under a bounded `--sync-timeout` context (`flSyncTimeout`, default 120s) via `git.Run`/`cmd.Runner`: [3](#0-2) [4](#0-3) 

If the checkout is interrupted before completion (context timeout hit, container OOM-killed by Kubernetes, node preemption, or simply an attacker pushing a very large commit/tree so the reset takes longer than `--sync-timeout`), git may have already updated refs/index metadata for the target commit while working-tree files are still incomplete on disk. On the next loop iteration, `SyncRepo` compares `currentHash == remoteHash` and, if so, treats the worktree as "already correct" and only re-validates it with the weak `sanityCheckWorktree`: [5](#0-4) 

Because `sanityCheckWorktree` doesn't verify the actual file contents (`fsck --connectivity-only` checks reachability of git objects, not that the working directory matches the tree), a partially-checked-out worktree with the right `HEAD` hash can pass this check indefinitely. Since `changed` becomes `false` in this scenario, `SyncRepo` never regenerates the worktree, never re-runs `configureWorktree`, and never republishes the symlink — the `afterPublish` hooks (webhook/exec) may have already fired "success" for the hash on a prior partial run, and no future normal sync will detect or repair the corruption because the hash already matches upstream.

### Impact Explanation
This produces the "publishing wrong or partial content" outcome explicitly called out as an accepted impact class: consumers reading through the `--link` symlink (the documented "contract" per the README) can be served an incomplete/corrupted checkout of the repository state indefinitely, with no automatic self-healing, because the weak sanity check treats the state as valid. This is analogous to the raffle creator being trusted ("ownership was checked once") without any enforcement that the promised deliverable (a fully realized worktree) is actually complete at publish time.

### Likelihood Explanation
This requires an interruption mid-`git reset --hard` (timeout, OOM, signal, node eviction) that leaves the index/HEAD updated but files incomplete — a race condition rather than a fully attacker-controlled trigger. However, an attacker with push access to the synced repository can increase the likelihood by crafting a very large commit/tree (many/huge files) to make the reset run long enough to approach or exceed `--sync-timeout`, combined with normal operational conditions (resource-constrained sidecar, low `--sync-timeout`) that are common in Kubernetes deployments. This makes it a realistic, not purely theoretical, denial/corruption vector.

### Recommendation
Strengthen `sanityCheckWorktree` to verify actual working-tree content integrity (e.g., `git status --porcelain` for unexpected diffs, or comparing checked-out file list/hashes against the tree, or checking a completion marker written only after `configureWorktree` fully succeeds) rather than relying solely on `HEAD` hash equality and `fsck --connectivity-only`. Additionally, consider writing a completion sentinel at the end of `configureWorktree` and requiring that sentinel to be present before treating `currentHash == remoteHash` as "already valid," so an interrupted checkout is always redone rather than silently trusted.

### Proof of Concept
1. Attacker with push access commits a very large tree to the synced branch.
2. Operator's `--sync-timeout` (or pod resource limits causing an OOM kill) fires while `configureWorktree`'s `git reset --hard <hash>` (main.go:1729) is mid-execution, having already updated `HEAD`/index but not finished writing all files.
3. git-sync restarts (or the next loop iteration runs); `SyncRepo` (main.go:1861-1910) sees `currentHash == remoteHash` and calls `sanityCheckWorktree`, which passes because it only checks non-emptiness, `HEAD` hash, and `fsck --connectivity-only`.
4. `changed` is `false`, so no new worktree/checkout/publish occurs; consumers continue reading a partially checked-out tree through `--link` indefinitely, with git-sync reporting healthy/ready status.

### Citations

**File:** main.go (L204-206)
```go
	flSyncTimeout := pflag.Duration("sync-timeout",
		envDuration(120*time.Second, "GITSYNC_SYNC_TIMEOUT", "GIT_SYNC_SYNC_TIMEOUT"),
		"the total time allowed for one complete sync, must be >= 10ms; --timeout overrides this")
```

**File:** main.go (L1053-1056)
```go
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), *flSyncTimeout)

		if changed, hash, err := git.SyncRepo(ctx, syncHooks); err != nil {
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
