### Title
Unvalidated symlink target in `currentWorktree()` allows arbitrary path deletion outside `--root` - (File: `main.go`)

### Summary
`git-sync` determines its "currently synced" worktree by reading the `--link` symlink and deriving a worktree path/hash from its target, without ever validating that the resolved target is a legitimate git object hash or that it is actually contained within `--root/.worktrees`. This is the same class of defect as the Sherlock finding: an externally influenceable identifier (`tokenID` there, the symlink target / derived "hash" here) is consumed and used to drive further filesystem operations without a validity check, and the eventual failure mode is an unintended, unchecked operation rather than a graceful rejection.

### Finding Description
`currentWorktree()` reads the on-disk symlink and, if the target is absolute, returns it verbatim as the `worktree` value with **no containment check** against `git.root`: [1](#0-0) 

The `worktree.Hash()` accessor simply returns `filepath.Base()` of that value — again with no format/regex validation that it looks like a git SHA: [2](#0-1) 

In `SyncRepo`, this untrusted `currentWorktree`/`currentHash` pair is compared against the freshly fetched remote hash. Whenever they don't match (which is guaranteed if the link was pointed somewhere unexpected, since the "hash" will not equal any real commit), git-sync falls into the "update required" branch and — after publishing the new symlink — removes the *old* `currentWorktree.Path()` directly via `os.RemoveAll`, with no re-validation that this path is still inside `--root/.worktrees`: [3](#0-2) 

The same unchecked path is also used by `removeWorktree`, which calls `os.RemoveAll(worktree.Path().String())` on whatever path was derived from the symlink target: [4](#0-3) 

The publishing side (`publishSymlink`) only ever writes safe, `--root`-relative targets, so under normal operation this can't happen. But `git-sync` is documented to run as a sidecar that shares its `--root` volume (typically a Kubernetes `emptyDir`) with another, less-trusted "app" container, and the code explicitly anticipates that the on-disk state under `--root` can be tampered with between sync loops (see the `worktree_unexpected_removal` and similar e2e tests). Nothing in `currentWorktree()` restricts the symlink target to paths under `git.root`, so if that shared volume content (the `--link` symlink itself, or its target) is replaced by anything with write access to the volume — e.g., a compromised/malicious co-located container — `git-sync` will trust an arbitrary absolute path as its "current worktree" and later `os.RemoveAll` it.

### Impact Explanation
If the attacker can point the `--link` symlink (or any symlink chain read by `currentWorktree()`) at an arbitrary absolute path reachable by the `git-sync` process's file permissions, the next sync cycle will `os.RemoveAll` that path — a file/directory delete outside `--root`, matching the "Accept" criteria (file write/delete outside `--root`). This can cause data loss or persistent sync/service denial for anything sharing that filesystem namespace with the git-sync process.

### Likelihood Explanation
Medium-to-Low. Exploitation requires write access to the shared `--root` volume (e.g., a compromised or malicious sibling container in the same Pod, which is the intended trust boundary in git-sync's sidecar deployment model per the README/kubernetes docs), not control over git-sync's own flags/env (which would be an excluded "malicious operator" scenario). This is a real, reachable but privilege-adjacent path — it does not require compromising git-sync's own configuration, only the shared data volume that other pod-local components read/write.

### Recommendation
In `currentWorktree()`, validate that the resolved symlink target lies within `git.root.Join(".worktrees")` (e.g., via `filepath.Rel` + reject any result starting with `..` or being absolute-outside-root) and validate `worktree.Hash()` against a strict hex-SHA pattern before using it in any comparison or in `os.RemoveAll`/`git` commands. Treat any symlink target failing these checks the same way an already-handled "sanity check failed" worktree is treated (log and disregard, rather than trusting the derived path for deletion).

### Proof of Concept
1. Deploy `git-sync` as a sidecar sharing `--root` (an `emptyDir`) with another container, as in the documented deployment pattern.
2. From the other (attacker-controlled) container, after git-sync has done an initial sync, replace `--root/<link>` with a symlink pointing to an absolute path outside `--root` that the git-sync process has permission to delete (e.g., another subdirectory under the shared volume, or an incidental path in its container filesystem).
3. On the next sync loop, `git.currentWorktree()` reads this tampered symlink and returns the attacker-chosen path unchecked (`main.go:1842-1856`). Because its `Hash()` (basename) won't match the freshly fetched `remoteHash`, `SyncRepo` treats it as "changed" and, after publishing the new correct symlink, calls `os.RemoveAll(currentWorktree.Path().String())` on the attacker-chosen path (`main.go:1989-1993`), deleting it.

### Citations

**File:** main.go (L1622-1640)
```go
// removeWorktree is used to remove a worktree and its folder.
func (git *repoSync) removeWorktree(ctx context.Context, worktree worktree) error {
	// Clean up worktree, if needed.
	_, err := os.Stat(worktree.Path().String())
	switch {
	case os.IsNotExist(err):
		return nil
	case err != nil:
		return err
	}
	git.log.V(1).Info("removing worktree", "path", worktree.Path())
	if err := os.RemoveAll(worktree.Path().String()); err != nil {
		return fmt.Errorf("error removing directory: %w", err)
	}
	if _, _, err := git.Run(ctx, git.root, "worktree", "prune", "--verbose"); err != nil {
		return err
	}
	return nil
}
```

**File:** main.go (L1817-1826)
```go
// worktree represents a git worktree (which may or may not exist on disk).
type worktree absPath

// Hash returns the intended commit hash for this worktree.
func (wt worktree) Hash() string {
	if wt == "" {
		return ""
	}
	return absPath(wt).Base()
}
```

**File:** main.go (L1842-1856)
```go
// currentWorktree reads the repo's link and returns a worktree value for it.
func (git *repoSync) currentWorktree() (worktree, error) {
	target, err := os.Readlink(git.link.String())
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if target == "" {
		return "", nil
	}
	if filepath.IsAbs(target) {
		return worktree(target), nil
	}
	linkDir, _ := git.link.Split()
	return worktree(linkDir.Join(target)), nil
}
```

**File:** main.go (L1985-1993)
```go

		// We can end up here with no current hash but (the expectation of) a
		// current worktree (e.g. the hash was synced but the worktree does not
		// exist).
		if currentHash != "" && currentWorktree != git.worktreeFor(currentHash) {
			// The old worktree might have come from a prior version, and so
			// not get caught by the normal cleanup.
			os.RemoveAll(currentWorktree.Path().String())
		}
```
