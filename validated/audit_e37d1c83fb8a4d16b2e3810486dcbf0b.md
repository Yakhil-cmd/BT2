### Title
Attacker-controlled symlink target is trusted as the "current worktree" and later deleted with `os.RemoveAll`, allowing arbitrary directory deletion outside `--root` - (File: main.go)

### Summary
The Maia report's root cause is that a value obtained from a less-trusted context (the branch-chain recipient) was reused, without validation, as the authority for a privileged operation (redeeming/reclaiming funds) in a different trust domain. The reachable analog in `git-sync` is `currentWorktree()`, which reads whatever the `--link` symlink currently points to and treats that path as trusted "current state," including passing it straight into destructive filesystem operations (`os.RemoveAll`) elsewhere in the sync loop, without ever confirming the target is actually inside `--root`.

### Finding Description
`currentWorktree()` reads the on-disk symlink and returns its target as a `worktree` value with no bounds checking: [1](#0-0) 

If `target` is an absolute path, the function returns it verbatim (`worktree(target)`) as the "current worktree." This value then flows, unsanitized, into two destructive code paths:

1. `sanityCheckWorktree` failure path, which calls `removeWorktree` on `currentWorktree`: [2](#0-1) 

2. The general "old worktree from a prior version" cleanup path: [3](#0-2) 

`removeWorktree` performs `os.RemoveAll(worktree.Path().String())` on whatever path was derived from the symlink, with no verification that the path is a descendant of `git.root`: [4](#0-3) 

The design intent (per the README's "symlink contract") is that the `--link` symlink is only ever written by `git-sync` itself, always pointing at `<--root>/.worktrees/<hash>`, via `publishSymlink`, which does construct the link relative to `linkDir`: [5](#0-4) 

However, `currentWorktree()` does not enforce this invariant when *reading back* the link. It only distinguishes absolute vs. relative targets and blindly reconstructs a path from whatever bytes `os.Readlink` returns - the equivalent of the Maia bug's mistake of reusing an externally-supplied value (the branch-chain recipient) as an internally-trusted authority value (the refundee) without validating it belongs to the trusted domain (the Root Chain / here, `--root`).

Anyone who can write to the shared volume that backs `--link` (e.g., a co-located sidecar/init container in the same pod sharing the volume, or a compromised process with write access to the directory containing the symlink but not to `--root` itself) can replace the symlink with one pointing to an arbitrary absolute path (e.g. `/etc`, `/data`, or any path reachable by the git-sync process's UID). On the next sync cycle, if `sanityCheckWorktree` fails for that bogus "worktree" (which it will, since it's not a real worktree), git-sync calls `os.RemoveAll` on that attacker-chosen path.

### Impact Explanation
This allows file/directory deletion outside `--root`, which the rules explicitly list as an accepted impact ("file write or delete outside `--root`"). Depending on the UID git-sync runs as and volume-mount topology in a Kubernetes sidecar deployment, this can delete arbitrary data reachable by the container's filesystem view, or at minimum cause persistent sync denial by repeatedly targeting a bogus/critical path.

### Likelihood Explanation
Exploitation requires the ability to overwrite the file at `--link` (or the directory containing it) without also controlling `--root`/`.worktrees` — a realistic split-privilege scenario in Kubernetes sidecar deployments where `--link`'s parent directory is a shared volume mounted read-write into multiple containers while `--root` is private to the git-sync container (a common documented pattern per the "Kubernetes Deployment" wiki page). No special git-sync flags are required beyond normal operation; the flaw triggers automatically as part of the standard sync loop (`SyncRepo`) whenever the symlink is unexpectedly not a valid worktree path.

### Recommendation
In `currentWorktree()`, after resolving `target` to an absolute path, validate that it is a lexical descendant of `git.root` (e.g., using `filepath.Rel` and rejecting results starting with `..`, or comparing against `git.root.Join(".worktrees", ...)`). If the resolved path escapes `--root`, treat the link as invalid/corrupt (log and reset) rather than returning it as a `worktree` value that later gets passed to `os.RemoveAll`.

### Proof of Concept
1. Deploy `git-sync` with `--root=/root` and `--link=/shared/link`, where `/shared` is a volume also writable by another (lower-privileged) container/process.
2. From that other process, replace `/shared/link` with a symlink pointing to an arbitrary absolute path, e.g. `ln -sfn /shared/victim-dir /shared/link`.
3. On the next sync tick, `currentWorktree()` reads the symlink and returns `worktree("/shared/victim-dir")` because `filepath.IsAbs(target)` is true (main.go:1851-1852).
4. `sanityCheckWorktree` fails for this bogus worktree (it has no valid `.git` reference for a real hash), triggering `git.removeWorktree(ctx, currentWorktree)` (main.go:1904-1907), which executes `os.RemoveAll("/shared/victim-dir")` (main.go:1633), deleting the attacker-chosen (or arbitrary) directory outside of `--root`.

### Citations

**File:** main.go (L1592-1620)
```go
func (git *repoSync) publishSymlink(worktree worktree) error {
	targetPath := worktree.Path()
	linkDir, linkFile := git.link.Split()

	// Make sure the link directory exists.
	if err := os.MkdirAll(linkDir.String(), defaultDirMode); err != nil {
		return fmt.Errorf("error making symlink dir: %w", err)
	}

	// linkDir is absolute, so we need to change it to a relative path.  This is
	// so it can be volume-mounted at another path and the symlink still works.
	targetRelative, err := filepath.Rel(linkDir.String(), targetPath.String())
	if err != nil {
		return fmt.Errorf("error converting to relative path: %w", err)
	}

	const tmplink = "tmp-link"
	git.log.V(2).Info("creating tmp symlink", "dir", linkDir, "link", tmplink, "target", targetRelative)
	if err := os.Symlink(targetRelative, filepath.Join(linkDir.String(), tmplink)); err != nil {
		return fmt.Errorf("error creating symlink: %w", err)
	}

	git.log.V(2).Info("renaming symlink", "root", linkDir, "oldName", tmplink, "newName", linkFile)
	if err := os.Rename(filepath.Join(linkDir.String(), tmplink), git.link.String()); err != nil {
		return fmt.Errorf("error replacing symlink: %w", err)
	}

	return nil
}
```

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

**File:** main.go (L1986-1993)
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
