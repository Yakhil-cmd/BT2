## Analysis

The External Report describes a privileged function (`VeToken.burn`) that accepts an arbitrary target address instead of being restricted to the caller's own resource, so a compromised/malicious governance actor can destroy state belonging to any address, not just its own. The reachable analog in `git-sync` is the trust boundary between the `--link` symlink (a filesystem object that lives under `--root`, a shared/mounted volume) and the destructive worktree-removal logic that dereferences it without validating that the resolved target is actually contained inside `--root`.

### Title
Unvalidated symlink target from `--link` allows arbitrary file deletion outside `--root` - (File: `main.go`)

### Summary
`repoSync.currentWorktree()` blindly reads whatever the `--link` symlink points to and turns that into a `worktree` value used later for destructive operations (`os.RemoveAll`), with no check that the resolved path is actually inside `git.root`.

### Finding Description
`currentWorktree()` performs `os.Readlink(git.link.String())` and, for a relative target, joins it onto the link's directory to build the `worktree` value, with no verification that the result stays under `git.root`: [1](#0-0) 

This `worktree` value is then passed to functions that perform destructive filesystem operations without ever re-validating containment under `--root`:

- `removeWorktree` stats and then unconditionally `os.RemoveAll`s the path: [2](#0-1) 

- `SyncRepo` calls `removeWorktree` on the `currentWorktree` whenever `sanityCheckWorktree` fails (e.g., HEAD mismatch, fsck failure, empty dir), and separately does a raw `os.RemoveAll(currentWorktree.Path().String())` for the "stale worktree from a prior version" case: [3](#0-2) [4](#0-3) 

- `removeStaleWorktrees` also derives `currentWorktree` the same way and only special-cases its `Hash()` (i.e., `filepath.Base()`), so if the symlink resolves outside the `.worktrees` directory, the "skip current worktree" logic silently fails to protect anything meaningful while everything else in `.worktrees/` older than `--stale-worktree-timeout` is still deleted via `os.RemoveAll`: [5](#0-4) [6](#0-5) 

Because `--root` is documented as a shared/mounted volume (typically `emptyDir` in Kubernetes, or bind-mounted across multiple sidecars) and `--link` is a path *inside* that root, any process or init step with write access to that shared root before/while `git-sync` runs — the same threat surface the “atomic symlink contract” README section relies on — can place a symlink at the `--link` path pointing to an arbitrary path (e.g. `../../etc` or any absolute path). The very next sync cycle, when `sanityCheckWorktree` inevitably fails (empty dir / wrong HEAD / fsck failure) or the housekeeping path in `SyncRepo` runs, `git-sync` will call `os.RemoveAll` on that attacker-chosen target with no root-containment check anywhere in this call chain.

This mirrors the report’s bug class: a trusted/privileged internal operation (worktree deletion) accepts an “address” (a path derived from external/untrusted state — the symlink target) without validating that it is confined to the resource the operation is meant to affect (paths under `--root`).

### Impact Explanation
An attacker who can influence the contents of the shared `--root` volume before or during a sync cycle (e.g., a co-located untrusted container, an attacker with volume-mount access, or a scenario where the `--link` path is not fully owned by `git-sync`) can cause git-sync to recursively delete an arbitrary directory tree on the host/container filesystem outside `--root`, since `os.RemoveAll` follows the resolved (non-symlink) absolute path with no allow-list/containment check. This satisfies the "file write or delete outside `--root`" acceptance criterion.

### Likelihood Explanation
This requires an actor with some write access to the shared `--root`/link location — not a fully remote, unauthenticated attacker driving only pushed commits. It is most relevant in multi-container/sidecar deployments where `--root` is a shared `emptyDir`/volume and another container or init process could pre-seed or race the `--link` path. Given `git-sync`'s deployment model explicitly assumes a shared volume with other containers, this is a realistic (if not trivially remote) misconfiguration/compromise scenario, making likelihood moderate.

### Recommendation
In `currentWorktree()`, after resolving the symlink target (`main.go:1842-1856`), validate that the resulting absolute path is lexically contained within `git.root` (e.g., using `filepath.EvalSymlinks` + a prefix/`filepath.Rel` check that rejects `..` escapes or absolute targets outside root) before returning it as a `worktree`. If the target escapes `--root`, treat the link as corrupt (log and refuse to touch it, or delete only the symlink itself, never following it into `RemoveAll`) rather than propagating it into `removeWorktree`/`os.RemoveAll`.

### Proof of Concept
1. Deploy `git-sync` with `--root=/root --link=link` on a volume shared with another container/process that has write access to `/root`.
2. Before or during a sync cycle, the co-located process replaces `/root/link` with `ln -s /etc /root/link` (or any absolute path outside `/root`).
3. On the next sync, `currentWorktree()` resolves this to `worktree("/etc")`. Because the actual on-disk content at `/etc` obviously isn't a valid worktree, `sanityCheckWorktree` fails (`dirIsEmpty`/`rev-parse HEAD`/`fsck` mismatch), and `SyncRepo` calls `git.removeWorktree(ctx, currentWorktree)`, which executes `os.RemoveAll("/etc")`. [7](#0-6) [8](#0-7)

### Citations

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

**File:** main.go (L1553-1582)
```go
func removeDirContentsIf(dir absPath, log *logging.Logger, fn func(fi os.FileInfo) (bool, error)) error {
	dirents, err := os.ReadDir(dir.String())
	if err != nil {
		return err
	}

	// Save errors until the end.
	var errs multiError
	for _, fi := range dirents {
		name := fi.Name()
		p := filepath.Join(dir.String(), name)
		stat, err := os.Stat(p)
		if err != nil {
			log.Error(err, "failed to stat path, skipping", "path", p)
			continue
		}
		if shouldDelete, err := fn(stat); err != nil {
			log.Error(err, "predicate function failed for path, skipping", "path", p)
			continue
		} else if !shouldDelete {
			log.V(4).Info("skipping path", "path", p)
			continue
		}
		if log != nil {
			log.V(4).Info("removing path recursively", "path", p, "isDir", fi.IsDir())
		}
		if err := os.RemoveAll(p); err != nil {
			errs = append(errs, err)
		}
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
