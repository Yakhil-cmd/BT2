### Title
Ignored error return value from `os.RemoveAll` when disabling sparse-checkout can cause `git-sync` to publish stale, incomplete content - (File: main.go)

### Summary
`repoSync.configureWorktree()` disables sparse-checkout by calling `os.RemoveAll(gitSparseConfigPath)` and discarding the returned error, mirroring the reported class of bug ("return value is not used") where an actionable/critical return value from an operation is silently dropped, allowing downstream logic to proceed on a false assumption of success.

### Finding Description
When `--sparse-file` is unset, `configureWorktree` attempts to remove the worktree's existing sparse-checkout configuration file so that the full tree is checked out: [1](#0-0) 
The call `os.RemoveAll(gitSparseConfigPath)` at line 1690 returns an `error` value that is never captured or checked, unlike every other filesystem/git operation in this function, which explicitly checks and propagates errors (e.g. the `os.WriteFile` call two lines above, or the `os.Open`/`os.Mkdir`/`os.Create`/`io.Copy` calls in the sparse-enabled branch): [2](#0-1) [3](#0-2) 
If `os.RemoveAll` fails (e.g. due to a permission issue on the mounted `--root` volume, a transient I/O error, or the file being busy/locked while consumers read it), the stale `sparse-checkout` file remains in `.git/worktrees/<hash>/info/sparse-checkout`. `configureWorktree` proceeds unconditionally to `git reset --hard <hash> --`: [4](#0-3) 
Because git honors the `info/sparse-checkout` file whenever `core.sparseCheckout` remains effectively enabled for that worktree, a leftover sparse-checkout file can cause the subsequent checkout to still exclude paths from a previous configuration, even though the operator explicitly removed `--sparse-file` intending a full checkout.

### Impact Explanation
`git-sync`'s core contract is "atomic publish" of a complete, correct worktree behind the `--link` symlink: [5](#0-4) 
If the sparse-checkout residue is not actually cleared due to the ignored error, `SyncRepo` will still call `publishSymlink` and mark the sync as successful/ready, publishing a worktree with missing files under the new symlink target: [6](#0-5) 
This matches the "publishing wrong or partial content" impact category: consumers relying on the symlink contract receive an incomplete checkout while git-sync logs success and advances `syncCount`, giving no operator-visible signal that anything is wrong.

### Likelihood Explanation
This requires the operator to transition a `repoSync` from sparse to full checkout (unsetting `--sparse-file`/`$GITSYNC_SPARSE_CHECKOUT_FILE`) combined with an `os.RemoveAll` failure on the `--root` volume (e.g. read-only remount, permission drift, NFS/CSI transient error, or a concurrent reader holding the file open on some filesystems). This is a real but narrower operational condition rather than a directly attacker-triggerable path from a malicious push; it depends on environment/filesystem behavior rather than repo content, so likelihood is low-to-moderate and mostly relevant as a silent-failure/robustness gap rather than an actively exploitable vector.

### Recommendation
Check and handle the error returned by `os.RemoveAll(gitSparseConfigPath)` in `configureWorktree` the same way other filesystem operations are handled in this function — return the error (wrapped with context) so that `SyncRepo` aborts and reports failure instead of silently publishing a symlink pointing at a possibly stale/sparse worktree.

### Proof of Concept
Not applicable as a remote/attacker-triggerable PoC — the finding is a code-path/robustness issue, not a directly attacker-reachable exploit. It manifests when:
1. `git-sync` is run first with `--sparse-file=<path>` producing a sparse worktree.
2. The operator disables sparse checkout (removes `--sparse-file`/env var) and triggers a resync.
3. `os.RemoveAll(gitSparseConfigPath)` fails (simulate by making `.git/worktrees/<hash>/info` read-only or the directory non-writable to the git-sync process).
4. `configureWorktree` ignores the error, proceeds to `git reset --hard`, and `SyncRepo` publishes the symlink; the resulting worktree can retain sparse exclusions from the previous configuration despite git-sync reporting a successful sync.

### Citations

**File:** main.go (L1590-1620)
```go
// publishSymlink atomically sets link to point at the specified target.  If the
// link existed, this returns the previous target.
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

**File:** main.go (L1680-1683)
```go
	gitDirRef := []byte("gitdir: " + filepath.Join(rootDotGit, "worktrees", hash) + "\n")
	if err := os.WriteFile(worktree.Path().Join(".git").String(), gitDirRef, 0644); err != nil {
		return err
	}
```

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

**File:** main.go (L1697-1720)
```go
		source, err := os.Open(checkoutFile)
		if err != nil {
			return err
		}
		defer source.Close()

		if _, err := os.Stat(gitInfoPath); os.IsNotExist(err) {
			err := os.Mkdir(gitInfoPath, defaultDirMode)
			if err != nil {
				return err
			}
		}

		destination, err := os.Create(gitSparseConfigPath)
		if err != nil {
			return err
		}
		defer destination.Close()

		_, err = io.Copy(destination, source)
		if err != nil {
			return err
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

**File:** main.go (L1943-1981)
```go
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
