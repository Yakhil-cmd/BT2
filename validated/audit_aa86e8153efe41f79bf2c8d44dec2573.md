### Title
Incomplete stale git lock-file detection in `hasGitLockFile`/`sanityCheckRepo` permanently wedges sync after a killed git subprocess - (File: main.go)

### Finding Description
`repoSync.SyncRepo` calls `git.initRepo(ctx)` on every sync iteration [1](#0-0) . `initRepo` only re-validates/wipes the repo directory when it already exists, via `git.sanityCheckRepo(ctx)` [2](#0-1) . `sanityCheckRepo` in turn calls `hasGitLockFile(git.root)`, but that function only checks for a single, specific lock filename, `shallow.lock`, under `.git`: [3](#0-2) . It does not check for other lock files that real git operations create, e.g. `index.lock`, `HEAD.lock`, `packed-refs.lock`, or per-ref lock files under `refs/**.lock`, nor does it check locks inside a worktree's separate git-dir (`.git/worktrees/<hash>/`). `sanityCheckWorktree`, used to validate the currently-checked-out worktree, performs no lock-file check at all [4](#0-3) .

`configureWorktree` runs `git reset --hard` in the worktree (which takes the index lock) and, if submodules are enabled, `git submodule update` [5](#0-4) , and `git fetch`/ref updates in the root repo can leave ref or `packed-refs.lock` files behind. If the underlying `git` child process for any of these operations is killed abruptly (e.g. `exec.CommandContext` sends `SIGKILL` when git-sync's fetch/sync timeout fires while an attacker-controlled server stalls the connection at a chosen point mid-transfer), git does not get to run its normal lockfile cleanup handlers, leaving a stale lock file behind. Because `hasGitLockFile` only recognizes `shallow.lock`, and `sanityCheckWorktree` checks no locks at all, the self-healing "wipe root and re-clone" path in `initRepo` is never triggered for these other lock types. On the next sync loop, the same git operation fails again with "File exists" for the lock, `SyncRepo` returns an error, and the process repeats forever: the repo is never wiped, `setRepoReady()` [6](#0-5)  is never reached, and readiness/liveness permanently stalls with no operator-visible remediation other than manually clearing the volume.

### Impact Explanation
This is a permanent denial-of-sync / liveness failure: git-sync's readiness endpoint never updates and the published symlink is frozen at a stale commit indefinitely, matching the "permanent denial of sync" impact class described in the question. It requires no privileged access — only the ability to control the remote repo server's response timing, consistent with the "controls repo content and refs" attacker model.

### Likelihood Explanation
This requires the attacker-controlled/malicious server to stall a fetch or checkout-triggering operation long enough to exceed git-sync's configured sync/fetch timeout so the git child process is killed mid-operation, and it depends on which specific lock file git leaves at that stall point (only `shallow.lock` is auto-detected and repaired; any other lock type — `index.lock`, ref locks, `packed-refs.lock`, or worktree-scoped locks — is not). This is more likely with default timeout/retry settings under adversarial network conditions than a targeted, single-lock-type exploit, but it is not guaranteed to reproduce every stall since it depends on exact timing of the kill relative to git's internal lock-file lifecycle.

### Recommendation
Broaden `hasGitLockFile` to scan for any `*.lock` file under `.git` (recursively, including `refs/**/*.lock`, `packed-refs.lock`, `index.lock`, `HEAD.lock`) and also check locks inside each worktree's git-dir (`.git/worktrees/<hash>/`). Additionally, add an equivalent lock check to `sanityCheckWorktree` so stale worktree-level locks (e.g. `index.lock` from an interrupted `reset --hard`) also trigger the existing self-healing wipe-and-reclone path in `initRepo`/`removeWorktree`.

### Proof of Concept
Integration test sketch (extends `main_test.go`'s sync-loop tests):
1. Perform a normal `SyncRepo` to get a valid worktree.
2. Simulate a crashed git process by manually creating `<worktree>/.git`-referenced gitdir file `.git/worktrees/<hash>/index.lock` (or `<root>/.git/refs/heads/<branch>.lock`) after a successful sync.
3. Trigger a new commit on the remote and call `SyncRepo` repeatedly.
4. Assert: with current code, `sanityCheckRepo`/`sanityCheckWorktree` keep returning `true` (lock not detected), the fetch/reset operation keeps failing with "File exists" for the lock, `SyncRepo` returns an error on every call, and `getRepoReady()` never becomes true even after many retries — demonstrating the permanent wedge, in contrast to the `shallow.lock` case where `sanityCheckRepo` correctly wipes and recovers.

### Citations

**File:** main.go (L1372-1387)
```go
		// Make sure the directory we found is actually usable.
		git.log.V(3).Info("repo directory exists", "path", git.root)
		if git.sanityCheckRepo(ctx) {
			git.log.V(4).Info("repo directory is valid", "path", git.root)
		} else {
			// Maybe a previous run crashed?  Git won't use this dir.  We remove
			// the contents rather than the dir itself, because a common use-case
			// is to have a volume mounted at git.root, which makes removing it
			// impossible.
			git.log.V(0).Info("repo directory was empty or failed checks", "path", git.root)
			if err := removeDirContents(git.root, git.log); err != nil {
				return fmt.Errorf("can't wipe unusable root directory: %w", err)
			}
			needGitInit = true
		}
	}
```

**File:** main.go (L1443-1455)
```go
func hasGitLockFile(gitRoot absPath) (string, error) {
	gitLockFiles := []string{"shallow.lock"}
	for _, lockFile := range gitLockFiles {
		lockFilePath := gitRoot.Join(".git", lockFile).String()
		_, err := os.Stat(lockFilePath)
		if err == nil {
			return lockFilePath, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return lockFilePath, err
		}
	}
	return "", nil
}
```

**File:** main.go (L1505-1536)
```go
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

**File:** main.go (L1728-1747)
```go
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

**File:** main.go (L1868-1871)
```go
	// Initialize the repo directory if needed.
	if err := git.initRepo(ctx); err != nil {
		return false, "", err
	}
```

**File:** main.go (L1978-1981)
```go
		// Mark ourselves as "ready".
		setRepoReady()
		git.syncCount++
		git.log.V(0).Info("updated successfully", "ref", git.ref, "remote", remoteHash, "syncCount", git.syncCount)
```
