### Title
Attacker-controlled `.gitmodules` in synced repo can permanently block publishing / crash the sidecar (persistent sync denial) - (File: main.go, function `configureWorktree`)

### Summary
`git-sync`'s per-sync worktree preparation step (`configureWorktree`) unconditionally runs `git submodule update --init [--recursive]` on every new worktree whenever `--submodules` is not `off` (the default is not `off`), regardless of whether the checked-out commit actually references valid, reachable submodules. Because the ref being synced is entirely attacker-controlled content (any commit pushed to the tracked branch/tag), a single malicious commit that adds a `.gitmodules` file pointing to an unreachable, malformed, or slow-to-clone submodule URL will make this git command fail every time that commit is at the tip of the tracked ref, exactly analogous to the referenced Backd finding: a state-dependent, unconditional operation whose precondition is controlled by untrusted content and which, when unmet, blocks the entire legitimate workflow rather than just the affected step.

### Finding Description
`configureWorktree` in [1](#0-0)  resets the worktree to the fetched hash and then, if `git.submodules != submodulesOff`, always runs: [2](#0-1) 

The comment explicitly states "this works for repo with or without submodules" — i.e., the code assumes the command is always safe to run and always succeeds regardless of repo content. This mirrors the root cause in the Backd report: an unconditional operation (`burnFees`'s ETH-balance branch) that silently assumes a precondition about the input state (presence of an ETH-underlying pool) which is not actually guaranteed and is controlled by content the caller does not fully own.

In `git-sync`, the "input state" is the git commit content of `--repo`, which is untrusted from the sidecar's perspective (it is fetched from a remote git server or any collaborator with push access to the tracked branch/tag). If that commit introduces a `.gitmodules` referencing:
- an unreachable/typo'd URL,
- a URL requiring credentials the sidecar does not have,
- a submodule pointing at a huge or infinitely-redirecting resource,

then `git submodule update --init` returns a non-zero exit code, and `configureWorktree` returns that error up through `SyncRepo` at [3](#0-2) , aborting the entire sync attempt before `publishSymlink` is ever called for the new hash [4](#0-3) .

This failure propagates to the main loop, which increments `failCount` and, once it reaches `--max-failures`, calls `os.Exit(1)`: [5](#0-4) 

### Impact Explanation
- **Persistent sync denial**: As long as the offending commit remains at the tip of the tracked ref (which the attacker controls by not fixing/reverting it, or simply by controlling the branch), every sync attempt re-fetches the same bad hash, re-creates the worktree, and re-runs the failing submodule update — the symlink is never advanced past the last known-good commit, silently freezing the published content.
- **Sidecar crash / pod disruption**: If `--max-failures` is a small positive number (the flag documents that 0, the default, aborts on the very first failure), the sidecar process calls `os.Exit(1)`, which in a Kubernetes sidecar deployment can cause `CrashLoopBackOff` and, depending on `restartPolicy`/readiness wiring, block the whole pod from becoming ready — a denial of service beyond just the sync itself.
- Unlike the `burnFees` bug (funds get stuck), here the impact is availability: legitimate consumers of the synced volume never receive updates published after the malicious commit, and/or the sidecar container is repeatedly restarted.

### Likelihood Explanation
Likelihood depends on the trust model of the tracked repository: any principal with commit/push access to the branch or tag that `--ref` points to (which is often less trusted than the git-sync operator, e.g., a CI bot, a bot merging PRs, or a repo that accepts external contributions merged automatically) can trigger this by adding or modifying a `.gitmodules` entry with a broken URL. No special git-sync flags beyond the default submodule handling (`--submodules` not set to `off`) are required, and no privileged access to the sidecar or its credentials is needed — only the ability to land a commit on the synced ref. This is a realistic "attacker-pushed commit" scenario matching the requested threat model.

### Recommendation
- Before invoking `git submodule update --init`, verify that the checked-out tree actually contains a `.gitmodules` file (e.g., `git config -f .gitmodules --list` or checking file existence) and skip the submodule step entirely when none is present, rather than unconditionally assuming the command is a no-op for submodule-less repos.
- Consider adding a bounded timeout / retry-limit specifically for the submodule update step, distinct from the overall `--sync-timeout`, and surface a clear, actionable log message distinguishing "submodule fetch failed" from other sync failures.
- Optionally allow keeping the previously-published (good) hash live/stable rather than crash-looping the process outright when only the submodule step fails, so a single bad commit doesn't take down the whole sidecar via `--max-failures`.

### Proof of Concept
1. Deploy `git-sync` with default `--submodules` behavior (not `off`) against a repository the operator does not fully control the commit history of (e.g., accepts PRs merged by another bot), with `--max-failures` left at a small value.
2. An attacker with push access to the tracked branch adds a `.gitmodules` file:
   ```
   [submodule "bad"]
       path = bad
       url = https://nonexistent.example.invalid/bad.git
   ```
   and commits it to the tracked ref.
3. `git-sync`'s next `SyncRepo` call fetches the new hash, creates a worktree via `createWorktree`, then calls `configureWorktree`, which runs `git submodule update --init` per [2](#0-1) ; this fails because the submodule URL cannot be resolved.
4. `SyncRepo` returns the error at [3](#0-2) ; `publishSymlink` is never reached, so the symlink continues pointing at the previous (stale) hash.
5. Every subsequent sync period repeats the same failure since the bad commit remains the ref's tip; once `failCount` reaches `--max-failures`, the process exits via [6](#0-5) , producing a persistent sync/publish denial and sidecar restart loop.

### Citations

**File:** main.go (L1056-1063)
```go
		if changed, hash, err := git.SyncRepo(ctx, syncHooks); err != nil {
			failCount++
			updateSyncMetrics(metricKeyError, start)
			if maxFails := getMaxFailures(); maxFails >= 0 && failCount >= maxFails {
				log.Error(err, "too many failures, aborting", "failCount", failCount, "maxFailures", maxFails)
				os.Exit(1)
			}
			log.Error(err, "error syncing repo, will retry", "failCount", failCount)
```

**File:** main.go (L1665-1750)
```go
// configureWorktree applies some configuration (e.g. sparse checkout) to
// the specified worktree and checks out the specified hash and submodules.
func (git *repoSync) configureWorktree(ctx context.Context, worktree worktree) error {
	hash := worktree.Hash()

	// The .git file in the worktree directory holds a reference to
	// /git/.git/worktrees/<worktree-dir-name>. Replace it with a reference
	// using relative paths, so that other containers can use a different volume
	// mount name.
	var rootDotGit string
	if rel, err := filepath.Rel(worktree.Path().String(), git.root.String()); err != nil {
		return err
	} else {
		rootDotGit = filepath.Join(rel, ".git")
	}
	gitDirRef := []byte("gitdir: " + filepath.Join(rootDotGit, "worktrees", hash) + "\n")
	if err := os.WriteFile(worktree.Path().Join(".git").String(), gitDirRef, 0644); err != nil {
		return err
	}

	// If sparse checkout is requested, configure git for it, otherwise
	// unconfigure it.
	gitInfoPath := filepath.Join(git.root.String(), ".git/worktrees", hash, "info")
	gitSparseConfigPath := filepath.Join(gitInfoPath, "sparse-checkout")
	if git.sparseFile == "" {
		os.RemoveAll(gitSparseConfigPath)
	} else {
		// This is required due to the undocumented behavior outlined here:
		// https://public-inbox.org/git/CAPig+cSP0UiEBXSCi7Ua099eOdpMk8R=JtAjPuUavRF4z0R0Vg@mail.gmail.com/t/
		git.log.V(1).Info("configuring worktree sparse checkout")
		checkoutFile := git.sparseFile

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

		args := []string{"sparse-checkout", "init"}
		if _, _, err = git.Run(ctx, worktree.Path(), args...); err != nil {
			return err
		}
	}

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

	return nil
}
```

**File:** main.go (L1943-1945)
```go
		if err := git.configureWorktree(ctx, newWorktree); err != nil {
			return false, "", err
		}
```

**File:** main.go (L1947-1971)
```go
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
```
