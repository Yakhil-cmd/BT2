### Title
Persistent Sync Denial via Submodule "Bomb" in Recursive `git submodule update` - ([File: main.go])

### Summary
`git-sync` fetches an attacker-influenced repository and, when `--submodules recursive` (or `--submodules shallow`) is configured, runs `git submodule update --init [--recursive] [--depth N]` inside a single bounded sync attempt [1](#0-0) . Because the number and nesting of submodules referenced by `.gitmodules`/tree entries is entirely controlled by whoever can push to the synced repository, an attacker with write access to the source repo can craft a very large or deeply/cyclically nested submodule graph that makes this single command exceed the sync's time budget on every attempt, permanently blocking legitimate updates — the same class of low-cost, attacker-controlled amplification against a bounded per-cycle operation described in the report (many cheap "commits" that individually pass validation but collectively overwhelm an iterative, time/gas-bounded execution step).

### Finding Description
The main sync loop wraps each `SyncRepo` call in `context.WithTimeout(context.Background(), *flSyncTimeout)` [2](#0-1) . Inside `SyncRepo`, once a new remote hash is detected, `git-sync` creates a worktree and calls `configureWorktree`, which — for repos configured with submodule support — shells out to `git submodule update --init --recursive` (optionally with `--depth`) using that same request-scoped context [1](#0-0) .

There is no bound in `git-sync` on:
- the number of submodules declared in `.gitmodules`,
- the nesting depth of recursive submodules, or
- the total amount of work `git submodule update --init --recursive` must perform (each submodule requires its own clone/fetch/checkout).

An attacker who can push content to the tracked repository (or to a submodule reachable by an attacker-controlled fork/URL referenced from `.gitmodules`) can add hundreds or thousands of tiny submodule entries, or a deeply nested chain of submodules-of-submodules, none of which individually look abusive, but whose aggregate `git submodule update --init --recursive` cost exceeds `--sync-timeout` (`flSyncTimeout`) every single time it is attempted.

Because the command runs under the loop's context, it will be canceled/killed once the timeout elapses, `SyncRepo` returns an error, and the outer loop logs the failure and retries after `waitTime`/`flPeriod` [3](#0-2) . On retry, `createWorktree` first removes any partial worktree via `removeWorktree` and recreates it [4](#0-3) , then `configureWorktree` runs the same over-long submodule update again — so the pod never converges and never reaches `git.publishSymlink`, i.e., the symlink is never advanced past the last good state. If `--max-failures` is unset or high, this repeats indefinitely; if it is exceeded, the process exits, causing a crash-loop in Kubernetes. Either way, legitimate content updates are perpetually denied.

### Impact Explanation
This matches "persistent sync denial" from the accepted-impact list: a repository owner/committer with push rights (untrusted relative to the operator's expectation that any commit content should sync safely) can permanently stall the sidecar's ability to publish new revisions, without needing any credential leak or privileged access to the git-sync deployment itself. Consumers relying on the symlinked worktree stop receiving updates, and (depending on `--max-failures`) the container may enter a restart loop, amplifying operational disruption.

### Likelihood Explanation
Likelihood is moderate-to-high in any deployment where `--submodules recursive` (or `shallow`) is enabled and the tracked repository (or any of its declared submodule remotes) can receive content from a less-trusted contributor — e.g., CI-driven repos, GitOps repos accepting external PRs merged automatically, or monorepos with submodules pointing at third-party/community-controlled repos. No special privileges beyond ordinary push/merge access to the synced ref are required, and the attack is cheap to construct (adding many/nested `.gitmodules` entries).

### Recommendation
- Bound the cost of submodule processing: enforce a configurable maximum submodule count / recursion depth before invoking `git submodule update --init --recursive`, and reject/skip sync with a clear error if exceeded rather than silently retrying forever.
- Consider running submodule initialization with its own, tighter sub-timeout distinct from the overall `--sync-timeout`, so a runaway submodule tree fails fast with a diagnosable error instead of being retried unboundedly with the same fate.
- Emit a distinct metric/log (e.g., `git_sync_submodule_timeout`) to make this failure mode observable and alertable, distinguishing it from generic timeouts.
- Document that `--submodules recursive` extends trust to the full transitive submodule graph and should only be enabled when all submodule sources are trusted to the same degree as the primary repo.

### Proof of Concept
1. Deploy `git-sync` with `--repo=<target>` `--submodules=recursive` `--sync-timeout=<T>`.
2. As a contributor with push access to `<target>` (or to a submodule remote it references), commit a `.gitmodules` containing hundreds of submodule entries (or a chain of submodules that each reference another submodule, nested many levels deep), each pointing at small-but-numerous remote repos.
3. Push this commit as the new HEAD of the tracked ref.
4. Observe that every `SyncRepo` cycle: fetches the new hash, calls `configureWorktree` → `git submodule update --init --recursive`, and is killed by the `flSyncTimeout` context before completion [5](#0-4) ; the failure/retry loop repeats indefinitely (or the process exits after `--max-failures`), and `publishSymlink` is never reached, so the symlink never advances to the malicious (or any subsequent legitimate) commit [6](#0-5) .

### Citations

**File:** main.go (L1053-1063)
```go
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), *flSyncTimeout)

		if changed, hash, err := git.SyncRepo(ctx, syncHooks); err != nil {
			failCount++
			updateSyncMetrics(metricKeyError, start)
			if maxFails := getMaxFailures(); maxFails >= 0 && failCount >= maxFails {
				log.Error(err, "too many failures, aborting", "failCount", failCount, "maxFailures", maxFails)
				os.Exit(1)
			}
			log.Error(err, "error syncing repo, will retry", "failCount", failCount)
```

**File:** main.go (L1642-1663)
```go
// createWorktree creates a new worktree and checks out the given hash.  This
// returns the path to the new worktree.
func (git *repoSync) createWorktree(ctx context.Context, hash string) (worktree, error) {
	// Make a worktree for this exact git hash.
	worktree := git.worktreeFor(hash)

	// Avoid wedge cases where the worktree was created but this function
	// error'd without cleaning up.  The next time thru the sync loop fails to
	// create the worktree and bails out. This manifests as:
	//     "fatal: '/repo/root/nnnn' already exists"
	if err := git.removeWorktree(ctx, worktree); err != nil {
		return "", err
	}

	git.log.V(1).Info("adding worktree", "path", worktree.Path(), "hash", hash)
	_, _, err := git.Run(ctx, git.root, "worktree", "add", "--force", "--detach", worktree.Path().String(), hash, "--no-checkout")
	if err != nil {
		return "", err
	}

	return worktree, nil
}
```

**File:** main.go (L1733-1747)
```go
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

**File:** main.go (L1947-1963)
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
```
