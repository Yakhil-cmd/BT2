### Title
Single failing submodule aborts the entire sync, causing persistent sync denial - ([File: main.go])

### Summary
`repoSync.configureWorktree` runs a single all-or-nothing `git submodule update --init [--recursive]` command over every submodule declared in the attacker-controlled repository content, mirroring the `AssetManager.rebalance` pattern of iterating multiple sub-resources and failing the whole operation if any single one is unavailable.

### Finding Description
When git-sync detects a new commit, `SyncRepo` creates a worktree and then calls `configureWorktree`, which (unless `--submodules=off`) runs one `git submodule update --init [--recursive]` command covering all submodules referenced by `.gitmodules` in that commit: [1](#0-0) 

This is a single git invocation that must succeed for every submodule at once — there is no per-submodule fallback or partial-success handling, just like `AssetManager.rebalance` withdrawing from every money market in one all-or-nothing loop. If any one submodule reference is unreachable (dead host, private repo, network partition, or a URL an attacker who can push commits deliberately points at a non-existent/very slow endpoint), the whole `submodule update` command returns a non-nil error, which `configureWorktree` propagates directly: [2](#0-1) 

That error is bubbled straight up out of `SyncRepo` before the symlink is ever touched: [3](#0-2) 

Because `publishSymlink` is only called *after* `configureWorktree` succeeds, a single bad submodule reference in the target commit prevents git-sync from ever reaching that commit's published state: [4](#0-3) 

### Impact Explanation
The `--link` symlink is the entire "contract" that downstream consumers rely on for atomic, up-to-date data. Since the sync loop retries `SyncRepo` from scratch every `--period`, a single broken/unreachable submodule commit will cause every subsequent attempt to fail identically until the repository's HEAD moves past that commit or the submodule host becomes reachable again. This meets the accepted "persistent sync denial" impact — publishing is blocked indefinitely by a condition entirely outside git-sync's control, and it is reachable purely from attacker-pushed repository content (an attacker who can commit to the synced ref, e.g. via a webhook-triggered branch update or a compromised upstream contributor, can add/point a submodule at an address that is slow or unreachable).

### Likelihood Explanation
Requires `--submodules` to not be `off` (recursive is the default per README), and requires the attacker to control content merged into the synced ref (a `.gitmodules` entry or submodule gitlink pointing at an unreachable/slow remote). This is a realistic scenario for any git-sync deployment tracking a branch that accepts external contributions or webhook-driven pushes, similar in spirit to the original finding's requirement of "high utilization" — an externally-influenced, uncontrollable condition (submodule remote availability) that the sync/rebalance logic does not defensively handle.

### Recommendation
Avoid an all-or-nothing `git submodule update`. Options: run `git submodule update --init` per-submodule so a failure in one does not block others, add configurable timeouts/`--jobs` with partial-success tolerance, or fail the *specific* commit and continue publishing the previous good worktree instead of blocking the whole sync loop. At minimum, surface a clear, distinct error/metric so operators know a bad submodule is blocking progress rather than treating it identically to any other fetch error.

### Proof of Concept
1. Deploy git-sync with default `--submodules=recursive` pointed at a repo/ref the attacker can push to (directly or via PR-merge automation).
2. Attacker pushes a commit adding a `.gitmodules` entry with a submodule URL pointing to an unreachable host (e.g., a non-routable IP or a slow/blackholed endpoint).
3. On the next poll, `git.fetch` succeeds (only the superproject is fetched), `createWorktree` succeeds, but `configureWorktree`'s `git submodule update --init --recursive` call at [2](#0-1)  fails/hangs.
4. `SyncRepo` returns the error before calling `publishSymlink`, so the `--link` target is never updated to the new commit, and every subsequent sync attempt repeats the same failure — a persistent denial of forward progress until the offending commit is superseded or the remote becomes reachable.

### Citations

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

**File:** main.go (L1940-1945)
```go
		// Even if this worktree existed and passes sanity, it might not have all
		// the correct settings (e.g. sparse checkout).  The best way to get
		// it all set is just to re-run the configuration,
		if err := git.configureWorktree(ctx, newWorktree); err != nil {
			return false, "", err
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
