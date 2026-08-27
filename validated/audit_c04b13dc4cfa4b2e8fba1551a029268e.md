### Title
Persistent Denial of Sync via Attacker-Controlled Commit Causing Permanent `configureWorktree` Failure (Default `--max-failures=0`) - (File: main.go)

### Summary
`git-sync` fetches a ref cheaply and only performs the expensive/validating work (worktree creation, checkout, submodule update, fsck) in a second stage. If an attacker with push access to the synced branch commits content that makes this second stage fail deterministically (e.g., a submodule pointing at an unreachable or malicious URL, or otherwise-corrupt tree/objects), every future sync attempt against that same ref will fail identically. Because the default `--max-failures` is `0`, `git-sync` aborts the process (`os.Exit(1)`) on the very first such failure, and since Kubernetes will restart the sidecar, the container enters a permanent crash-restart cycle, denying any further sync progress until an operator manually intervenes on the upstream branch.

### Finding Description
`SyncRepo` splits work into a cheap "fetch" phase and an expensive "materialize" phase: [1](#0-0) 

then, if the ref changed (or on first run), it creates/reconfigures the worktree, which includes checkout and submodule update: [2](#0-1) [3](#0-2) 

`configureWorktree` runs `git submodule update --init` unconditionally when submodules are enabled (the default), meaning it will attempt to fetch from any submodule URL present in `.gitmodules`, which is fully attacker-controlled content coming from the synced repo. If that submodule points to an unreachable host, a huge/slow endpoint, or a URL causing repeated failures, `configureWorktree` returns an error and `SyncRepo` bubbles it up without any partial-state fix-up other than the "wedge" cleanup that only runs on the *next* `createWorktree` call: [4](#0-3) 

In the main loop, any error from `SyncRepo` increments `failCount` and is compared against `getMaxFailures()`, which defaults to `0` (abort on first failure) unless explicitly overridden: [5](#0-4) [6](#0-5) 

Because the ref (branch/tag) still points at the same bad commit on every restart, the fetch phase will keep succeeding cheaply while the checkout/submodule phase keeps failing identically — there is no way for the process to make forward progress without a new, fixed commit being pushed upstream. This is directly analogous to the referenced Batching Manager finding: a two-phase operation where phase 1 (cheap/fetch, or `executeBatchStake`) succeeds but phase 2 (expensive validation/checkout, or `executeBatchDeposit`) fails deterministically for a given input, permanently blocking forward progress until external remediation.

### Impact Explanation
With the documented default configuration (`--max-failures=0`, submodules enabled by default), an attacker who can push a single commit to the tracked ref can force `git-sync` into an unrecoverable crash-restart loop. Consumers relying on the `--link` symlink stop receiving any updates, and the sidecar container never reaches a healthy/ready state again (`setRepoReady()` is never reached), constituting a persistent sync denial reachable purely from repo content pushed by an unprivileged (from git-sync's perspective) but repo-write-capable actor. This matches the "persistent sync denial" impact category.

### Likelihood Explanation
Likelihood is moderate-to-high for any deployment where the pushing identity is not fully trusted (e.g., CI bots, multiple contributors, or a compromised upstream) and `--max-failures`/`--init-max-failures` are left at their defaults. No special git-sync flags are required to trigger the failure beyond default submodule handling; only the attacker needs write access to the tracked branch to introduce a submodule (or other checkout-breaking content) that is guaranteed to fail during `configureWorktree`.

### Recommendation
- Make submodule/checkout failures in `configureWorktree` retryable without necessarily aborting the whole container, e.g., treat post-fetch validation failures the same as transient errors but avoid hard process exit by default.
- Consider defaulting `--max-failures` to a small positive/negative-retry-forever value rather than `0`, or clearly re-emphasize in docs that any repo content controllable by less-trusted committers (including submodule URLs) can trigger process termination.
- Add a circuit breaker that detects "same hash repeatedly failing the same way" and surfaces this distinctly (e.g., mark unready but keep retrying at a backoff) instead of exiting the process, so Kubernetes restart policies don't turn a content-triggered failure into a permanent crash loop.

### Proof of Concept
1. Deploy `git-sync` with default flags against a repo where the operator does not fully trust all committers, e.g.:
   `git-sync --repo=<repo> --root=/git --link=link` (defaults: `--max-failures=0`, submodules enabled).
2. Attacker with push access to the tracked branch adds a `.gitmodules` entry with a submodule URL pointing to an unreachable host (or one that always errors), then commits and pushes it as the new HEAD of the tracked ref.
3. On next sync cycle: `fetch` succeeds (cheap, gets the new commit) at [1](#0-0) ; `createWorktree` succeeds; `configureWorktree`'s `git submodule update --init` fails at [7](#0-6) , causing `SyncRepo` to return an error.
4. Main loop increments `failCount`, and since `getMaxFailures()` returns `0` by default, `os.Exit(1)` is called immediately: [8](#0-7) .
5. Kubernetes restarts the pod; the same bad commit is fetched and fails identically every time, producing a permanent CrashLoopBackOff and no further updates via `--link` until the upstream branch is fixed by an operator.

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

**File:** main.go (L1885-1897)
```go
	if err := git.fetch(ctx, git.ref); err != nil {
		return false, "", err
	}

	// Figure out what we got.  The ^{} syntax "peels" annotated tags to
	// their underlying commit hashes, but has no effect if we fetched a
	// branch, plain tag, or hash.
	var remoteHash string
	if output, _, err := git.Run(ctx, git.root, "rev-parse", "FETCH_HEAD^{}"); err != nil {
		return false, "", err
	} else {
		remoteHash = strings.Trim(output, "\n")
	}
```

**File:** main.go (L1929-1945)
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
```

**File:** main.go (L2790-2794)
```go
    --max-failures <int>, $GITSYNC_MAX_FAILURES
            The number of consecutive failures allowed before aborting.
            Setting this to a negative value will retry forever.  If not
            specified, this defaults to 0, meaning any sync failure will
            terminate git-sync.
```
