### Title
Unbounded submodule tree in synced repo can force `git-sync` to permanently fail every sync attempt - ([File: main.go])

### Summary
`git-sync`'s per-sync work (fetch, reset, worktree checkout, and `git submodule update --init --recursive`) all run under a single `context.WithTimeout(ctx, *flSyncTimeout)` deadline [1](#0-0) . The content and structure of the synced repository — including the number and nesting depth of git submodules declared in `.gitmodules` — is fully controlled by whoever can push to the upstream `--repo`, i.e., untrusted repo content in the git-sync threat model. Because there is no limit on submodule count/depth and no independent timeout budget for the submodule step, an attacker who controls the source repo can make `configureWorktree`'s submodule step exceed `--sync-timeout` on every single sync attempt, producing a persistent, unrecoverable sync failure (and, once `--max-failures` is reached, process termination) — a liveness/DoS effect analogous to the "unbounded list blocks liquidation" bug class.

### Finding Description
`SyncRepo` performs `fetch`, `git reset`, worktree creation, and `configureWorktree` (which runs `git submodule update --init [--recursive] [--depth N]`) all inside one context timeout window [2](#0-1) . Submodule handling is on by default (`--submodules=recursive`) [3](#0-2) , and neither the flag parsing nor `configureWorktree` impose any cap on the number of submodules, the recursion depth, or the time budget dedicated to this step specifically [2](#0-1) .

Because the repository content (and hence `.gitmodules`) is attacker-controlled untrusted input to git-sync, a malicious upstream maintainer/attacker with push access to the synced repo can commit a large or deeply nested submodule tree (many entries, or nested submodules referencing further submodules) so that `git submodule update --init --recursive` alone takes longer than `--sync-timeout` to complete. When `ctx` is canceled, `SyncRepo` returns an error; this error is caught in the main loop, `failCount` is incremented, and the sync is retried on the next `--period` tick [4](#0-3) . Since the underlying condition (huge/slow submodule tree at that ref) is deterministic and repo-side, every subsequent retry will fail identically — the loop never converges. If `--max-failures` is a non-negative bound, `os.Exit(1)` is eventually called, terminating the sidecar entirely [5](#0-4) ; if `--max-failures` is left at its default of `0` (or negative for "retry forever"), the process either exits immediately after the first failure or spins forever retrying the same doomed operation, in both cases never publishing the new commit and denying legitimate consumers of the symlinked data [6](#0-5) .

This is structurally analogous to the Panoptic `positionIdList` bug: a single unbounded, attacker-growable collection (submodule graph vs. position list) is processed in full during a security/liveness-critical operation (sync/publish vs. liquidation) bound by a fixed resource budget (sync-timeout vs. block gas limit), letting the attacker deny the operation indefinitely by inflating that collection.

### Impact Explanation
A successful trigger causes **persistent sync denial**: the sidecar can never publish the new commit/hash to the `--link` target, the health/readiness signal (`setRepoReady`) is never reached for that update [7](#0-6) , and depending on `--max-failures` configuration the process may crash-loop or hang the pod indefinitely. This directly matches the accepted impact class "persistent sync denial."

### Likelihood Explanation
This requires the attacker to have push access to the source repository that `git-sync` is configured to track (the standard "untrusted repo content" threat model explicitly in scope), and requires no special git-sync flags beyond the default submodule behavior (`recursive`, which is already the default). No credentials, cooperating operator, or node compromise is needed — only the ability to add commits/submodules to the upstream repo, which is the exact capability the report's rules identify as in-scope ("attacker-pushed commit"). The main uncertainty is the exact magnitude of submodule count/depth needed to exceed a given `--sync-timeout` in a specific deployment, which is deployment-dependent and was not empirically measured here.

### Recommendation
- Apply an independent, bounded timeout to the submodule update step (and possibly to fetch/checkout individually) rather than sharing the full `--sync-timeout` budget with all other operations, so a pathological submodule graph fails fast without necessarily consuming the whole cycle.
- Consider adding a configurable cap on submodule recursion depth/count (e.g., refuse or warn beyond a threshold) similar to the recommendation in the referenced report to bound "the length of the list being processed."
- Ensure `--max-failures`/backoff behavior is documented clearly for this scenario, and consider surfacing a specific error/metric for "submodule update exceeded timeout" so operators can distinguish this failure mode from transient network issues.

### Proof of Concept
1. Attacker (or malicious/compromised maintainer) with push access to the tracked repo adds `.gitmodules` entries referencing thousands of unique submodule URLs, or nests submodules many levels deep, and commits/pushes this to the ref that `git-sync --ref` tracks.
2. `git-sync` (default `--submodules=recursive`) begins its normal sync loop: `fetch` succeeds and detects a new `remoteHash` [8](#0-7) , then `createWorktree`/`configureWorktree` is invoked, which runs `git submodule update --init --recursive ...` [2](#0-1) .
3. Because the submodule graph is large/deep enough, this command does not finish before the shared `context.WithTimeout(ctx, *flSyncTimeout)` deadline expires [1](#0-0) , causing `SyncRepo` to return an error.
4. The main loop logs the error and increments `failCount` [4](#0-3) ; on the next `--period` tick the identical operation is retried against the same (still oversized) submodule tree and fails again identically, repeating indefinitely (or until `--max-failures` triggers `os.Exit(1)`), so the new commit is never published via `--link`.

### Citations

**File:** main.go (L182-184)
```go
	flSubmodules := pflag.String("submodules",
		envString("recursive", "GITSYNC_SUBMODULES", "GIT_SYNC_SUBMODULES"),
		"git submodule behavior: one of 'recursive', 'shallow', or 'off'")
```

**File:** main.go (L213-215)
```go
	flMaxFailures := pflag.Int("max-failures",
		envInt(0, "GITSYNC_MAX_FAILURES", "GIT_SYNC_MAX_FAILURES"),
		"the number of consecutive failures allowed before aborting (-1 will retry forever")
```

**File:** main.go (L1054-1063)
```go
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

**File:** main.go (L1064-1073)
```go
		} else {
			if !initialSyncDone {
				initialSyncDone = true
				waitTime = *flPeriod
				if *flInitPeriod != *flPeriod {
					log.V(0).Info("initial sync complete, switching to normal period", "initPeriod", flInitPeriod.String(), "period", flPeriod.String())
				}
			}
			// this might have been called before, but also might not have
			setRepoReady()
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

**File:** main.go (L1892-1919)
```go
	var remoteHash string
	if output, _, err := git.Run(ctx, git.root, "rev-parse", "FETCH_HEAD^{}"); err != nil {
		return false, "", err
	} else {
		remoteHash = strings.Trim(output, "\n")
	}

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

	// This catches in-place upgrades from older versions where the worktree
	// path was different.
	changed := (currentHash != remoteHash) || (currentWorktree != git.worktreeFor(currentHash))

	// We have to do at least one fetch, to ensure that parameters like depth
	// are set properly.  This is cheap when we already have the target hash.
	if changed || git.syncCount == 0 {
		git.log.V(0).Info("update required", "ref", git.ref, "local", currentHash, "remote", remoteHash, "syncCount", git.syncCount)
```
