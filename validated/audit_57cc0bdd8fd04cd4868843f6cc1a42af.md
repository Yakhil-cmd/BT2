### Title
Persistent sync denial via attacker-controlled unbounded submodule/ref processing during a single sync-timeout window - (File: main.go)

### Summary
`git-sync`'s per-iteration sync operation (`SyncRepo` → `fetch` → `configureWorktree`) performs `git submodule update --init [--recursive]` over the full submodule graph of whatever commit the upstream repository currently has checked out [1](#0-0) . Because the upstream repository's content (including its `.gitmodules` and nested submodule references) is attacker-controlled data that flows unfiltered into a single git command invocation bounded only by the fixed `--sync-timeout` (default 120s) [2](#0-1) , the cost of this step scales with the number/depth of submodules the attacker adds, with no cap on submodule count, recursion depth, or per-submodule size — structurally the same "unbounded work driven by an attacker-influenced list, no protective refund/limit" pattern as the referenced Sherlock finding's `lockedWhileVotesCast` loop over `activeProposals`.

### Finding Description
Each sync pass runs within a single `context.WithTimeout(..., *flSyncTimeout)` [3](#0-2) . Inside that budget, `git-sync` calls `fetch` (network I/O over the whole ref) and then, for every worktree checkout, `configureWorktree` invokes `git submodule update --init --recursive` (or the shallow variant) with no limit on submodule count or nesting depth [1](#0-0) . The set and depth of submodules is dictated entirely by `.gitmodules` content committed to the upstream repository — i.e., by whoever can push to the repo `git-sync` is configured to follow. If that party (or anyone able to influence the tracked ref/branch, e.g., via a merged PR in a CI-triggered `--repo`) adds a very large number of submodules, or deeply nested/recursive submodule chains, the `git submodule update --init --recursive` call can take arbitrarily long, exceeding `--sync-timeout` on every attempt.

When a sync attempt errors out (context deadline exceeded), `failCount` increments; once it reaches `--max-failures`, `git-sync` calls `os.Exit(1)` [4](#0-3) . In a Kubernetes sidecar deployment this leads to a container CrashLoopBackOff, and because the *next* attempt hits the exact same oversized submodule graph, the failure is not transient — it recurs on every restart, producing a persistent inability to sync (the analog to "unstaking always reverting/being unaffordable due to attacker-inflated active-proposal count").

Unlike the Solidity case (gas cost paid directly by the caller), here the "cost" is wall-clock time consumed against the shared `--sync-timeout` budget, and the consequence is denial of the atomic-publish sync loop rather than a monetary loss — but the root cause class (unbounded iteration/work over an attacker-influenced collection with no size/depth guard) is the same.

### Impact Explanation
This can cause `git-sync` to permanently fail to publish new commits (denial of the sync/publish contract that is the sidecar's core guarantee, per README's atomic publish contract description) once an attacker (or any party with write/merge access equal to whoever `git-sync` trusts as `--repo`) commits an oversized/deeply-nested submodule tree. Existing consumers keep serving the last-good worktree, but the pipeline stops progressing, and repeated crash-looping consumes CPU/network resources on every restart. This matches the "persistent sync denial" acceptance criterion.

### Likelihood Explanation
Likelihood depends on the threat model for who can influence the commit tree of the tracked `--repo`/`--ref`. In scenarios where `git-sync` follows a branch that receives contributions from lower-trust parties (e.g., PR-merge automation, shared repos, or a compromised upstream dependency listed as a submodule), an attacker only needs to add many/nested submodule entries in `.gitmodules` — no privileged access to `git-sync` itself, its `--root`, or its credentials is required. Default `--submodules=recursive` means this exposure exists out of the box unless operators explicitly set `--submodules=off`.

### Recommendation
- Do not default to `--submodules=recursive`; consider making a bounded, opt-in setting.
- Add a configurable maximum submodule count/recursion depth check before running `git submodule update`, and fail fast (with a clear log/error) if exceeded rather than silently timing out.
- Consider giving submodule processing its own timeout budget distinct from `--sync-timeout`, so a submodule blow-up degrades gracefully (skips submodules, keeps the primary content published) instead of failing the whole sync and tripping `--max-failures`.

### Proof of Concept
1. Deploy `git-sync` with default flags (`--submodules=recursive`) pointed at a repository the "attacker" can commit/merge to.
2. Attacker commits `.gitmodules` referencing hundreds/thousands of submodules (or a submodule chain nested many levels deep, each adding its own submodules) at HEAD of the tracked ref.
3. `git-sync`'s `configureWorktree` runs `git submodule update --init --recursive` [5](#0-4)  against this graph; the operation exceeds `--sync-timeout` (e.g., 120s default).
4. `failCount` increments each cycle [6](#0-5) ; once `--max-failures` is reached, the process exits, and on restart hits the identical oversized graph — an unrecoverable, persistent sync failure without any manual intervention (e.g., disabling submodules) on the operator's part.

### Citations

**File:** main.go (L204-206)
```go
	flSyncTimeout := pflag.Duration("sync-timeout",
		envDuration(120*time.Second, "GITSYNC_SYNC_TIMEOUT", "GIT_SYNC_SYNC_TIMEOUT"),
		"the total time allowed for one complete sync, must be >= 10ms; --timeout overrides this")
```

**File:** main.go (L1053-1054)
```go
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), *flSyncTimeout)
```

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
