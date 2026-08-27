### Title
Denial of Service via Attacker-Controlled Submodule Tree Exhausting `--sync-timeout` - ([File: main.go])

### Summary
The Talentir report describes an attacker flooding an order book with many cheap entries so that a victim's bounded-gas operation is forced to iterate over unbounded attacker-controlled state until it fails. The equivalent primitive in `git-sync` is `configureWorktree`'s unconditional, unbounded `git submodule update --init --recursive` call driven entirely by the content of the synced repository (`.gitmodules`), executed inside a fixed `--sync-timeout` budget with a fail-fast (`--max-failures=0`) default.

### Finding Description
Every sync, after checking out the target hash, `git-sync` updates submodules with no bound on their number, size, or nesting depth: [1](#0-0) 

The behavior defaults to `recursive`, meaning nested submodules of submodules are also expanded, and the whole operation is attacker-controlled purely through `.gitmodules` and the referenced repositories in the content being synced: [2](#0-1) 

This work happens inside a single `context.WithTimeout(..., *flSyncTimeout)` for the whole `SyncRepo` call, defaulting to 120s: [3](#0-2) 

If that budget is exceeded (e.g., because an attacker who controls the ref being synced — a merged PR, an untrusted fork, or a webhook-triggered branch — adds a large number of submodules, deeply nested recursive submodules, or submodules pointing at very large/slow-to-clone repositories), the sync fails with a context-deadline error. Because the default `--max-failures` is `0`, the very first such failure causes an immediate process exit rather than tolerant retries: [4](#0-3) [5](#0-4) 

Since the repo content (and therefore the cost of the recursive submodule expansion) is deterministic across restarts, a container restart (the normal Kubernetes recovery action) replays the identical expensive operation and fails identically every time — an unbounded, attacker-controlled cost embedded in a bounded-time operation, exactly mirroring the "many cheap orders forcing a bounded-gas loop to fail" pattern in the report. The project's own end-to-end test suite explicitly documents that a slow git operation combined with a short `--sync-timeout` causes the sync to fail and the link to never be created: [6](#0-5) 

### Impact Explanation
This results in persistent sync denial: `git-sync` can never successfully publish an update (or, on first run, never publish at all) once the attacker-controlled submodule tree exceeds what fits in `--sync-timeout`, and with default settings the process aborts (`os.Exit(1)`) rather than degrading gracefully, causing a crash-loop in whatever orchestrator (e.g., Kubernetes) manages the container.

### Likelihood Explanation
Likelihood is moderate to high in any deployment where the synced ref's content is not fully trusted by the operator (e.g., GitOps repos accepting external contributions, mirrored/forked repositories, or CI pipelines that merge PRs before syncing). No special privileges beyond the ability to influence the content that lands on the synced ref/branch are required, and `--submodules=recursive` is the default.

### Recommendation
- Add explicit limits (max submodule count, max recursion depth, or a submodule-specific sub-timeout) independent of the outer `--sync-timeout`, so a single oversized/deeply nested submodule tree cannot consume the entire sync budget.
- Consider making `--max-failures` default to a small positive retry count (or documenting the crash-loop risk clearly) so a single slow sync doesn't immediately terminate the process.
- Allow operators to cap submodule recursion (e.g., `--submodules=shallow` enforcement or a max-depth flag) when syncing less-trusted content.

### Proof of Concept
1. Prepare an upstream repository whose `.gitmodules` references a very large number of submodules (or a chain of nested submodules many levels deep), each cheap for the attacker to create but expensive in aggregate to clone/update.
2. Point `git-sync` at that repo with default flags (`--submodules=recursive`, default `--sync-timeout=120s`, default `--max-failures=0`).
3. Observe that `configureWorktree`'s `git submodule update --init --recursive` step (main.go:1733-1747) cannot complete within `--sync-timeout`; `SyncRepo` returns a context-deadline error, and with `--max-failures=0` the process exits immediately (main.go:1056-1063), matching the behavior demonstrated by the existing `e2e::error_slow_git_short_timeout` test (test_e2e.sh:1594-1607). Restarting the container reproduces the same failure deterministically, since the same repo content is fetched again.

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

**File:** main.go (L1052-1054)
```go
	for {
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

**File:** test_e2e.sh (L1594-1607)
```shellscript
##############################################
# Test with slow git, short timeout
##############################################
function e2e::error_slow_git_short_timeout() {
    assert_fail \
        GIT_SYNC \
            --git="/$SLOW_GIT_FETCH" \
            --one-time \
            --sync-timeout=1s \
            --repo="file://$REPO" \
            --root="$ROOT" \
            --link="link"
    assert_file_absent "$ROOT/link/file"
}
```
