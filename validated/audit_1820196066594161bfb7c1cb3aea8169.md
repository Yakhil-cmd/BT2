Confirmed: `exec.CommandContext(ctx, ...)` kills the git subprocess (e.g. `reset --hard`) when the `--sync-timeout` context deadline expires [1](#0-0) , which returns an error from `configureWorktree`/`git.Run` up through `SyncRepo` [2](#0-1) . In the main sync loop, this error path skips `git.cleanup(ctx)` (and thus `removeStaleWorktrees`) entirely — cleanup only runs in the success branch [3](#0-2) . Each new attacker push creates a **new** worktree directory keyed by the new commit hash via `createWorktree`/`worktreeFor(hash)` [4](#0-3) , so `removeWorktree`'s "avoid wedge cases" cleanup only removes a *stale* worktree with the *same* target hash, not prior different-hash worktrees from earlier failed periods [5](#0-4) .

### Title
Repeated sync-timeout failures on adversarial pushes bypass stale-worktree cleanup, causing unbounded worktree accumulation and volume exhaustion - ([File: main.go])

### Summary
`repoSync.configureWorktree`'s git subprocess calls (`sparse-checkout init`, `reset --hard`, `submodule update`) run under a per-sync `context.WithTimeout(*flSyncTimeout)` and are killed via `exec.CommandContext` on expiry, returning an error from `SyncRepo`. Because the sync loop only invokes `git.cleanup` (which calls `removeStaleWorktrees`) on the success path, an attacker who repeatedly pushes commits large/deep enough to make checkout exceed `--sync-timeout` can force perpetual failure, during which each new push spawns a distinct half-materialized worktree directory that is never pruned, exhausting the `--root` volume.

### Finding Description
The sync loop creates a fresh timeout context each iteration [6](#0-5) , calls `git.SyncRepo(ctx, syncHooks)`, and only performs cleanup (`git.cleanup(ctx)`, which calls `removeStaleWorktrees`) inside the `else` (no-error) branch [3](#0-2) . If `SyncRepo` returns an error, the loop just increments `failCount` and sleeps — no cleanup runs regardless of `--stale-worktree-timeout` [7](#0-6) .

`SyncRepo`, when a new remote hash is detected, calls `createWorktree(ctx, remoteHash)` to `git worktree add ... --no-checkout` (fast) and then `configureWorktree(ctx, newWorktree)`, which performs the (potentially slow) `reset --hard <hash> --` and submodule update [8](#0-7) , [9](#0-8) . Each of these git invocations goes through `runWithStdin`, which uses `exec.CommandContext(ctx, ...)` — when the sync-timeout context expires, the git process is killed mid-checkout and the function returns an error tagged with `context.DeadlineExceeded` [1](#0-0) . That error propagates straight out of `configureWorktree` and `SyncRepo`, bypassing symlink publish and — critically — bypassing `git.cleanup` for that iteration.

`createWorktree` does call `git.removeWorktree` before creating a new one, but only for the worktree keyed by the *current target hash* (`git.worktreeFor(hash)`), to avoid "already exists" errors on retry of the *same* hash [4](#0-3) . It does not touch worktrees left behind from *earlier* hashes. If the attacker pushes a new large/deeply-nested commit each period (new hash each time), each period's failed `configureWorktree` leaves a distinct, partially-checked-out worktree directory named after that period's hash. Since `SyncRepo` errors out every time (checkout never completes within `--sync-timeout`), `git.cleanup`/`removeStaleWorktrees` is never reached, so these directories are never removed no matter how `--stale-worktree-timeout` is configured — the invariant "timeouts leave no residue" is violated.

### Impact Explanation
Each failed period leaves an additional partially-materialized worktree directory (potentially containing large numbers of files already written by `reset --hard` before the kill) under `--root`, which is never reclaimed while the attacker keeps forcing timeouts. This matches the Kubernetes bounty "resource/volume exhaustion" impact class: the persistent volume backing `--root` fills up, and because `SyncRepo` never succeeds, the published symlink is never advanced, leaving consumers permanently on stale data (denial of fresh data) in addition to eventual disk-full failures affecting the whole pod/volume.

### Likelihood Explanation
Requires only default git-sync operation with a non-default (but documented) `--sync-timeout` short enough, or a repo large enough, for checkout to routinely exceed it — this is plausible for an attacker who can push arbitrarily large/deep trees to the synced repo, as posited in the threat model (unprivileged push access, no flag/env control needed beyond what's already configured by the operator). `--stale-worktree-timeout` being non-zero is not actually required for the bypass — even its default (immediate removal) is irrelevant because `cleanup` is never invoked on the failure path at all. The attack is fully repeatable: one large/deep push per sync period sustains the leak indefinitely.

### Recommendation
Run `git.cleanup` (or at least `removeStaleWorktrees`) unconditionally after every sync attempt, independent of whether `SyncRepo` returned an error, using a bounded/separate context so a hung sync doesn't also starve cleanup. Additionally, consider having `createWorktree`/`configureWorktree` register newly-created worktree directories for guaranteed removal on failure (not just same-hash retries), and consider capping checkout resource usage (e.g., via a distinct checkout-specific timeout that fails fast and triggers immediate removal of the partial worktree) so partial directories from timed-out syncs are always cleaned before the next iteration.

### Proof of Concept
Integration test sketch (extending `test_e2e.sh` style):
1. Start a local bare repo; commit an initial small file; run `git-sync --one-time --repo=... --root=$ROOT --link=link` to establish a baseline good sync.
2. Configure git-sync in daemon mode with a short `--sync-timeout` (e.g. `2s`) and a normal `--period`.
3. In a loop, on each period, push a new commit to the repo containing a very large number of tiny files (e.g. `for i in $(seq 1 200000); do echo x > file$i; done; git add -A; git commit`), each commit producing a distinct hash.
4. After several periods, assert: (a) `$ROOT/link` still points at the original/first-successful hash (no progress), and (b) `ls $ROOT | wc -l` (number of worktree directories under `--root`) grows monotonically with each failed period rather than staying bounded — demonstrating residue accumulation that `--stale-worktree-timeout` does not bound because `cleanup` is never invoked on the failure path.

### Citations

**File:** pkg/cmd/cmd.go (L67-87)
```go
	cmd := exec.CommandContext(ctx, command, args...)
	if cwd != "" {
		cmd.Dir = cwd
	}
	if len(env) != 0 {
		cmd.Env = env
	}
	outbuf := bytes.NewBuffer(nil)
	errbuf := bytes.NewBuffer(nil)
	cmd.Stdout = outbuf
	cmd.Stderr = errbuf
	cmd.Stdin = bytes.NewBufferString(stdin)

	start := time.Now()
	err := cmd.Run()
	wallTime := time.Since(start)
	stdout := strings.TrimSpace(outbuf.String())
	stderr := strings.TrimSpace(errbuf.String())
	if ctx.Err() == context.DeadlineExceeded {
		return stdout, stderr, fmt.Errorf("Run(%s): %w: { stdout: %q, stderr: %q }", cmdStr, ctx.Err(), stdout, stderr)
	}
```

**File:** main.go (L1052-1054)
```go
	for {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), *flSyncTimeout)
```

**File:** main.go (L1056-1092)
```go
		if changed, hash, err := git.SyncRepo(ctx, syncHooks); err != nil {
			failCount++
			updateSyncMetrics(metricKeyError, start)
			if maxFails := getMaxFailures(); maxFails >= 0 && failCount >= maxFails {
				log.Error(err, "too many failures, aborting", "failCount", failCount, "maxFailures", maxFails)
				os.Exit(1)
			}
			log.Error(err, "error syncing repo, will retry", "failCount", failCount)
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
			// We treat the first loop as a sync, including sending hooks.
			if changed || syncCount == 0 {
				if absTouchFile != "" {
					if err := touch(absTouchFile); err != nil {
						log.Error(err, "failed to touch touch-file", "path", absTouchFile)
					} else {
						log.V(3).Info("touched touch-file", "path", absTouchFile)
					}
				}
				updateSyncMetrics(metricKeySuccess, start)
			} else {
				updateSyncMetrics(metricKeyNoOp, start)
			}
			syncCount++

			// Clean up old worktree(s) and run GC.
			if err := git.cleanup(ctx); err != nil {
				log.Error(err, "git cleanup failed")
			}
```

**File:** main.go (L1644-1663)
```go
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

**File:** main.go (L1727-1747)
```go
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
