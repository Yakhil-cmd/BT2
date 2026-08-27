### Title
Unbounded accumulation of half-built worktree directories when sync repeatedly times out - ([File: main.go])

### Summary
`git.cleanup()` (which calls `removeStaleWorktrees()`) is only invoked from the main sync loop in the success branch of `SyncRepo`. When `SyncRepo` returns an error (e.g. `context.DeadlineExceeded` from `--sync-timeout`), cleanup is skipped entirely. An attacker who pushes commits fast enough to force `git-sync` to repeatedly time out during checkout can cause every failed attempt's partially-created worktree directory to be permanently orphaned on disk.

### Finding Description
In the main sync loop, each iteration creates a fresh `context.WithTimeout(context.Background(), *flSyncTimeout)` and calls `git.SyncRepo(ctx, syncHooks)`: [1](#0-0) 

Cleanup (`git.cleanup(ctx)`, which internally calls `removeStaleWorktrees()`) is only reached in the `else` branch, i.e. only when `SyncRepo` returns no error. On the `err != nil` branch, the loop only increments `failCount` and logs — it never calls `cleanup`: [2](#0-1) 

Inside `SyncRepo`, when a new remote hash is detected, `createWorktree(ctx, remoteHash)` is called to build a worktree for the *new* hash. `createWorktree` only calls `removeWorktree` on the worktree matching the hash it's about to create (to guard against a previous crash creating that exact same path); it does not clean up any *other* worktree directories left behind by a previous, different, timed-out attempt: [3](#0-2) 

The checkout step itself (`configureWorktree`, called after `createWorktree`) is where the actual (potentially slow) file materialization happens, and it runs under the same `ctx` with the `--sync-timeout` deadline. If the context expires mid-checkout, the underlying `git` command run via `cmd.Run()` is killed (`exec.CommandContext`) and `Run` returns an error wrapping `context.DeadlineExceeded`: [4](#0-3) 

This error propagates up through `configureWorktree` → `SyncRepo` → the main loop's `err != nil` branch, so `cleanup()`/`removeStaleWorktrees()` is never called for that iteration. The worktree directory just created by `git worktree add --no-checkout` at `git.worktreeFor(remoteHash).Path()` remains on disk, partially checked out.

If the attacker keeps pushing new commits faster than `--sync-timeout` allows a full checkout to complete, each loop iteration:
1. Fetches the new hash.
2. Calls `createWorktree` for the new hash (a new directory).
3. Begins checkout via `configureWorktree`, which times out.
4. Returns an error, so the outer loop skips `cleanup()`.

Each iteration leaves behind a distinct, never-cleaned worktree directory (one per attempted hash), because `removeStaleWorktrees()` — the only mechanism that reaps non-current worktree directories under `git.worktreeFor("").Path()` — is gated behind the success path in the main loop: [5](#0-4) [6](#0-5) 

Since these directories are never the current published link target and their sync never succeeds, they are never opportunistically cleaned by any other code path either (the in-place-upgrade path in `SyncRepo` that calls `os.RemoveAll` on `currentWorktree.Path()` is only reached inside the success branch as well). This results in unbounded growth of worktree directories under `--root/.worktrees`, each partially populated with attacker-sized file content, consuming disk indefinitely.

### Impact Explanation
This is a disk/resource-exhaustion vulnerability (Kubernetes bounty impact class: denial of service / resource exhaustion via unbounded local disk consumption). An attacker who controls push rate to a tracked branch and can make checkout of a commit take longer than `--sync-timeout` (e.g. via very large or many files) can force the git-sync sidecar/container to fill its volume with orphaned worktree directories, eventually exhausting disk space on the shared volume/node, potentially disrupting other containers sharing that volume or the node's storage.

### Likelihood Explanation
Requires `--sync-timeout` to be set below the time needed to check out attacker-sized commits — a documented, supported flag (`--sync-timeout`, default 120s) that operators may reasonably set lower for responsiveness, or that an attacker can defeat by pushing sufficiently large commits regardless of a longer default timeout. The attacker only needs write/push access to the tracked ref (a public/writable branch), matching the stated threat model. The exploit is fully repeatable as long as the attacker keeps outpacing the timeout, and does not require any special privileges beyond normal push access.

### Recommendation
Decouple worktree cleanup from sync success: call `git.cleanup(ctx)` (or at minimum `removeStaleWorktrees()`) unconditionally on every loop iteration regardless of whether `SyncRepo` returned an error, using a bounded age/size limit independent of `--stale-worktree-timeout`'s "not-current" semantics. Additionally, `createWorktree`/`SyncRepo` should track and remove any worktree directory it creates if the surrounding sync attempt fails/times out (e.g. via `defer` cleanup keyed on success), rather than relying solely on the next successful sync's stale-worktree pass.

### Proof of Concept
Integration test outline (extending the existing `test_e2e.sh` style, cf. `e2e::error_slow_git_short_timeout` and `e2e::stale_worktree_timeout`):
1. Configure a repo whose checkout is artificially slow (large number of files, similar to `$SLOW_GIT_FETCH` helper used in `e2e::error_slow_git_short_timeout`). [7](#0-6) 
2. Run `GIT_SYNC` with `--period=100ms --sync-timeout=200ms --root="$ROOT" --link=link` in the background (not `--one-time`), and repeatedly commit+push new large commits to `$REPO` faster than 200ms.
3. After sustaining rapid pushes for several seconds, count directories under `$ROOT/.worktrees`.
4. Assert that the count is bounded (e.g. does not exceed 2-3) and that no directories older than a small bound remain — this assertion will fail on the current code because each timed-out sync leaves a new, never-cleaned worktree directory, causing the count to grow linearly with the number of failed sync attempts.

### Citations

**File:** main.go (L1052-1092)
```go
	for {
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

**File:** main.go (L1420-1441)
```go
func (git *repoSync) removeStaleWorktrees() (int, error) {
	currentWorktree, err := git.currentWorktree()
	if err != nil {
		return 0, err
	}

	git.log.V(3).Info("cleaning up stale worktrees", "currentHash", currentWorktree.Hash())

	count := 0
	err = removeDirContentsIf(git.worktreeFor("").Path(), git.log, func(fi os.FileInfo) (bool, error) {
		// delete files that are over the stale time out, and make sure to never delete the current worktree
		if fi.Name() != currentWorktree.Hash() && time.Since(fi.ModTime()) > git.staleTimeout {
			count++
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}
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

**File:** main.go (L1752-1799)
```go
// cleanup removes old worktrees and runs git's garbage collection.  The
// specified worktree is preserved.
func (git *repoSync) cleanup(ctx context.Context) error {
	// Save errors until the end.
	var cleanupErrs multiError

	// Clean up previous worktree(s).
	if n, err := git.removeStaleWorktrees(); err != nil {
		cleanupErrs = append(cleanupErrs, err)
	} else if n == 0 {
		// We didn't clean up any worktrees, so the rest of this is moot.
		return nil
	}

	// Let git know we don't need those old commits any more.
	git.log.V(3).Info("pruning worktrees")
	if _, _, err := git.Run(ctx, git.root, "worktree", "prune", "--verbose"); err != nil {
		cleanupErrs = append(cleanupErrs, err)
	}

	// Expire old refs.
	git.log.V(3).Info("expiring unreachable refs")
	if _, _, err := git.Run(ctx, git.root, "reflog", "expire", "--expire-unreachable=all", "--all"); err != nil {
		cleanupErrs = append(cleanupErrs, err)
	}

	// Run GC if needed.
	if git.gc != gcOff {
		args := []string{"gc"}
		switch git.gc {
		case gcAuto:
			args = append(args, "--auto")
		case gcAlways:
			// no extra flags
		case gcAggressive:
			args = append(args, "--aggressive")
		}
		git.log.V(3).Info("running git garbage collection")
		if _, _, err := git.Run(ctx, git.root, args...); err != nil {
			cleanupErrs = append(cleanupErrs, err)
		}
	}

	if len(cleanupErrs) > 0 {
		return cleanupErrs
	}
	return nil
}
```

**File:** pkg/cmd/cmd.go (L63-90)
```go
func runWithStdin(ctx context.Context, log logintf, cwd string, env []string, stdin, command string, args ...string) (string, string, error) {
	cmdStr := cmdForLog(command, args...)
	log.V(5).Info("running command", "cwd", cwd, "cmd", cmdStr)

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
	if err != nil {
		return stdout, stderr, fmt.Errorf("Run(%s): %w: { stdout: %q, stderr: %q }", cmdStr, err, stdout, stderr)
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
