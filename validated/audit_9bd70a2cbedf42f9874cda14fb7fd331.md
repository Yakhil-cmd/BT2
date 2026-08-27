### Title
`Exechook.Do`'s in-flight subprocess `cwd` can be deleted mid-execution by `git.cleanup`'s stale-worktree pruning, violating publish integrity - ([File: main.go], [File: pkg/hook/exechook.go], [File: pkg/hook/hook.go])

### Summary
`hook.HookRunner.Send` is a fire-and-forget, non-blocking notification (`pkg/hook/hook.go:79-89`), and `HookRunner.Run` executes `Hook.Do` in a goroutine fully decoupled from the main sync loop. The main sync loop calls `git.cleanup` (which deletes non-current worktrees) immediately after triggering the hook, with default `--stale-worktree-timeout=0` meaning "removed immediately" — so a still-running `Exechook.Do` invocation can have its `cmd.Dir` (the old hash's worktree) deleted out from under it by the very next sync cycle.

### Finding Description
`Exechook.Do` resolves the worktree path for a hash and runs the exec command with that path as `cmd.Dir`: [1](#0-0) 

`HookRunner.Send` just stores the new hash and pings a non-blocking channel — it does not wait for or interlock with the previous `Do` invocation, and `HookRunner.Run` runs in an independent goroutine: [2](#0-1) [3](#0-2) 

Meanwhile, the main sync loop calls `git.cleanup(ctx)` on every successful sync, unconditionally, right after triggering the hooks for the new hash: [4](#0-3) 

`git.cleanup` calls `removeStaleWorktrees`, which deletes any worktree that is not the current one and whose `ModTime` exceeds `staleTimeout` — and the documented default for `--stale-worktree-timeout` is `0`, meaning "stale worktrees will be removed immediately": [5](#0-4) [6](#0-5) 

Deletion itself is a straightforward `os.RemoveAll` of the worktree directory: [7](#0-6) 

Because `hook.Do(ctx, oldHash)` may still be running (bounded only by `--exechook-timeout`, default 30s) when a subsequent sync for `newHash` completes, and the main loop does not wait for the previous hook invocation before pruning worktrees, the sequence is:

1. Sync N: hash `A` synced, worktree A created/current, `exechookRunner.Send("A")` fires asynchronously; `Exechook.Do(ctx, "A")` starts running with `cmd.Dir = worktreeFor(A)`.
2. Attacker pushes/force-pushes again quickly (repo content/ref is attacker-controlled).
3. Sync N+1: hash `B` synced, worktree B becomes current, `Send("B")` fires; the main loop immediately calls `git.cleanup` → `removeStaleWorktrees`, which deletes worktree A (`A != currentWorktree.Hash()` and `staleTimeout==0`) via `os.RemoveAll`.
4. If step 1's `Do("A")` subprocess is still executing, its `cwd` no longer exists — it can observe `ENOENT`, fail mid-write, or read a partially deleted tree.

No existing mechanism references-counts or locks a worktree while a hook execution is in flight; `Send`/`Run` and `cleanup` operate on entirely independent schedules.

### Impact Explanation
This is a publish-integrity failure: an exec-hook that is meant to act on a fully consistent, immutable checkout of a given hash can have its working directory vanish mid-run, causing it to fail, observe a corrupted/partial tree, or crash with `ENOENT`. If the hook itself copies/publishes artifacts derived from files in its `cwd`, the published output can be incomplete or wrong, matching the "publishing wrong or partial content" / "symlink/publish integrity failure" impact class. Repeated hook failures also feed the retry/backoff loop indefinitely if the race recurs on every fast update, degrading availability of downstream consumers of the hook's output.

### Likelihood Explanation
The precondition is only that: (a) `--exechook-command` is configured (a normal, documented, supported feature) and (b) the hook's execution time (bounded by the default 30s `--exechook-timeout`) exceeds the interval between two hash changes reaching the current worktree. An unprivileged attacker who controls the repo content/refs that git-sync fetches can force this interval to be arbitrarily short by pushing rapid successive commits/force-pushes, and `--stale-worktree-timeout` defaults to `0` ("removed immediately"), so no non-default flags are required to enable the vulnerable cleanup timing. The race is repeatable as long as the attacker can out-pace the hook's runtime.

### Recommendation
Introduce a reference count or explicit "in-use" marker per worktree that `Exechook.Do` (and any other cwd-dependent hook) holds for the duration of execution, and have `removeStaleWorktrees`/`cleanup` skip (or defer) deletion of any worktree currently marked in-use by a running hook. Alternatively, have the main sync loop wait for (or bound) prior hook completion before pruning the worktree it depended on, or snapshot/copy the worktree content the hook operates on rather than passing a live, prunable directory as `cmd.Dir`.

### Proof of Concept
Integration test sketch (Go, using existing `hook` and worktree-cleanup machinery):
```go
func TestHookRunnerRaceWithWorktreeCleanup(t *testing.T) {
    // 1. Configure Exechook with a slow shell command (e.g. "sleep 2; touch $PWD/marker")
    //    and getWorktree(hash) returning root/.worktrees/<hash>.
    // 2. Create worktree A, call runner.Send("A") to trigger Do(ctx, "A") asynchronously.
    // 3. Immediately (before the 2s sleep completes) simulate the next sync:
    //    create worktree B, mark it current, then call removeStaleWorktrees()
    //    with --stale-worktree-timeout=0 (default).
    // 4. Assert: removeStaleWorktrees must NOT delete worktree A while
    //    Do(ctx, "A") is still in-flight (e.g. check for a "hook in progress" lock,
    //    or assert the hook's marker file inside worktree A exists after cleanup runs,
    //    proving the directory survived until the hook finished).
    // Expected (buggy) result: worktree A directory is removed via os.RemoveAll
    //    while sleep is still running, and the hook subsequently fails with ENOENT
    //    when it tries to `touch $PWD/marker`.
}
```
This directly demonstrates that `git.cleanup`/`removeStaleWorktrees` (main.go:1754, main.go:1420) can delete a worktree referenced by an in-flight `Exechook.Do` invocation (pkg/hook/exechook.go:65), because `HookRunner.Send`/`Run` (pkg/hook/hook.go:79-157) provide no synchronization with the main sync loop's cleanup cadence.

### Citations

**File:** pkg/hook/exechook.go (L65-79)
```go
func (h *Exechook) Do(ctx context.Context, hash string) error {
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	worktreePath := h.getWorktree(hash)

	env := os.Environ()
	env = append(env, envKV("GITSYNC_HASH", hash))

	h.log.V(0).Info("running exechook", "hash", hash, "command", h.command, "timeout", h.timeout)
	stdout, stderr, err := h.cmdrunner.Run(ctx, worktreePath, env, h.command, h.args...)
	if err == nil {
		h.log.V(1).Info("exechook succeeded", "hash", hash, "stdout", stdout, "stderr", stderr)
	}
	return err
```

**File:** pkg/hook/hook.go (L79-89)
```go
func (d *hookData) send(newHash string) {
	d.set(newHash)

	// Non-blocking write.  If the channel is full, the consumer will see the
	// newest value.  If the channel was not full, the consumer will get another
	// event.
	select {
	case d.ch <- struct{}{}:
	default:
	}
}
```

**File:** pkg/hook/hook.go (L128-157)
```go
func (r *HookRunner) Run(ctx context.Context) {
	var lastHash string

	// Wait for trigger from hookData.Send
	for range r.data.events() {
		// Retry in case of error
		for {
			// Always get the latest value, in case we fail-and-retry and the
			// value changed in the meantime.  This means that we might not send
			// every single hash.
			hash := r.data.get()
			if hash == lastHash {
				break
			}

			if err := r.hook.Do(ctx, hash); err != nil {
				r.log.Error(err, "hook failed", "hash", hash, "retry", r.backoff)
				updateHookRunCountMetric(r.hook.Name(), "error")
				// don't want to sleep unnecessarily terminating anyways
				r.sendOneTimeResultAndTerminate(false)
				time.Sleep(r.backoff)
			} else {
				updateHookRunCountMetric(r.hook.Name(), "success")
				lastHash = hash
				r.sendOneTimeResultAndTerminate(true)
				break
			}
		}
	}
}
```

**File:** main.go (L1090-1092)
```go
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

**File:** main.go (L1622-1640)
```go
// removeWorktree is used to remove a worktree and its folder.
func (git *repoSync) removeWorktree(ctx context.Context, worktree worktree) error {
	// Clean up worktree, if needed.
	_, err := os.Stat(worktree.Path().String())
	switch {
	case os.IsNotExist(err):
		return nil
	case err != nil:
		return err
	}
	git.log.V(1).Info("removing worktree", "path", worktree.Path())
	if err := os.RemoveAll(worktree.Path().String()); err != nil {
		return fmt.Errorf("error removing directory: %w", err)
	}
	if _, _, err := git.Run(ctx, git.root, "worktree", "prune", "--verbose"); err != nil {
		return err
	}
	return nil
}
```

**File:** README.md (L520-525)
```markdown
    --stale-worktree-timeout <duration>, $GITSYNC_STALE_WORKTREE_TIMEOUT
            The length of time to retain stale (not the current link target)
            worktrees before being removed. Once this duration has elapsed,
            a stale worktree will be removed during the next sync attempt
            (as determined by --sync-timeout). If not specified, this defaults
            to 0, meaning that stale worktrees will be removed immediately.
```
