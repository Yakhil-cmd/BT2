### Title
Unsynchronized race between async exechook execution and stale-worktree cleanup causes hooks to run against partially/fully deleted worktrees - ([File: pkg/hook/hook.go], [File: main.go])

### Summary
`exechookRunner.Send(hash)` in `main.go`'s `afterPublish` callback only enqueues a hash; the actual `Exechook.Do` call happens later, asynchronously, in the independent `HookRunner.Run` goroutine [1](#0-0) . Because `--stale-worktree-timeout` defaults to `0` (immediate eligibility) and the outer sync loop's `cleanup()`/`removeStaleWorktrees()` runs unconditionally on the next sync with no coordination with pending hook goroutines, a worktree can be `os.RemoveAll`'d out from under an in-flight `exechook` command.

### Finding Description
`afterPublish` sends the new hash to both `webhookRunner` and `exechookRunner` via `HookRunner.Send`, which just writes into a size-1 buffered channel/`hookData` and returns immediately [1](#0-0) [2](#0-1) . The real work happens in a separate goroutine started at startup, `HookRunner.Run`, which loops, fetches the latest hash, and calls `hook.Do(ctx, hash)` — this is completely decoupled in time from the main sync loop [3](#0-2) .

`Exechook.Do` resolves the worktree path via the `getWorktree` closure at execution time — `git.worktreeFor(hash).Path().String()` — and then calls `cmdrunner.Run(ctx, worktreePath, ...)`, which spawns the configured command with that directory as its cwd [4](#0-3)  and [5](#0-4) .

Meanwhile, on the very next sync loop iteration (which can happen immediately if the attacker pushes a fast follow-up commit/ref update that git-sync fetches), the previous worktree's mtime is touched to start the stale-timer [6](#0-5) , and `cleanup()` → `removeStaleWorktrees()` removes any worktree other than the new current one whose age exceeds `--stale-worktree-timeout` [7](#0-6) . With the documented default of `0` for `--stale-worktree-timeout`, `time.Since(fi.ModTime()) > 0` is true almost immediately, so the previous worktree is removed on the very next sync pass [8](#0-7) . Actual removal uses `os.RemoveAll` on the worktree path [9](#0-8) .

There is no lock, refcount, or "in-use" marker shared between the `HookRunner` goroutine executing `Exechook.Do` and the main sync loop's `removeStaleWorktrees`/`removeWorktree` path. An attacker who controls the repo content/refs that git-sync fetches can push two rapid successive commits: the first triggers a hash publish and a `Send` to the exechook runner; the second (arriving before the first exechook command finishes, e.g., because the exechook command is slow) triggers a full sync-to-B, which touches and then removes worktree A's directory while the exechook goroutine for A is still mid-`cmdrunner.Run`. This is exactly the "publish integrity" race the question describes: the exechook process ends up operating on a directory that is being deleted concurrently by `os.RemoveAll`, producing spurious errors or reading truncated/partial content.

### Impact Explanation
Scoped impact is limited to `publish integrity` for the exechook consumer: the exechook command can observe a partially removed worktree (files disappearing mid-execution), yielding spurious failures, corrupted/partial reads, or, depending on what the exechook script does with that content (e.g. copies files, checks hashes), it could act on inconsistent data. This does not by itself grant the attacker new code execution or secrets beyond what a configured exechook already exposes them to, but it is a genuine, reproducible correctness/integrity violation matching the "publish integrity failure" impact class named in the rules.

### Likelihood Explanation
No non-default or unsupported flags are required beyond having `--exechook-command` configured (a documented, supported flag) and either the documented default `--stale-worktree-timeout=0` or any small timeout. The attacker only needs the ability to push rapid successive commits/ref updates to the repo git-sync fetches — this is within the explicitly allowed attacker capability ("controls repo content and refs that git-sync fetches"). The race window is widened by a slow-running exechook command, which is operator-configured content, not attacker-controlled, so exploitability depends somewhat on the specific exechook script's runtime, but the underlying lack of synchronization is a structural bug independent of any particular exechook duration — it's just easier to trigger and observe with a slower command.

### Recommendation
Introduce synchronization between hook execution and worktree cleanup: e.g., track in-flight worktree references (a per-worktree refcount or a `sync.Map` of "in use by hook" markers) that `removeStaleWorktrees`/`removeWorktree` consult before removing a directory, or have `HookRunner`/`Exechook` acquire a shared read-lock on the worktree while `Do` is executing and have cleanup take a write-lock before `os.RemoveAll`. Alternatively, defer stale-worktree removal until any hook run associated with that hash's worktree has completed.

### Proof of Concept
Integration test sketch (Go, in `pkg/hook` or `main_test.go`-style):
1. Configure a `repoSync` with `--stale-worktree-timeout=0`, a slow `--exechook-command` (e.g. `sh -c "sleep 2; ls ."`), and no `--webhook-url` (or both, per the question).
2. Sync to hash A; capture the goroutine dispatch of `exechookRunner.Send("A")`.
3. Immediately update the repo to hash B and force a second, fast sync (e.g. via `--sync-on-signal` or minimal `--period`) so that `SyncRepo` completes for B and `cleanup()` runs before the 2-second sleep in the exechook command for A finishes.
4. Assert that the exechook process for A either: (a) completes successfully before `removeWorktree` deletes A's directory, or (b) is skipped entirely if A is already gone — but demonstrate that in the current code neither guarantee holds: the `sh` process for A returns a nonzero/garbled result (e.g., "No such file or directory") because `os.RemoveAll` executed concurrently with the running command's `cwd`.

### Citations

**File:** main.go (L923-933)
```go
		exechook := hook.NewExechook(
			logname,
			cmd.NewRunner(log),
			*flExechookCommand,
			func(hash string) string {
				return git.worktreeFor(hash).Path().String()
			},
			[]string{},
			*flExechookTimeout,
			log,
		)
```

**File:** main.go (L1029-1037)
```go
		afterPublish: func(hash string) error {
			if exechookRunner != nil {
				exechookRunner.Send(hash)
			}
			if webhookRunner != nil {
				webhookRunner.Send(hash)
			}
			return nil
		},
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

**File:** main.go (L1633-1635)
```go
	if err := os.RemoveAll(worktree.Path().String()); err != nil {
		return fmt.Errorf("error removing directory: %w", err)
	}
```

**File:** main.go (L1964-1970)
```go
			if currentWorktree != "" {
				// Start the stale worktree removal timer.
				err = touch(currentWorktree.Path())
				if err != nil {
					git.log.Error(err, "can't change stale worktree mtime", "path", currentWorktree.Path())
				}
			}
```

**File:** pkg/hook/hook.go (L122-125)
```go
// Send sends hash to hookdata.
func (r *HookRunner) Send(hash string) {
	r.data.send(hash)
}
```

**File:** pkg/hook/hook.go (L127-156)
```go
// Run waits for trigger events from the channel, and run hook when triggered.
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
```

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
