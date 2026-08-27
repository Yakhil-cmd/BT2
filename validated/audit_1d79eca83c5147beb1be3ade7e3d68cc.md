### Title
Pre-publish exechook does not gate symlink publication - unpublished/failing hook is bypassed (File: main.go, pkg/hook/hook.go)

### Summary
The `--pre-publish-exechook-command` mechanism is documented as running "before publishing the symlink" so that consumers only see a symlink flip after a successful pre-publish action. In practice, `SyncRepo` fires the pre-publish hook asynchronously and unconditionally proceeds to flip the symlink regardless of whether the hook has finished or succeeded, exactly mirroring the `harvest()` cooldown/revert bug: an intended "gate" step is queued but not actually awaited/enforced before the state-changing action executes.

### Finding Description
`beforePublish` is defined as a closure that only enqueues work and always returns `nil`: [1](#0-0) 

`HookRunner.Send` is a non-blocking, fire-and-forget call that just writes the hash into a channel: [2](#0-1) 

The actual hook execution happens on a separate goroutine, `prePubExechookRunner.Run`, started once at startup: [3](#0-2) 

Inside `Run`, if the underlying `Exechook.Do` errors, the runner just logs, updates a metric, sleeps for the configured backoff, and retries — it never returns an error to the caller of `Send`, and there is no synchronization primitive forcing `SyncRepo` to wait: [4](#0-3) 

In `SyncRepo`, the sequence is: call `syncHooks.beforePublish(hash)` (which merely enqueues the hook and returns immediately with `nil`), then unconditionally call `git.publishSymlink(newWorktree)`: [5](#0-4) 

This reproduces both scenarios from the referenced report:
- **Cooldown-equivalent**: If the previous pre-publish hook invocation is still retrying/backing off (`time.Sleep(r.backoff)` in `HookRunner.Run`), a new `Send` overwrites `lastHash`'s target data but the symlink is still published before the hook for the *new* hash has ever run.
- **Revert-equivalent**: If `Exechook.Do` (the actual command) fails, `HookRunner.Run` swallows the error into a log line and retries later; `beforePublish` already returned `nil` to `SyncRepo`, so `publishSymlink` proceeds regardless.

A `WaitForCompletion` API exists on `HookRunner` for the `--one-time` case, but it is not used here to synchronously block on the pre-publish hook's outcome — `oneTimeResult` is only consulted when the caller explicitly awaits it, which `SyncRepo`'s `beforePublish` closure does not do: [6](#0-5) 

### Impact Explanation
The `--pre-publish-exechook-command` feature is documented as a pre-condition to be satisfied "before publishing the symlink" — this is meant to let operators run validation, warm-up, or side-effect actions (e.g., signing, scanning, extra checkout steps) prior to consumers seeing new content. Because the gate is not actually enforced, git-sync can publish a new worktree via the atomic symlink even though the configured pre-publish action failed or hasn't completed, silently breaking the operator's intended safety contract. This can result in consumers observing content that skipped a required pre-publish step (e.g. unscanned, unsigned, or otherwise not-yet-validated data), which is the sync-denial/wrong-content-published class of impact.

### Likelihood Explanation
This triggers on every sync cycle where `--pre-publish-exechook-command` is configured and the command is slow, still backing off from a prior failure, or fails outright — no attacker action beyond causing a slow/failing pre-publish command (or a remote content change that makes the pre-publish hook do more work / fail, e.g. a malicious commit that trips a validation script) is required. Any repo owner able to push commits that make the pre-publish hook fail or run long can reliably cause this gate bypass.

### Recommendation
Make `beforePublish` synchronously wait for the pre-publish hook's result for the specific hash before returning, and propagate failure as an error so `SyncRepo` aborts the publish (similar to how the reported fix makes `harvest()` revert instead of silently no-op'ing). Concretely: use a per-hash completion channel from `HookRunner` (not only the `oneTimeResult` reserved for `--one-time` mode) and have `beforePublish` block on it, returning any hook error so `git.publishSymlink` is never reached on failure or incompleteness.

### Proof of Concept
1. Configure `git-sync` with `--pre-publish-exechook-command=/bin/false --pre-publish-exechook-backoff=30s`.
2. On each sync where the ref changes, `SyncRepo` calls `syncHooks.beforePublish(hash)` → `prePubExechookRunner.Send(hash)`, which returns immediately and always yields `nil` from `beforePublish`.
3. `SyncRepo` continues to `git.publishSymlink(newWorktree)` and updates the symlink even though `/bin/false` fails every time in the background `HookRunner.Run` loop.
4. Consumers observe the new symlink/content despite the configured pre-publish gate never succeeding — confirmable by inspecting `git_sync_hook_run_count_total{name="pre-publish-exechook",status="error"}` incrementing while `assert_link_exists`/publish still occurs each cycle.

### Citations

**File:** main.go (L960-967)
```go
		prePubExechookRunner = hook.NewHookRunner(
			exechook,
			*flPrePubExechookBackoff,
			hook.NewHookData(),
			log,
			*flOneTime,
		)
		go prePubExechookRunner.Run(context.Background())
```

**File:** main.go (L1023-1028)
```go
		beforePublish: func(hash string) error {
			if prePubExechookRunner != nil {
				prePubExechookRunner.Send(hash)
			}
			return nil
		},
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

**File:** pkg/hook/hook.go (L122-125)
```go
// Send sends hash to hookdata.
func (r *HookRunner) Send(hash string) {
	r.data.send(hash)
}
```

**File:** pkg/hook/hook.go (L128-156)
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
```

**File:** pkg/hook/hook.go (L172-189)
```go
// WaitForCompletion waits for HookRunner to send completion message to
// calling thread and returns either true if HookRunner executed successfully
// and some error otherwise.
// Assumes that r.oneTimeResult is not nil, but if it is, returns an error.
func (r *HookRunner) WaitForCompletion() error {
	// Make sure function should be called
	if r.oneTimeResult == nil {
		return fmt.Errorf("HookRunner.WaitForCompletion called on async runner")
	}

	// Perform wait on HookRunner
	hookRunnerFinishedSuccessfully := <-r.oneTimeResult
	if !hookRunnerFinishedSuccessfully {
		return fmt.Errorf("hook completed with error")
	}

	return nil
}
```
